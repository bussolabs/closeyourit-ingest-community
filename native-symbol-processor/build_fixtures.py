"""Compile actual source; never fabricate object files, IDs or debug information."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent


def run(args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=120).stdout


def build(destination):
    destination.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(ROOT / 'fixture.c', destination / 'fixture.c')
    for depth in (31, 32):
        functions = ['static __attribute__((always_inline)) inline int f0(int x) { volatile int y=x+1; return y; }']
        functions.extend(f'static __attribute__((always_inline)) inline int f{i}(int x) {{ volatile int y=f{i-1}(x); return y+1; }}' for i in range(1, depth))
        functions.append(f'__attribute__((noinline)) int native_leaf(int x) {{ return f{depth-1}(x); }}')
        functions.append('int main(void) { return native_leaf(1); }')
        (destination / f'inline-{depth}.c').write_text('\n'.join(functions) + '\n')
    docker = ['docker', 'run', '--rm', '--network=none', '--cap-drop=ALL',
              '--security-opt=no-new-privileges', '--memory=768m', '--pids-limit=64',
              '-v', f'{destination}:/proof', '-w', '/proof',
              'cyi-native-symbol-fixtures:u13-local', '-ec']
    linux = run(docker + ['''
        clang -g -O1 -DRUNTIME_PROOF -fPIE -pie -Wl,--build-id=sha1 fixture.c -ldl -o proof.elf
        ./proof.elf > elf-runtime.json
        /usr/lib/llvm21/bin/llvm-objcopy --only-keep-debug proof.elf proof.debug
        /usr/lib/llvm21/bin/llvm-strip --strip-debug -o proof.stripped proof.elf
        clang --target=x86_64-pc-windows-msvc -g -gcodeview -O1 -c fixture.c -o proof.obj
        lld-link /debug:full /nodefaultlib /entry:main /subsystem:console /out:proof.exe /pdb:proof.pdb proof.obj
        /usr/lib/llvm21/bin/llvm-readobj --coff-debug-directory proof.exe > pe-identity.txt
        /usr/lib/llvm21/bin/llvm-pdbutil dump -publics proof.pdb > pdb-publics.txt
        for depth in 31 32; do
          clang -g -O1 -Wl,--build-id=sha1 inline-$depth.c -o inline-$depth.elf
          /usr/lib/llvm21/bin/llvm-nm --format=posix inline-$depth.elf > inline-$depth-symbols.txt
        done
        clang --version
    '''])
    result = {'schema_version': 1, 'linux_toolchain': linux.strip(),
              'elf': {'runtime': json.loads((destination / 'elf-runtime.json').read_text())},
              'pe': {'runtime_executed': False, 'reason': 'No Windows runtime; real cross-compiled PE and PDB.'}}
    if sys.platform == 'darwin':
        result['macos_toolchain'] = run(['xcrun', 'clang', '--version']).strip()
        run(['xcrun', 'clang', '-g', '-O1', '-DRUNTIME_PROOF', '-arch', 'arm64', '-arch', 'x86_64',
             '-c', str(destination / 'fixture.c'), '-o', str(destination / 'proof.macho.o')])
        run(['xcrun', 'clang', '-g', '-arch', 'arm64', '-arch', 'x86_64',
             str(destination / 'proof.macho.o'), '-o', str(destination / 'proof.macho')])
        run(['xcrun', 'dsymutil', str(destination / 'proof.macho')])
        result['macho'] = {'runtime': json.loads(run([str(destination / 'proof.macho')])),
                           'uuids': run(['xcrun', 'dwarfdump', '--uuid', str(destination / 'proof.macho')]).strip()}
    result['artifacts'] = {str(path.relative_to(destination)): {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                          'bytes': path.stat().st_size} for path in destination.rglob('*') if path.is_file()}
    (destination / 'build-report.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'built': str(destination), 'artifacts': len(result['artifacts'])}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('destination', type=Path)
    build(parser.parse_args().destination.resolve())
