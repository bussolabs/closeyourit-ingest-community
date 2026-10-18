"""Real HTTP proof against compiled files and an independent LLVM oracle."""
import argparse
import base64
import hashlib
import http.client
import json
from pathlib import Path
import re
import subprocess
import time
import urllib.error
import urllib.request


class Proof:
    def __init__(self, fixtures, endpoint):
        self.fixtures, self.endpoint = fixtures, endpoint
        self.assertions = []
        self.observations = {}

    def check(self, name, condition):
        self.assertions.append({'name': name, 'passed': bool(condition)})
        if not condition:
            raise AssertionError(name)

    def send(self, file, addresses=None, expected=None, body=None):
        if body is None:
            body = json.dumps({'object_base64': base64.b64encode(file.read_bytes()).decode(),
                               'addresses': addresses or [], 'expected': expected}).encode()
        request = urllib.request.Request(self.endpoint + '/symbolicate', body,
                                         {'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as response:
            return response.code, json.load(response)

    def compiler(self, args):
        return subprocess.run(['docker', 'run', '--rm', '--network=none', '--read-only',
            '--cap-drop=ALL', '--security-opt=no-new-privileges', '--memory=512m', '--pids-limit=32',
            '-v', f'{self.fixtures}:/proof:ro', '--entrypoint', args[0],
            'cyi-native-symbol-fixtures:u13-local', *args[1:]],
            check=True, capture_output=True, text=True, timeout=30).stdout

    @staticmethod
    def expected(identity):
        return {key: identity[key] for key in ('format', 'architecture', 'debug_id', 'code_id')
                if identity[key] is not None}

    def run(self):
        build = json.loads((self.fixtures / 'build-report.json').read_text())
        for path, meta in build['artifacts'].items():
            self.check('input_digest:' + path,
                hashlib.sha256((self.fixtures / path).read_bytes()).hexdigest() == meta['sha256'])
        self.observations['version'] = json.load(urllib.request.urlopen(self.endpoint + '/version', timeout=3))
        self.check('outbound_syscalls_denied', self.observations['version']['outbound_syscalls_denied'] is True)
        section = self.compiler(['/usr/lib/llvm21/bin/llvm-readobj', '--sections', '/proof/proof.exe'])
        match = re.search(r'Number: 1\s+Name: \.text.*?VirtualAddress: (0x[0-9A-Fa-f]+)', section, re.S)
        self.check('pe_real_text_section', match is not None)
        pe_base = int(match.group(1), 16)
        # Public symbol offset comes from the real PDB, not the processor under test.
        publics = (self.fixtures / 'pdb-publics.txt').read_text()
        match = re.search(r'`native_leaf`\s+flags = function, addr = 0001:([0-9]+)', publics)
        self.check('pdb_real_public_symbol', match is not None)
        pe_address = pe_base + int(match.group(1))
        cases = [('elf', 'proof.elf', build['elf']['runtime']['address'], 'arm64'),
                 ('pdb', 'proof.pdb', hex(pe_address), 'x86_64')]
        if 'macho' in build:
            cases.append(('macho', 'proof.macho.dSYM/Contents/Resources/DWARF/proof.macho',
                          build['macho']['runtime']['address'], 'arm64'))
        for kind, name, start, arch in cases:
            file = self.fixtures / name
            status, inspection = self.send(file)
            self.check(kind + '.zero', status == 200 and inspection['frames'] == [])
            identities = [item for item in inspection['objects'] if item['architecture'] == arch]
            self.check(kind + '.unique_arch', len(identities) == 1)
            identity = identities[0]
            self.check(kind + '.usable_debug_identity', identity['usable'] and identity['has_debug_info'])
            expected = self.expected(identity)
            status, single = self.send(file, [start], expected)
            self.check(kind + '.single', status == 200 and len(single['frames']) == 1)
            addresses = [hex(int(start, 16) + delta) for delta in (0, 4, 8, 12, 16)]
            status, result = self.send(file, addresses, expected)
            self.check(kind + '.batch', status == 200 and [f['address'] for f in result['frames']] == addresses)
            self.check(kind + '.inline_present', any(len(f['locations']) > 1 for f in result['frames']))
            oracle_file = 'proof.exe' if kind == 'pdb' else name
            oracle_addresses = addresses
            options = ['--relative-address']
            if kind == 'macho':
                options = ['--default-arch=' + arch]
                oracle_addresses = [hex(int(value, 16) + int(identity['preferred_load_address'], 16)) for value in addresses]
            oracle = json.loads(self.compiler(['/usr/lib/llvm21/bin/llvm-symbolizer', '--no-debuginfod',
                '--output-style=JSON', '--obj=/proof/' + oracle_file, *options, *oracle_addresses]))
            actual = [[(v['function'], v['file'], v['line']) for v in f['locations']] for f in result['frames']]
            reference = [[(v['FunctionName'], v['FileName'], v['Line'] or None) for v in f['Symbol']] for f in oracle]
            if kind == 'pdb':
                # Symbolic includes the PDB signature; LLVM prints the C identifier alone.
                # These two exact signatures are independently defined in fixture.c.
                signatures = {'native_leaf': 'native_leaf(int)', 'inline_add': 'inline_add(int)'}
                reference = [[(signatures[name], path, line) for name, path, line in frame] for frame in reference]
            self.check(kind + '.independent_full_function_file_line_inline_oracle', actual == reference)
            status, unknown = self.send(file, ['0xfffffffe'], expected)
            self.check(kind + '.unmapped_remains_unresolved', status == 200 and unknown['frames'][0]['status'] == 'unresolved')
            for field, bad in [('debug_id', '00000000-0000-0000-0000-000000000001'), ('architecture', 'unknown')]:
                wrong = dict(expected, **{field: bad})
                self.check(kind + '.wrong_' + field, self.send(file, [start], wrong)[0] == 422)
            self.observations[kind] = {'identity': identity, 'frames': result['frames'], 'oracle': oracle}
            if kind == 'elf':
                wrong = dict(expected, code_id=expected['code_id'][:-1] + ('0' if expected['code_id'][-1] != '0' else '1'))
                self.check('elf.full_build_id_not_only_debug_prefix', self.send(file, [start], wrong)[0] == 422)
                self.check('elf.stripped_companion_not_fetched', self.send(self.fixtures / 'proof.stripped', [start], expected)[0] == 422)
                self.check('elf.explicit_debug_companion', self.send(self.fixtures / 'proof.debug', [start], expected)[0] == 200)
            if kind == 'pdb':
                pe = self.send(self.fixtures / 'proof.exe')[1]['objects'][0]
                self.check('pdb.guid_age_matches_pe_codeview', pe['debug_id'] == identity['debug_id'])
                self.check('pdb.age_mismatch_rejected', self.send(file, [start], dict(expected, debug_id=expected['debug_id'].rsplit('-', 1)[0] + '-2'))[0] == 422)
                self.check('pdb.absent_pe_code_identity_not_invented', identity['code_id'] is None and self.send(file, [start], dict(expected, code_id=pe['code_id']))[0] == 422)
                self.check('pe.absent_pdb_not_fetched', self.send(self.fixtures / 'proof.exe', [start], self.expected(pe))[0] == 422)
                self.check('pdb.appendix_tail_rejected', self.send(file, [start], dict(expected, debug_id=expected['debug_id'].rsplit('-', 1)[0] + '-00000001ffff'))[0] == 422)
                status, maximum = self.send(file, [start] * 500, expected)
                self.check('pdb.500_frames_preserved', status == 200 and len(maximum['frames']) == 500 and [f['index'] for f in maximum['frames']] == list(range(500)))
                self.check('pdb.501_frames_rejected', self.send(file, [start] * 501, expected)[0] == 422)
            if kind == 'macho':
                other = [item for item in inspection['objects'] if item['architecture'] != arch]
                self.check('macho.fat_two_real_slices', len(other) == 1)
                self.check('macho.cross_slice_identity_rejected', self.send(file, [start], dict(expected, architecture=other[0]['architecture']))[0] == 422)
                self.check('macho.other_slice_explicit_selection', self.send(file, [], self.expected(other[0]))[0] == 200)
                self.check('macho.uuid_matches_executed_binary', identity['debug_id'].upper() in build['macho']['uuids'])
        for depth in (31, 32):
            symbols = (self.fixtures / f'inline-{depth}-symbols.txt').read_text()
            match = re.search(r'^native_leaf T ([0-9a-f]+) ([0-9a-f]+)$', symbols, re.M)
            self.check(f'inline{depth}.real_function', match is not None)
            address, size = (int(value, 16) for value in match.groups())
            addresses = [hex(value) for value in range(address, address + size, 4)]
            oracle = json.loads(self.compiler(['/usr/lib/llvm21/bin/llvm-symbolizer', '--no-debuginfod',
                '--output-style=JSON', f'--obj=/proof/inline-{depth}.elf', *addresses]))
            deepest = max(oracle, key=lambda frame: len(frame['Symbol']))
            self.check(f'inline{depth}.independent_depth', len(deepest['Symbol']) == depth + 1)
            file = self.fixtures / f'inline-{depth}.elf'
            identity = self.send(file)[1]['objects'][0]
            status, result = self.send(file, [deepest['Address']], self.expected(identity))
            self.check(f'inline{depth}.exact_boundary', (status == 200 and len(result['frames'][0]['locations']) == 32) if depth == 31 else status == 422)
        # Derived size cases retain the real ELF prefix and add inert trailing padding.
        original = (self.fixtures / 'proof.elf').read_bytes()
        for extra, expected_status in ((0, 200), (1, 413)):
            binary = original + bytes(20 * 1024 * 1024 + extra - len(original))
            body = json.dumps({'object_base64':base64.b64encode(binary).decode(), 'expected':None, 'addresses':[]}).encode()
            self.check(f'decoded_binary_limit_plus_{extra}', self.send(None, body=body)[0] == expected_status)
        for body in (b'{}', b'not JSON', b'{"expected":null,"expected":null}', b'\xff'):
            self.check('invalid_input_rejected:' + hashlib.sha256(body).hexdigest()[:8], self.send(None, body=body)[0] == 422)
        self.check('random_binary_rejected', self.send(None, body=json.dumps({'object_base64':base64.b64encode(b'invalid binary').decode(),'expected':None,'addresses':[]}).encode())[0] == 422)
        parsed = urllib.parse.urlparse(self.endpoint)
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5)
        connection.putrequest('POST', '/symbolicate')
        connection.putheader('Content-Type', 'application/json')
        connection.putheader('Content-Length', str(28 * 1024 * 1024 + 1))
        connection.endheaders()
        self.check('wire_size_before_body', connection.getresponse().status == 413)
        connection.close()
        stalled = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5)
        stalled.putrequest('POST', '/symbolicate')
        stalled.putheader('Content-Type', 'application/json')
        stalled.putheader('Content-Length', '10')
        stalled.endheaders()
        # Allow the real server to enter the body read, then exercise its occupied slot.
        time.sleep(0.1)
        self.check('busy_request_rejected', self.send(self.fixtures / 'proof.elf')[0] == 503)
        self.check('body_deadline', stalled.getresponse().status == 408)
        stalled.close()
        self.check('service_recovers_after_body_deadline', self.send(self.fixtures / 'proof.elf')[0] == 200)
        self.observations['limitations'] = ['Local processor proof; no Rails, SDK crash transport or production deployment.',
            'PE/PDB is cross-compiled and compared with LLVM; no Windows execution.',
            'Addresses are module-relative instruction addresses; caller owns stack unwinding and return-address adjustment.']


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('fixtures', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--endpoint', default='http://127.0.0.1:39570')
    args = parser.parse_args()
    proof = Proof(args.fixtures.resolve(), args.endpoint)
    started = time.time()
    try:
        proof.run()
    finally:
        args.output.write_text(json.dumps({'schema_version':1,'claim':'implemented','duration_seconds':time.time()-started,
            'assertions':proof.assertions,'observations':proof.observations}, indent=2) + '\n')
    print(json.dumps({'passed':len(proof.assertions),'report':str(args.output)}))
