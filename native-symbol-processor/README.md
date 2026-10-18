# Native symbol processor

Local implementation candidate for CYRA-957. This is a private parser service, not
a public ingest route, an artifact store or a release/deployment claim. Sentry
Symbolic 13.9.0 parses debug objects and builds an in-memory SymCache. It never
opens a source path, follows a debug companion link, downloads a symbol or executes
an uploaded binary. Upstream source-server metadata is not resolved.

## Contract

`POST /symbolicate`, exactly `Content-Type: application/json`, one Content-Length,
no HTTP transfer/content encoding:

```json
{
  "object_base64": "<canonical base64 of one file>",
  "expected": {"format":"pdb","architecture":"x86_64","debug_id":"397bb368-5b91-d8ae-4c4c-44205044422e-1"},
  "addresses": ["0x1008"]
}
```

For inspection use `expected: null, addresses: []`. Inspection parses every
slice and validates present debug information by actually constructing its cache.
An upload can instead pass expected identity with zero addresses to validate the
binding. Any nonempty address list requires identity. Unknown fields are rejected.

Response 200:

```json
{
  "schema_version": 1,
  "objects": [{"format":"pdb","architecture":"x86_64","debug_id":"397bb368-5b91-d8ae-4c4c-44205044422e-1","code_id":null,"usable":true,"has_debug_info":true,"has_symbols":true,"preferred_load_address":"0x0"}],
  "selected": 0,
  "frames": [{"index":0,"address":"0x1008","status":"resolved","locations":[{"function":"inline_add(int)","symbol":"inline_add(int)","file":"/proof/fixture.c","line":10,"function_address":null},{"function":"native_leaf(int)","symbol":"native_leaf(int)","file":"/proof/fixture.c","line":15,"function_address":"0x1000"}]}]
}
```

`objects` contains each slice's file-derived identity. `selected` is null for an
unbound inspection or the unique matched slice index. Locations are innermost
inline function first. Unknown lines, paths and inline entry addresses remain
null. `symbol` is the parser-provided name; `function` applies Symbolic demangling.
PDB names may include a signature even when LLVM displays the bare C identifier.
The original address string and index are unchanged. No raw frame is overwritten;
the caller stores this derived result separately from its original crash report.

Addresses are **module-relative instruction addresses**, 0 through 0xfffffffe.
The caller owns stack unwinding, ASLR subtraction and architecture-appropriate
return-address adjustment. This service neither subtracts one from all frames nor
guesses an image base. SymCache's u32 address limit is explicit, not truncated.
An unmapped address has `status: unresolved, locations: []`.

## Exact identity and supported files

- `elf`: require full lowercase-normalized `code_id` (GNU build ID), plus debug ID
  and architecture. Symbolic's ELF debug ID uses only the first 16 build-ID bytes;
  matching that alone is insufficient. A synthesized .text hash without a build
  ID is not usable. Upload the ELF with DWARF or its explicit separate debug file.
- `macho`: UUID and architecture select exactly one slice, including universal
  files. Upload the actual DWARF file inside a dSYM, not the directory/ZIP.
- `pdb`: match GUID **and age**, with architecture. A PDB does not carry the PE
  code ID; `code_id` is null, and requiring a PE code ID against it fails closed.
- `pe`: inspect CodeView debug ID, architecture, code ID and preferred image base.
  PE without embedded DWARF is inspection-only; resolve its matching PDB as a
  separate explicit object. The service never reads the PDB path in the PE.

Formats and architectures are exact lowercase Symbolic names (`elf`, `macho`,
`pe`, `pdb`; real proof covers `arm64`, `x86_64`). IDs accept UUID36 or compact32,
optionally followed by 1–8 hexadecimal age digits (hyphen separator for UUID36).
Canonical output is lowercase UUID plus `-<age hex>` when nonzero. An age suffix
is never silently truncated; zero UUID is unusable. `code_id` is compared in full,
case-insensitively, and every supplied identity field must agree.

Missing/unreliable identity, unknown architecture, ambiguous slice, unsupported
format, malformed object or invalid debug data cannot produce a resolved result.
No Windows runtime support is inferred from static PE/PDB compilation.

## Bounds and isolation

20 MiB decoded file; 28 MiB JSON body (base64 plus bounded metadata fits); 16
archive slices; 500 addresses; 32 inline locations per address; 4096 UTF-8 bytes
per output name/path; 1 MiB complete output; 64 MiB serialized cache. A breached
bound rejects the whole request, never a silently shortened stack. The parser
child has RLIMIT_AS 384 MiB, CPU 10 seconds, 32 open files and disabled core dumps.
The parent enforces a 10-second wall deadline and kills the owned process group.
Header/body/write deadlines are 2 seconds, one active request, eight connections.

Failures contain only a static `R<status>-NATIVE-<number>` code: 422 invalid input,
identity mismatch or parser/output limit; 413 byte budget; 408 body deadline;
503 overload, subprocess deadline or storage failure. Parser stderr/panics are
discarded. File names, function names and source paths are private artifact
metadata, not public-safe output; the caller must enforce project visibility and
its display/privacy policy. No source text is returned.

Build from `services/ingest`:

```sh
docker build -f native-symbol-processor/Dockerfile -t cyi-native-symbol-processor:u13-local .
docker run -d --name cyi-native-symbol-u13-local --read-only --user 65532:65532 \
  --cap-drop=ALL --security-opt=no-new-privileges --memory=512m --memory-swap=512m \
  --cpus=1 --pids-limit=32 --ulimit core=0 --log-driver=none \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777 \
  -p 127.0.0.1:39570:8080 cyi-native-symbol-processor:u13-local
```

The shared crash processor's boot guard requires a read-only root, actual tmpfs,
non-root UID, no capabilities and no-new-privileges. Its inherited seccomp filter
denies TCP/UDP outbound calls and io_uring in the service and parser child; a real
socket probe validates this before listening. Loopback publication permits local
HTTP tests without granting egress. `/up` and `/version` expose bounded health and
processor identity. `/version` also exposes `app`, `tag`, `sha`, `short_sha`,
`build_time` and `environment`. Build args `GIT_TAG`, `GIT_SHA`, `BUILD_TIME` inject
the corresponding `APP_GIT_TAG`, `APP_GIT_SHA`, `APP_BUILD_TIME`; runtime `APP_ENV`
selects the environment. Missing/invalid values stay `unknown`, including local
builds; a dependency version does not masquerade as the wrapper's release.
No production configuration is changed by these commands.

## Reproducible real builds and verification

```sh
docker build -f native-symbol-processor/Fixture.Dockerfile -t cyi-native-symbol-fixtures:u13-local .
cd native-symbol-processor
mise exec rust@1.99.0 -- cargo test --locked
mise exec rust@1.99.0 -- cargo clippy --locked --all-targets -- -D warnings
python3 -m unittest discover -p test_processor.py
python3 build_fixtures.py /tmp/cyi-native-proof-new
python3 verify_real_builds.py /tmp/cyi-native-proof-new /tmp/cyi-native-proof-report.json
```

The fixture image pins LLVM 21.1.2. ELF is compiled and executed in Linux; macOS
builds a universal executable and dSYM with Apple clang/dsymutil and executes the
native arm64 slice. The cross-compiled PE/PDB is **not executed on Windows**.
LLVM symbolizer, independently from Symbolic, checks complete function/file/line
and inline ordering from actual compiled code. Fixture-specific C signatures
explain PDB name formatting without filtering stack frames. Compiler versions,
source/object hashes, runtime observations and failed assertions are retained.
An existing destination is refused to preserve previous evidence.

Rust 1.99.0, Symbolic 13.9.0 and direct dependencies are pinned; Cargo.lock pins
the transitive graph and checksums. Base images use immutable digests. Full
dependency license/notice files, including nested vendored components, and Cargo
metadata are copied under `/usr/share/licenses/native-symbol-bridge`. Retaining
notices is not legal approval and does not change CYRA-915.

Primary references: [Symbolic object API 13.9.0](https://docs.rs/symbolic-debuginfo/13.9.0/symbolic_debuginfo/enum.Object.html),
[SymCache 13.9.0](https://docs.rs/symbolic-symcache/13.9.0/symbolic_symcache/),
[DebugId parser 0.8.0](https://docs.rs/debugid/0.8.0/debugid/struct.DebugId.html),
[LLVM symbolizer](https://llvm.org/docs/CommandGuide/llvm-symbolizer.html).
