# Isolated crash processor

CYRA-954 implementation candidate. This service converts an actual minidump into a
small structured report **before** any durable queue or storage. It does not store
raw dumps and does not provide symbolication, native-mobile certification or a
production-capacity claim.

## Contract

`POST /process`, `Content-Type: application/octet-stream`, one `Content-Length`,
no transfer/content encoding. Rails owns multipart/envelope parsing and bounded
decompression. The processor accepts at most **10 MiB**, rejects non-minidump
magic, and executes upstream `minidump-stackwalk 0.27.0` without a symbol server.

A successful response is JSON with `schema_version: 1` and these fields only:

- `system_info`: `os`, `cpu_arch`, `os_version` (upstream `os_ver`).
- `crash_info`: `type`, `address`, `crashing_thread` (upstream **thread-array index**).
- `threads`: `thread_id`, `frames` containing `instruction` (upstream `offset`),
  `module`, `module_offset`, `trust`.
- `modules`: `base_addr`, `end_addr`, `code_id`, `debug_id`, `filename`.

Optional null values are omitted. Addresses and build/debug identifiers retain
exact string values. Paths become basenames; credential patterns, email addresses,
URLs and control characters are filtered. These deterministic rules do not claim
recognition of every personal identifier in arbitrary text. Raw memory, register
values, assertion text, annotations, function arguments and arbitrary upstream
fields never enter the projection.

Limits are **128 threads, 256 frames per thread, 512 modules, 1 MiB response** and
8 MiB intermediate JSON in memory. Excess is rejected, not silently truncated.
Headers and request bodies each have a **2-second total deadline**; stackwalking
has an **8-second deadline**, one concurrent processing slot, at most eight client
connections. A killed/failed parser cannot produce a successful response.

Responses: 200 report; 400 framing/encoding; 411 invalid length; 413 input size;
415 media type; 422 invalid dump/projection/budget; 408 body deadline; 503 busy,
processing deadline or unavailable processor. Error bodies contain only static
`R<status>-CRASH-<number>` identifiers, never rejected values. Slow/incomplete
headers are closed after their deadline. Saturated connection slots are closed.
`GET /up` reports liveness; `/version` identifies the parser and successful
outbound-filter startup checks.

## Local build and isolation

The Dockerfile pins the official Python **3.14.4 Alpine 3.23 arm64** base manifest,
upstream Linux x86_64 musl walker archive SHA-256 and libseccomp **2.6.0-r1**.
The upstream MIT license is included in the image. The wrapper is native arm64;
the walker uses Docker's x86_64 emulation in the current local proof. Other host
architectures and emulation performance are not established by that proof.

```sh
docker build --platform linux/arm64 -t cyi-crash-processor:local .
docker network create cyi-crash-lab
docker run --name cyi-crash-processor --network cyi-crash-lab \
  --platform linux/arm64 --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m,mode=1777 \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory 256m --cpus 1 --pids-limit 32 --log-driver none \
  -p 127.0.0.1:39540:8080 cyi-crash-processor:local
```

This is a local lab command, not a deployment procedure. Never publish the port on
all interfaces. The HTTP service has no public authentication boundary; Rails
must authenticate the project before calling its fixed private URL.

Startup fails unless `/tmp` is an actual tmpfs, root is read-only, UID is nonzero,
capabilities are empty and `NoNewPrivs` is enabled. An additional libseccomp filter
is installed **before listen/fork/exec**, leaving Docker's default filter intact.
It denies `connect`, `sendto`, `sendmsg`, `sendmmsg` and all `io_uring` entry points.
The process and a real exec child test TCP/UDP/sendmsg rejection with `EPERM` at
startup. Responses use `write` on already accepted sockets. Parser children get a
clean environment, no inherited client sockets, bounded stdout, discarded stderr,
and no symbol-server arguments. The real emulated stackwalker must also complete
under this inherited filter; testing a separate `docker exec` process would not
prove inheritance.

Dump files exist only in private temporary directories on tmpfs and are unlinked
after processing. Parser JSON stays in bounded pipes/memory. No request body,
header, path, dump or parser stderr is logged. Container logging is disabled.
Puma/Rack can spool bodies **before** Rails parses them: the Rails crash feature
must enforce a RAM-backed `TMPDIR` before boot too. A volatile processor alone is
insufficient to protect the earlier ingress hop.

## Proof and checks

The producer lives in `closeyourit-labs/consumers/native_crash`. It builds official
Sentry Native **0.17.1**, uses vendored Breakpad, and crashes only its dedicated
benign process. The actual ELF build ID is checked against the processed module's
`code_id`; frames and a debug ID must exist. A deliberate stack-memory sentinel
must occur in the actual dump and be absent from the projected report. No raw
minidump fixture is committed or exported.

With the service running and a freshly generated sanitized producer report:

```sh
python3 test_processor.py http://127.0.0.1:39540 < /absolute/path/producer-proof.json
```

The checks use real HTTP/stackwalker rejection and derived mutations of that
actual sanitized report for privacy and limits. They do not invent a dump or
mock the service. Full authenticated Rails persistence, download and tenant
checks belong to Labs `bin/certify-native-crash`; a processor-only success cannot
certify that chain. Failed dossiers remain unchanged.

Sources: [Sentry Native](https://github.com/getsentry/sentry-native/tree/0.17.1),
[minidump protocol/privacy](https://docs.sentry.io/platforms/native/guides/minidumps/),
[rust-minidump 0.27.0](https://github.com/rust-minidump/rust-minidump/releases/tag/v0.27.0),
[processor JSON schema](https://github.com/rust-minidump/rust-minidump/blob/v0.27.0/minidump-processor/json-schema.md),
[seccomp rules](https://man7.org/linux/man-pages/man3/seccomp_rule_add.3.html),
[libseccomp package](https://pkgs.alpinelinux.org/package/v3.23/main/x86_64/libseccomp).
