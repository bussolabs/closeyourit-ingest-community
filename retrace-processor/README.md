# Isolated R8 Retrace processor

CYRA-956 local implementation candidate. This private service reconstructs JVM
stack traces using official **R8 9.4.28**. It does not deploy or enable Rails
integration, certify Android devices or handle native NDK frames.

## Contract

`POST /retrace`, exactly one `Content-Type: application/json` and one decimal
`Content-Length`, no content/transfer encoding. JSON contains only:

- `mapping`: complete UTF-8 mapping, including semantic comments, at most **5 MiB**.
- `stacktrace`: **0–500 strings**, each at most **4096 UTF-8 bytes**, no CR/LF/NUL.

The complete HTTP body is limited to **10 MiB**. Duplicate JSON keys, malformed
Unicode, NUL in mappings and empty/comment-only mappings are rejected. A zero-line
stack validates the mapping through R8 with `loadAllDefinitions`; malformed,
unknown and experimental mapping versions fail. No source code, URL or referenced
file is fetched. Mapping text is never executed.

Response:

```json
{"schema_version":1,"groups":[{"index":0,"ambiguous":false,"alternatives":[{"lines":["..."]}]}]}
```

This is a schema illustration, not an observed event. Each group corresponds to
the same **zero-based input index**; the bridge rejects a cardinality mismatch.
An alternative can contain multiple lines after inlining. Empty alternatives can
represent a synthesized frame removed by R8. Ambiguity is preserved according to
R8's nonverbose rendered results; identical rendered alternatives can collapse.
The backend must never choose an arbitrary ambiguous alternative. Input must be
in ordinary Java stack order, including cause headers; Sentry event order differs
and is the caller's responsibility. Exactly one `retraceStackTrace` call processes
the entire stack with shared context, never independent calls per frame.

Limits: **20 alternatives per group, 2000 output lines, 16384 UTF-8 bytes per
output line, 1 MiB complete response**. Exceeding a bound fails, never truncates.
Raw exception messages can appear in a private result; Rails remains responsible
for its existing privacy projection before storage or display. This service
does not claim that arbitrary exception text is free of personal information.

Status codes: 200 result; 400 framing; 411 invalid/missing length; 413 request/map
size; 415 media type; 422 mapping/input/output rejection; 408 body deadline;
503 busy, process deadline or unavailable subprocess. Error bodies contain only
static `R<status>-RETRACE-<number>` codes. No rejected mapping, stack or R8
diagnostic is logged or returned as an error. `/up` is liveness; `/version`
identifies R8 and the enforced outbound syscall restrictions.

## Runtime isolation

Build from **services/ingest**, allowing unchanged shared isolation helpers to be
copied from `crash-processor`; no crash source is modified:

```sh
docker build --platform linux/arm64 -f retrace-processor/Dockerfile \
  -t cyi-retrace-processor:local .
docker run --name cyi-retrace-local --platform linux/arm64 --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=32m,mode=1777 \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory 384m --cpus 1 --pids-limit 64 --log-driver none \
  -p 127.0.0.1:39560:8080 cyi-retrace-processor:local
```

Local lab only, not a deployment instruction. The HTTP service is unauthenticated
and must remain private behind Rails project authorization. No public port,
Compose service, operator configuration or production rollout is added.

Startup verifies read-only root, actual tmpfs, nonzero UID, no capabilities and
NoNewPrivs. Before listening, the shared seccomp helper denies outbound connect,
sendto/sendmsg/sendmmsg and io_uring, verifies TCP/UDP denial and actual exec-child
inheritance. Responses use writes on already accepted sockets. At most eight
connections and one processing request are admitted. Headers and body each have
a **2-second total deadline**, Java has **8 seconds**, response writes at most
**2 seconds**. The owned process group is killed even if its leader already exited.

Java uses a clean environment, 128 MiB heap, 96 MiB metaspace, serial GC and one
active processor. stderr is discarded; stdout is bounded while reading. A private
tmpfs directory stores a length-prefixed binary input for that one subprocess and
is removed afterward. No request data reaches a durable file or container log.

The Dockerfile pins the Python 3.14.4/Alpine 3.23 arm64 manifest, OpenJDK
21.0.12_p8-r0 and libseccomp 2.6.0-r1. The official Google Maven R8 jar is verified
against SHA-256 `51af0a9d41cc541d619064224aec628923bd779cbcc5a62cb914ea2d669c4063`.
Its complete embedded LICENSE, including third-party notices, is preserved at
`/usr/share/licenses/r8/LICENSE`; the jar remains unchanged.

R8's public `getMapVersions` API returns a raw set whose metadata type is obfuscated
to `com.android.tools.r8.naming.mappinginformation.b` in this exact distribution.
The bridge explicitly uses its `o()` MapVersion accessor. Upgrades require source
review and recompilation; no reflection or substitute mapping parser hides drift.

## Real proof

With the isolated service running:

```sh
mise exec -- python3 retrace-processor/test_processor.py \
  http://127.0.0.1:39560 /absolute/path/r8-9.4.28.jar /tmp/owned-r8-proof-new
```

The test compiles an owned Java program with the configured JDK, runs it, then
uses official R8 to optimize/obfuscate and runs the transformed program. The full
recovered stack must exactly match the original execution, including cause
context and inline expansion. A second actual program proves ambiguous renamed
methods after deliberately removing line positions from its observed stack.
Derived repetition of an actual inline frame checks expansion bounds. Zero/one/N,
validate-only malformed/unknown versions, request bounds, duplicate framing,
body/header deadlines and single-slot admission are exercised over actual HTTP.
Only sanitized check summaries/digests are printed. Owned compiler outputs remain
in the explicitly supplied fresh temporary directory for review.

This processor proof is independent of Sentry SDK transport, CLI upload, private
Rails persistence and authenticated readback. Those require the separate Labs
end-to-end run; a processor-only success cannot certify that chain.

Sources: [Android Retrace](https://developer.android.com/tools/retrace),
[R8 mapping semantics](https://r8.googlesource.com/r8/+/refs/heads/main/doc/retrace.md),
[official R8 Maven artifact](https://dl.google.com/dl/android/maven2/com/android/tools/r8/9.4.28/r8-9.4.28.jar).
