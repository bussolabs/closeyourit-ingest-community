"""Compile, obfuscate and crash an owned Java program, then test the real HTTP processor."""
import hashlib
import http.client
import json
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
from urllib.parse import urlsplit

SOURCE = '''package proof;
public class Crash {
  private static int leaf(int value) {
    if (value == 0) throw new IllegalArgumentException("owned-retrace-proof");
    return value + 1;
  }
  private static void first() { leaf(0); }
  private static void second() { first(); }
  private static void third() { second(); }
  private static void boundary() { third(); }
  public static void main(String[] args) {
    try { boundary(); }
    catch (RuntimeException error) { throw new IllegalStateException("outer-proof", error); }
  }
}
'''
AMBIGUOUS_SOURCE = '''package proof;
public class Crash {
  private static void first(int value) { throw new IllegalArgumentException("integer-proof"); }
  private static void second(String value) { throw new IllegalStateException("string-proof"); }
  public static void main(String[] args) {
    if (args.length == 0) first(0); else second(args[0]);
  }
}
'''


def command(argv, expected=0):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)
    if result.returncode != expected:
        raise AssertionError('Owned compilation or execution failed')
    return result


def compile_proof(directory, jar, ambiguous=False):
    root = Path(directory)
    source = root / 'Crash.java'
    source.write_text(AMBIGUOUS_SOURCE if ambiguous else SOURCE)
    classes = root / 'classes'
    classes.mkdir()
    command(['javac', '-g', '-d', str(classes), str(source)])
    original = command(['java', '-cp', str(classes), 'proof.Crash'], expected=1).stderr.decode().splitlines()
    input_jar = root / 'input.jar'
    command(['jar', 'cf', str(input_jar), '-C', str(classes), '.'])
    rules = root / 'rules.txt'
    rules.write_text('-keep public class proof.Crash { public static void main(java.lang.String[]); }\n'
                     '-keepattributes SourceFile,LineNumberTable\n' + ('-dontoptimize\n' if ambiguous else ''))
    mapping, output = root / 'mapping.txt', root / 'obfuscated.jar'
    settings = command(['java', '-XshowSettings:properties', '-version']).stderr.decode()
    java_home = re.search(r'^\s*java.home = (.+)$', settings, re.MULTILINE).group(1)
    command(['java', '-cp', str(jar), 'com.android.tools.r8.R8', '--classfile', '--release',
             '--lib', str(java_home), '--pg-conf', str(rules), '--pg-map-output', str(mapping),
             '--output', str(output), str(input_jar)])
    stack = command(['java', '-cp', str(output), 'proof.Crash'], expected=1).stderr.decode().splitlines()
    assert original != stack, 'The real program must actually be transformed'
    return mapping.read_text(), stack, original


def request(endpoint, payload, headers=None):
    url = urlsplit(endpoint)
    connection = http.client.HTTPConnection(url.hostname, url.port, timeout=15)
    data = json.dumps(payload).encode() if not isinstance(payload, bytes) else payload
    try:
        connection.request('POST', '/retrace', data, headers or {'Content-Type': 'application/json'})
        response = connection.getresponse()
        return response.status, json.loads(response.read(1024 * 1024 + 1))
    finally:
        connection.close()


def raw(endpoint, headers, body=b''):
    url = urlsplit(endpoint)
    with socket.create_connection((url.hostname, url.port), timeout=4) as connection:
        connection.sendall(b'POST /retrace HTTP/1.1\r\nHost: localhost\r\n' + headers + b'\r\n' + body)
        return connection.recv(4096).split(b'\r\n', 1)[0]


def run(endpoint, jar, proof_directory):
    assert hashlib.sha256(Path(jar).read_bytes()).hexdigest() == '51af0a9d41cc541d619064224aec628923bd779cbcc5a62cb914ea2d669c4063', 'The proof requires the pinned official R8 jar'
    mapping, stack, original = compile_proof(proof_directory, jar)
    payload = {'mapping': mapping, 'stacktrace': stack}
    status, result = request(endpoint, payload)
    assert status == 200, f'Actual R8 request returned status {status}'
    assert result['schema_version'] == 1
    assert [group['index'] for group in result['groups']] == list(range(len(stack)))
    assert all(not group['ambiguous'] for group in result['groups'])
    lines = [line for group in result['groups'] for alternative in group['alternatives'] for line in alternative['lines']]
    # Compare the complete recovered stack, including cause context and inline frames.
    assert lines == original, 'The real recovered stack must match the unoptimized execution exactly'
    assert any(len(group['alternatives'][0]['lines']) > 1 for group in result['groups'] if group['alternatives']), 'An actual inline expansion must be exercised'
    inline_index = next(group['index'] for group in result['groups'] if len(group['alternatives'][0]['lines']) > 4)
    oversized = request(endpoint, {'mapping': mapping, 'stacktrace': [stack[inline_index]] * 500})
    assert oversized[0] == 422, 'Expansion beyond 2000 output lines must be rejected'
    ambiguous_root = Path(proof_directory) / 'ambiguous'
    ambiguous_root.mkdir()
    ambiguous_map, ambiguous_stack, _ = compile_proof(ambiguous_root, jar, ambiguous=True)
    # Deliberately remove positions from real frames to exercise genuine overload ambiguity.
    ambiguous_stack = [re.sub(r':\d+\)', ')', line) for line in ambiguous_stack]
    ambiguous_status, ambiguous_result = request(endpoint, {'mapping': ambiguous_map, 'stacktrace': ambiguous_stack})
    assert ambiguous_status == 200
    alternatives = [group for group in ambiguous_result['groups'] if group['ambiguous']]
    assert alternatives and all(len(group['alternatives']) >= 2 for group in alternatives)
    assert request(endpoint, {'mapping': mapping, 'stacktrace': []}) == (200, {'schema_version': 1, 'groups': []})
    one = request(endpoint, {'mapping': mapping, 'stacktrace': [stack[0]]})
    assert one[0] == 200 and len(one[1]['groups']) == 1
    for data, expected in [
        ({'mapping': mapping, 'stacktrace': ['x'] * 501}, 422),
        ({'mapping': mapping, 'stacktrace': ['x' * 4097]}, 422),
        ({'mapping': mapping, 'stacktrace': ['x\ny']}, 422),
        ({'mapping': 'x' * (5 * 1024 * 1024 + 1), 'stacktrace': []}, 413),
        ({'mapping': '\0', 'stacktrace': []}, 422),
        ({'mapping': '# No definitions', 'stacktrace': []}, 422),
        ({'mapping': 'not a mapping', 'stacktrace': []}, 422),
        ({'mapping': mapping.replace('"version":"2.2"', '"version":"999.0"'), 'stacktrace': []}, 422),
        ({'mapping': mapping, 'stacktrace': stack, 'unexpected': True}, 422),
        (b'{"mapping":', 422),
        (json.dumps(payload).encode('utf-16'), 422),
        (json.dumps(payload).encode('utf-32'), 422),
        (b'{"mapping":"one","mapping":"two","stacktrace":[]}', 422),
    ]:
        observed, diagnostic = request(endpoint, data)
        assert observed == expected and set(diagnostic) == {'error'}
        assert re.fullmatch(r'R\d{3}-RETRACE-\d{3}', diagnostic['error'])
    assert b'413' in raw(endpoint, b'Content-Type: application/json\r\nContent-Length: 10485761\r\n')
    assert b'411' in raw(endpoint, b'Content-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n', b'{}')
    assert b'400' in raw(endpoint, b'Content-Type: application/json\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n', b'{}')
    start = time.monotonic()
    assert b'408' in raw(endpoint, b'Content-Type: application/json\r\nContent-Length: 20\r\n', b'{')
    assert time.monotonic() - start < 4
    url = urlsplit(endpoint)
    with socket.create_connection((url.hostname, url.port), timeout=4) as slow:
        slow.sendall(b'POST /retrace HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{')
        deadline = time.monotonic() + 1
        while True:
            busy, _ = request(endpoint, {'mapping': mapping, 'stacktrace': []})
            if busy == 503:
                break
            assert time.monotonic() < deadline, 'The owned slow request must hold the processing slot'
        assert b'408' in slow.recv(4096).split(b'\r\n', 1)[0]
    with socket.create_connection((url.hostname, url.port), timeout=4) as slow_header:
        slow_header.sendall(b'POST /retrace HTTP/1.1\r\nHost:')
        start = time.monotonic()
        assert slow_header.recv(4096) == b''
        assert time.monotonic() - start < 4
    report = {'claim': 'implemented', 'processor': 'R8 9.4.28',
              'input_lines': len(stack), 'output_lines': len(lines),
              'mapping_sha256': hashlib.sha256(mapping.encode()).hexdigest(),
              'checks': ['actual_java_compile_obfuscate_crash', 'full_stack_exact', 'inline_expansion',
                         'cause_context', 'real_overload_ambiguity', 'output_expansion_budget',
                         'zero_one_many', 'input_budgets', 'framing', 'body_deadline',
                         'single_processing_slot', 'header_deadline', 'validate_only_unknown_version'],
              'limitations': ['Owned JVM program only; no Android device or Sentry SDK certification.']}
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('Usage: test_processor.py LOOPBACK_URL R8_JAR OWNED_PROOF_DIRECTORY')
    # Explicit output directory retains only this owned compiler fixture, never user mappings.
    Path(sys.argv[3]).mkdir(mode=0o700, parents=True, exist_ok=False)
    run(*sys.argv[1:])
