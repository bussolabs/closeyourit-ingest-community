"""Real HTTP boundaries and mutations of an actual sanitized crash report, not dump fixtures."""
import copy
import http.client
import json
import socket
import sys
import time
import unittest
from urllib.parse import urlsplit

from processor import Rejected, project_report

PROOF = json.load(sys.stdin)
TARGET = urlsplit(sys.argv.pop(1))


def upstream_shape():
    report = copy.deepcopy(PROOF['report'])
    report['status'] = 'OK'
    report.pop('schema_version')
    system = report['system_info']
    if 'os_version' in system:
        system['os_ver'] = system.pop('os_version')
    for thread in report['threads']:
        for frame in thread['frames']:
            if 'instruction' in frame:
                frame['offset'] = frame.pop('instruction')
    return report


class ProcessorTest(unittest.TestCase):
    def request(self, path, body=None, headers=None):
        connection = http.client.HTTPConnection(TARGET.hostname, TARGET.port, timeout=5)
        try:
            connection.request('POST' if body is not None else 'GET', path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_actual_crash_has_matching_build_and_private_memory_removed(self):
        self.assertEqual(PROOF['crash_exit_code'], -11)
        self.assertEqual(PROOF['processor_status'], 200)
        self.assertTrue(PROOF['privacy']['sentinel_in_dump'])
        self.assertTrue(PROOF['privacy']['sentinel_absent_from_report'])
        module = next(row for row in PROOF['report']['modules'] if row['filename'] == 'cyi-native-crash')
        self.assertEqual(module['code_id'], PROOF['build_id'])
        self.assertTrue(module['debug_id'])
        self.assertTrue(any(row['frames'] for row in PROOF['report']['threads']))

    def test_projection_preserves_actual_allowed_fields(self):
        self.assertEqual(json.loads(project_report(upstream_shape())), PROOF['report'])

    def test_registers_memory_annotations_and_function_args_are_not_projected(self):
        source = upstream_shape()
        source['memory'] = 'private-memory'
        source['annotations'] = {'secret': 'private-annotation'}
        source['threads'][0]['frames'][0].update(registers={'x1': 'private-register'}, function_args=['private-argument'])
        result = project_report(source).decode()
        for sentinel in ('private-memory', 'private-annotation', 'private-register', 'private-argument'):
            self.assertNotIn(sentinel, result)

    def test_arbitrary_text_is_scrubbed_and_module_paths_drop_directories(self):
        source = upstream_shape()
        source['system_info']['os_ver'] = 'tester@example.test password=private-value https://user:pass@example.test/?key=value'
        source['modules'][0]['filename'] = '/private/user-home/bin/app'
        result = json.loads(project_report(source))
        serialized = json.dumps(result)
        for sentinel in ('tester@example.test', 'private-value', 'user:pass', 'user-home'):
            self.assertNotIn(sentinel, serialized)
        self.assertEqual(result['modules'][0]['filename'], 'app')

    def test_budget_overflows_fail_without_truncation(self):
        for kind in ('threads', 'frames', 'modules'):
            with self.subTest(kind=kind):
                source = upstream_shape()
                if kind == 'threads':
                    source['threads'] = source['threads'][:1] * 129
                elif kind == 'frames':
                    source['threads'][0]['frames'] = source['threads'][0]['frames'][:1] * 257
                else:
                    source['modules'] = source['modules'][:1] * 513
                with self.assertRaises(Rejected) as failure:
                    project_report(source)
                self.assertEqual(failure.exception.status, 422)

    def test_actual_service_reports_egress_filter_and_liveness(self):
        status, version = self.request('/version')
        self.assertEqual(status, 200)
        self.assertEqual(version['version'], '0.27.0')
        self.assertTrue(version['outbound_syscalls_denied'])
        self.assertEqual(self.request('/up')[0], 200)

    def test_invalid_magic_and_real_walker_rejection(self):
        for body in (b'not-a-minidump' * 4, b'MDMP' + bytes(28)):
            with self.subTest(length=len(body)):
                status, body = self.request('/process', body, {'Content-Type': 'application/octet-stream'})
                self.assertEqual(status, 422)
                self.assertEqual(body, {'error': 'R422-CRASH-001'})

    def test_oversize_rejected_before_body_read(self):
        status, _ = self.request('/process', b'', {'Content-Type': 'application/octet-stream', 'Content-Length': str(10 * 1024 * 1024 + 1)})
        self.assertEqual(status, 413)

    def test_compressed_and_wrong_media_type_rejected(self):
        status, _ = self.request('/process', b'MDMP' + bytes(28), {'Content-Type': 'application/octet-stream', 'Content-Encoding': 'gzip'})
        self.assertEqual(status, 400)
        self.assertEqual(self.request('/process', b'{}', {'Content-Type': 'application/json'})[0], 415)

    def test_header_deadline_is_total_even_when_bytes_keep_arriving(self):
        with socket.create_connection((TARGET.hostname, TARGET.port), timeout=5) as slow:
            started = time.monotonic()
            slow.sendall(b'POST /process HTTP/1.1\r\nHost: processor\r\n')
            for _ in range(3):
                time.sleep(0.5)
                slow.sendall(b'X-Slow: partial\r\n')
            self.assertEqual(slow.recv(1), b'')
            self.assertLess(time.monotonic() - started, 3)

    def test_busy_and_absolute_body_deadline_release_capacity(self):
        with socket.create_connection((TARGET.hostname, TARGET.port), timeout=5) as slow:
            slow.sendall(b'POST /process HTTP/1.1\r\nHost: processor\r\nContent-Type: application/octet-stream\r\nContent-Length: 100\r\n\r\nMDMP')
            # Give the already-sent partial request its processing slot before racing another.
            time.sleep(0.05)
            deadline = time.monotonic() + 1
            status = None
            while status != 503 and time.monotonic() < deadline:
                status, _ = self.request('/process', b'MDMP' + bytes(28), {'Content-Type': 'application/octet-stream'})
            self.assertEqual(status, 503)
            response = http.client.HTTPResponse(slow)
            response.begin()
            self.assertEqual(response.status, 408)
            response.read()
        self.assertEqual(self.request('/process', b'MDMP' + bytes(28), {'Content-Type': 'application/octet-stream'})[0], 422)


if __name__ == '__main__':
    unittest.main()
