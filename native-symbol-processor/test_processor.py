"""Boundary tests for the private native symbol processor."""
import base64
import importlib.util
import json
from pathlib import Path
import sys
import subprocess
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'crash-processor'))
spec = importlib.util.spec_from_file_location('base_processor', ROOT.parent / 'crash-processor/processor.py')
base = importlib.util.module_from_spec(spec)
sys.modules['base_processor'] = base
spec.loader.exec_module(base)
spec = importlib.util.spec_from_file_location('native_processor', ROOT / 'processor.py')
processor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(processor)


class RequestBoundaries(unittest.TestCase):
    def test_build_identity_uses_injected_values_without_claiming_a_local_release(self):
        with patch.dict(processor.os.environ, {'APP_GIT_TAG':'unknown','APP_GIT_SHA':'unknown','APP_BUILD_TIME':'unknown','APP_ENV':'test'}):
            self.assertEqual('unknown', processor.build_identity()['tag'])
        with patch.dict(processor.os.environ, {'APP_GIT_TAG':'v0.1.0','APP_GIT_SHA':'a'*40,'APP_BUILD_TIME':'2026-10-04T09:00:00Z','APP_ENV':'test'}):
            identity = processor.build_identity()
            self.assertEqual('a'*40, identity['sha'])
            self.assertEqual('a'*7, identity['short_sha'])
            self.assertEqual('v0.1.0', identity['tag'])
            self.assertEqual('test', identity['environment'])
            self.assertEqual('2026-10-04T09:00:00Z', identity['build_time'])

    def request(self, **changes):
        data = {'object_base64': base64.b64encode(b'actual file is parsed by the child').decode(),
                'addresses': [], 'expected': None}
        data.update(changes)
        return json.dumps(data).encode()

    def test_inspection_accepts_zero_addresses_without_claiming_identity(self):
        binary, metadata = processor.prepare(self.request())
        self.assertTrue(binary)
        self.assertEqual([], metadata['addresses'])

    def test_resolution_requires_exact_expected_identity(self):
        with self.assertRaises(processor.Rejected):
            processor.prepare(self.request(addresses=['0x1']))

    def test_rejects_noncanonical_base64_duplicate_keys_and_utf16(self):
        for body in (self.request(object_base64='YQ'), b'{"addresses":[],"addresses":[]}',
                     self.request().decode().encode('utf-16')):
            with self.subTest(body_length=len(body)), self.assertRaises(processor.Rejected):
                processor.prepare(body)

    def test_rejects_lossy_offsets_and_excessive_requests(self):
        expected = {'format': 'elf', 'architecture': 'x86_64', 'debug_id': 'a'}
        for addresses in (['0xffffffff'], ['-1'], [1], ['0x1'] * 501):
            with self.subTest(count=len(addresses)), self.assertRaises(processor.Rejected):
                processor.prepare(self.request(addresses=addresses, expected=expected))

    def test_rejects_unknown_expected_fields_and_empty_binary(self):
        for changes in ({'expected': {'path': '/private/file'}}, {'object_base64': ''}):
            with self.assertRaises(processor.Rejected):
                processor.prepare(self.request(**changes))

    def test_requires_full_elf_build_id(self):
        with self.assertRaises(processor.Rejected):
            processor.prepare(self.request(expected={'format':'elf','architecture':'arm64','debug_id':'a'}))

    def test_accepts_500_addresses_and_rejects_501_without_truncation(self):
        expected = {'format':'pdb','architecture':'x86_64','debug_id':'397bb368-5b91-d8ae-4c4c-44205044422e-1'}
        _, metadata = processor.prepare(self.request(expected=expected, addresses=['0x10'] * 500))
        self.assertEqual(500, len(metadata['addresses']))
        with self.assertRaises(processor.Rejected):
            processor.prepare(self.request(expected=expected, addresses=['0x10'] * 501))


class RealChildBounds(unittest.TestCase):
    """Unit tests inject an owned executable, never a fabricated E2E success response."""

    def child(self, source):
        original = subprocess.Popen
        return lambda _args, **kwargs: original([sys.executable, '-c', source], **kwargs)

    def test_deadline_covers_a_descendant_holding_stdout_after_parent_exit(self):
        source = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(20)'])"
        start = time.monotonic()
        with patch.object(processor.subprocess, 'Popen', self.child(source)), patch.object(processor, 'PARSER_SECONDS', 0.1):
            with self.assertRaises(processor.Rejected) as error:
                processor.symbolize(Path('/unused'), Path('/unused'), 0)
        self.assertEqual(503, error.exception.status)
        self.assertLess(time.monotonic() - start, 1.5)

    def test_output_budget_stops_an_actual_noisy_child(self):
        with patch.object(processor.subprocess, 'Popen', self.child("import os,time; os.write(1,b'x'*4096); time.sleep(20)")), patch.object(processor, 'MAX_OUTPUT', 64):
            with self.assertRaises(processor.Rejected) as error:
                processor.symbolize(Path('/unused'), Path('/unused'), 0)
        self.assertEqual(422, error.exception.status)


if __name__ == '__main__':
    unittest.main()
