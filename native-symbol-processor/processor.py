"""Private native symbolication with bounded input, output and process lifetime."""
import base64
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import subprocess
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from base_processor import Handler as BaseHandler, Server as BaseServer, require_isolation
from isolation import deny_egress

MAX_INPUT = 28 * 1024 * 1024
MAX_OUTPUT = 1024 * 1024
PARSER_SECONDS = 10
PROCESS_SLOT = threading.BoundedSemaphore(1)


def build_identity():
    def value(key, pattern):
        raw = os.environ.get(key, 'unknown')
        return raw if re.fullmatch(pattern, raw) else 'unknown'
    sha = value('APP_GIT_SHA', r'[0-9a-f]{40}|[0-9a-f]{64}')
    return {'app': 'native-symbol-processor', 'tag': value('APP_GIT_TAG', r'[A-Za-z0-9._-]{1,64}'),
            'sha': sha, 'short_sha': sha[:7] if sha != 'unknown' else 'unknown',
            'build_time': value('APP_BUILD_TIME', r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z'),
            'environment': value('APP_ENV', r'development|test|staging|production|unknown')}


class Rejected(Exception):
    def __init__(self, status, number=1):
        self.status = status
        self.code = f'R{status}-NATIVE-{number:03}'


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Rejected(422)
        result[key] = value
    return result


def prepare(body):
    try:
        data = json.loads(body.decode('utf-8', errors='strict'), object_pairs_hook=unique_object)
        if not isinstance(data, dict) or set(data) != {'object_base64', 'expected', 'addresses'}:
            raise Rejected(422)
        encoded, expected, addresses = data['object_base64'], data['expected'], data['addresses']
        if not isinstance(encoded, str) or len(encoded) > 27962028:
            raise Rejected(413)
        binary = base64.b64decode(encoded, validate=True)
        if not binary or base64.b64encode(binary).decode('ascii') != encoded:
            raise Rejected(422)
        if len(binary) > 20 * 1024 * 1024:
            raise Rejected(413)
        if not isinstance(addresses, list) or len(addresses) > 500:
            raise Rejected(422)
        for address in addresses:
            if (not isinstance(address, str) or not re.fullmatch(r'0x[0-9a-fA-F]{1,8}', address)
                    or int(address, 16) >= 0xffffffff):
                raise Rejected(422)
        if expected is not None:
            if (not isinstance(expected, dict) or not {'format', 'architecture', 'debug_id'} <= set(expected)
                    or set(expected) - {'format', 'architecture', 'debug_id', 'code_id'}
                    or expected['format'] not in ('elf', 'macho', 'pe', 'pdb')):
                raise Rejected(422)
            if any(not isinstance(value, str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,128}', value)
                   for value in expected.values()):
                raise Rejected(422)
            if expected['format'] == 'elf' and 'code_id' not in expected:
                raise Rejected(422)
        elif addresses:
            raise Rejected(422)
        return binary, {'expected': expected, 'addresses': addresses}
    except (ValueError, UnicodeError, RecursionError, TypeError) as error:
        raise Rejected(422) from error


def symbolize(path, metadata_path, expected_groups):
    process = subprocess.Popen(['/app/native-symbol-bridge', str(path), str(metadata_path)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TMPDIR': '/tmp'},
        start_new_session=True)
    output = bytearray()
    deadline = time.monotonic() + PARSER_SECONDS
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Rejected(503)
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(chunk)
                        if len(output) > MAX_OUTPUT:
                            raise Rejected(422, 2)
        try:
            status = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            raise Rejected(503) from error
        if status != 0:
            raise Rejected(422, 2)
        try:
            result = json.loads(output)
            if (result['schema_version'] != 1 or len(result['frames']) != expected_groups
                    or [g['index'] for g in result['frames']] != list(range(expected_groups))):
                raise Rejected(422, 2)
        except (ValueError, KeyError, TypeError) as error:
            raise Rejected(422, 2) from error
        return output
    finally:
        # Escalate the owned group even when the leader has already exited.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        process.stdout.close()


class Handler(BaseHandler):
    def send_error(self, code, message=None, explain=None):
        self.reply(code, b'{"error":"R400-NATIVE-001"}')

    def do_GET(self):
        self.header_deadline.cancel()
        if self.path == '/up':
            self.reply(200, b'{"status":"ok"}')
        elif self.path == '/version':
            self.reply(200, json.dumps({**build_identity(), 'processor': 'native-symbols',
                'version': '13.9.0', 'schema_version': 1, 'outbound_syscalls_denied': True}).encode())
        else:
            self.reply(404, b'{"error":"R404-NATIVE-001"}')

    def do_POST(self):
        self.header_deadline.cancel()
        acquired = False
        try:
            if self.path != '/symbolicate':
                raise Rejected(404)
            if self.headers.get_all('Content-Type', []) != ['application/json']:
                raise Rejected(415)
            if self.headers.get_all('Transfer-Encoding') or self.headers.get_all('Content-Encoding'):
                raise Rejected(400)
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths) != 1 or not re.fullmatch(r'[0-9]{1,10}', lengths[0]):
                raise Rejected(411)
            length = int(lengths[0])
            if length > MAX_INPUT:
                raise Rejected(413)
            acquired = PROCESS_SLOT.acquire(blocking=False)
            if not acquired:
                raise Rejected(503, 2)
            body = bytearray()
            deadline = time.monotonic() + 2
            while len(body) < length:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Rejected(408)
                self.connection.settimeout(remaining)
                chunk = self.rfile.read1(min(65536, length - len(body)))
                if not chunk:
                    raise Rejected(422)
                body.extend(chunk)
            encoded, metadata = prepare(body)
            del body
            with tempfile.TemporaryDirectory(dir='/tmp', prefix='native-symbols-') as directory:
                path = Path(directory) / 'input.bin'
                path.write_bytes(encoded)
                del encoded
                metadata_path = Path(directory) / 'request.json'
                metadata_path.write_text(json.dumps(metadata), encoding='utf-8')
                result = symbolize(path, metadata_path, len(metadata['addresses']))
            self.reply(200, result)
        except Rejected as error:
            self.reply(error.status, json.dumps({'error': error.code}).encode())
        except (TimeoutError, socket.timeout):
            self.reply(408, b'{"error":"R408-NATIVE-001"}')
        except OSError:
            self.reply(503, b'{"error":"R503-NATIVE-003"}')
        finally:
            if acquired:
                PROCESS_SLOT.release()


class Server(BaseServer):
    def __init__(self, address):
        self.slots = threading.BoundedSemaphore(8)
        ThreadingHTTPServer.__init__(self, address, Handler)

    def handle_error(self, request, address):
        return  # No request values, parser diagnostics or stack traces in logs.


if __name__ == '__main__':
    require_isolation()
    deny_egress()
    Server(('0.0.0.0', 8080)).serve_forever()
