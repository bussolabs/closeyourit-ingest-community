"""Private R8 full-stack retracing with bounded input, output and process lifetime."""
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from base_processor import Handler as BaseHandler, Server as BaseServer, require_isolation
from isolation import deny_egress

MAX_INPUT = 10 * 1024 * 1024
MAX_OUTPUT = 1024 * 1024
PROCESS_SLOT = threading.BoundedSemaphore(1)


class Rejected(Exception):
    def __init__(self, status, number=1):
        self.status = status
        self.code = f'R{status}-RETRACE-{number:03}'


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
        if not isinstance(data, dict) or set(data) != {'mapping', 'stacktrace'}:
            raise Rejected(422)
        mapping, stack = data['mapping'], data['stacktrace']
        if not isinstance(mapping, str) or not mapping.strip() or '\0' in mapping:
            raise Rejected(422)
        if not any(line.strip() and not line.lstrip().startswith('#') for line in mapping.splitlines()):
            raise Rejected(422)
        mapping = mapping.encode('utf-8')
        if len(mapping) > 5 * 1024 * 1024:
            raise Rejected(413)
        if not isinstance(stack, list) or len(stack) > 500:
            raise Rejected(422)
        chunks = [struct.pack('>I', len(mapping)), mapping, struct.pack('>I', len(stack))]
        for line in stack:
            if not isinstance(line, str) or any(c in line for c in '\r\n\0'):
                raise Rejected(422)
            encoded = line.encode('utf-8')
            if len(encoded) > 4096:
                raise Rejected(422)
            chunks.extend((struct.pack('>I', len(encoded)), encoded))
        return b''.join(chunks), len(stack)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Rejected(422) from error


def retrace(path, expected_groups):
    process = subprocess.Popen(['/usr/bin/java', '-Xms16m', '-Xmx128m',
        '-XX:MaxMetaspaceSize=96m', '-XX:+UseSerialGC', '-XX:ActiveProcessorCount=1',
        '-XX:-UsePerfData', '-XX:-CreateCoredumpOnCrash', '-XX:ErrorFile=/dev/null',
        '-cp', '/app:/app/r8.jar', 'RetraceBridge', str(path)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TMPDIR': '/tmp'},
        start_new_session=True)
    output = bytearray()
    deadline = time.monotonic() + 8
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
            if (result['schema_version'] != 1 or len(result['groups']) != expected_groups
                    or [g['index'] for g in result['groups']] != list(range(expected_groups))):
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
        self.reply(code, b'{"error":"R400-RETRACE-001"}')

    def do_GET(self):
        self.header_deadline.cancel()
        if self.path == '/up':
            self.reply(200, b'{"status":"ok"}')
        elif self.path == '/version':
            self.reply(200, b'{"processor":"r8-retrace","version":"9.4.28","schema_version":1,"outbound_syscalls_denied":true}')
        else:
            self.reply(404, b'{"error":"R404-RETRACE-001"}')

    def do_POST(self):
        self.header_deadline.cancel()
        acquired = False
        try:
            if self.path != '/retrace':
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
            encoded, groups = prepare(body)
            del body
            with tempfile.TemporaryDirectory(dir='/tmp', prefix='retrace-') as directory:
                path = Path(directory) / 'input.bin'
                path.write_bytes(encoded)
                del encoded
                result = retrace(path, groups)
            self.reply(200, result)
        except Rejected as error:
            self.reply(error.status, json.dumps({'error': error.code}).encode())
        except (TimeoutError, socket.timeout):
            self.reply(408, b'{"error":"R408-RETRACE-001"}')
        except OSError:
            self.reply(503, b'{"error":"R503-RETRACE-003"}')
        finally:
            if acquired:
                PROCESS_SLOT.release()


class Server(BaseServer):
    def __init__(self, address):
        self.slots = threading.BoundedSemaphore(8)
        ThreadingHTTPServer.__init__(self, address, Handler)

    def handle_error(self, request, address):
        return  # No request values, Java diagnostics or stack traces in logs.


if __name__ == '__main__':
    require_isolation()
    deny_egress()
    Server(('0.0.0.0', 8080)).serve_forever()
