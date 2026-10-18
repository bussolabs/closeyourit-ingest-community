"""Isolated, bounded minidump processing. Never return or log raw process memory."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from isolation import deny_egress
import json
import io
import os
from pathlib import Path
import re
import selectors
import select
import signal
import socket
import subprocess
import tempfile
import threading
import time

MAX_INPUT = 10 * 1024 * 1024
MAX_OUTPUT = 1024 * 1024
MAX_WALKER_OUTPUT = 8 * 1024 * 1024
DEADLINE = 8
WALKER = '/usr/local/bin/minidump-stackwalk'
PROCESS_SLOT = threading.BoundedSemaphore(1)


class Rejected(Exception):
    def __init__(self, status, code):
        self.status = status
        self.code = code


def scrub(value):
    if not isinstance(value, str) or len(value.encode('utf-8')) > 1024:
        raise Rejected(422, 'R422-CRASH-002')
    value = re.sub(r'cyi_(?:[a-z]_)?[A-Za-z0-9_-]{16,}', '[FILTERED]', value)
    value = re.sub(r'(?i)\b(?:Bearer|Basic)\s+\S+', '[FILTERED]', value)
    value = re.sub(r'(?i)\bhttps?://\S+', '[FILTERED_URL]', value)
    value = re.sub(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', '[FILTERED_EMAIL]', value)
    value = re.sub(r'(?i)\b(?:password|token|secret|api[_-]?key)\s*[=:]\s*\S+', '[FILTERED]', value)
    return re.sub(r'[\x00-\x1f\x7f]', '', value)


def text_fields(source, names, filenames=()):
    result = {}
    if not isinstance(source, dict):
        raise Rejected(422, 'R422-CRASH-002')
    for name in names:
        if source.get(name) is not None:
            value = scrub(source[name])
            if name in filenames:
                value = value.replace('\\', '/').rsplit('/', 1)[-1]
            result[name] = value
    return result


def hex_fields(source, names):
    result = {}
    for name in names:
        value = source.get(name)
        if value is not None:
            if not isinstance(value, str) or not re.fullmatch(r'0x[0-9a-fA-F]{1,16}', value):
                raise Rejected(422, 'R422-CRASH-002')
            result[name] = value
    return result


def integer_field(source, name):
    value = source.get(name)
    if value is None:
        return {}
    if type(value) is not int or not 0 <= value <= 0xffffffff:
        raise Rejected(422, 'R422-CRASH-002')
    return {name: value}


def bounded_list(source, name, limit):
    value = source.get(name)
    if not isinstance(value, list) or len(value) > limit:
        raise Rejected(422, 'R422-CRASH-003')
    return value


def project_report(source):
    if not isinstance(source, dict) or source.get('status') != 'OK':
        raise Rejected(422, 'R422-CRASH-002')
    system = text_fields(source.get('system_info'), ('os', 'cpu_arch', 'os_ver'))
    if 'os_ver' in system:
        system['os_version'] = system.pop('os_ver')
    crash_source = source.get('crash_info')
    crash = text_fields(crash_source, ('type',))
    crash.update(hex_fields(crash_source, ('address',)))
    crash.update(integer_field(crash_source, 'crashing_thread'))
    threads = []
    for thread in bounded_list(source, 'threads', 128):
        if not isinstance(thread, dict):
            raise Rejected(422, 'R422-CRASH-002')
        item = integer_field(thread, 'thread_id')
        frames = []
        for frame in bounded_list(thread, 'frames', 256):
            result = text_fields(frame, ('module', 'trust'), ('module',))
            result.update(hex_fields(frame, ('offset', 'module_offset')))
            if 'offset' in result:
                result['instruction'] = result.pop('offset')
            frames.append(result)
        item['frames'] = frames
        threads.append(item)
    modules = []
    for module in bounded_list(source, 'modules', 512):
        item = text_fields(module, ('filename',), ('filename',))
        item.update(hex_fields(module, ('base_addr', 'end_addr')))
        for key in ('code_id', 'debug_id'):
            value = module.get(key)
            if value:
                if not isinstance(value, str) or not re.fullmatch(r'[0-9a-fA-F-]{1,128}', value):
                    raise Rejected(422, 'R422-CRASH-002')
                item[key] = value
        modules.append(item)
    result = {'schema_version': 1, 'system_info': system, 'crash_info': crash,
              'threads': threads, 'modules': modules}
    payload = json.dumps(result, separators=(',', ':'), allow_nan=False).encode('utf-8')
    if len(payload) > MAX_OUTPUT:
        raise Rejected(422, 'R422-CRASH-003')
    return payload


def require_isolation():
    mounts = [line.split() for line in Path('/proc/mounts').read_text().splitlines()]
    if not any(row[1:3] == ['/tmp', 'tmpfs'] for row in mounts):
        raise RuntimeError('A tmpfs /tmp is required')
    if not any(row[1] == '/' and 'ro' in row[3].split(',') for row in mounts):
        raise RuntimeError('A read-only root filesystem is required')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines())
    if (os.getuid() == 0 or int(status['CapEff'].strip(), 16) != 0
            or status['NoNewPrivs'].strip() != '1'):
        raise RuntimeError('An unprivileged process with no new privileges is required')


def walk_dump(path):
    process = subprocess.Popen([WALKER, '--json', '--verbose', 'off', str(path)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8',
             'TMPDIR': '/tmp', 'TOKIO_WORKER_THREADS': '1'}, start_new_session=True)
    deadline = time.monotonic() + DEADLINE
    output = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Rejected(503, 'R503-CRASH-001')
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(chunk)
                        if len(output) > MAX_WALKER_OUTPUT:
                            raise Rejected(422, 'R422-CRASH-003')
        try:
            status = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            raise Rejected(503, 'R503-CRASH-001') from error
        if status != 0:
            raise Rejected(422, 'R422-CRASH-001')
        try:
            return project_report(json.loads(output))
        except (ValueError, UnicodeError, RecursionError) as error:
            raise Rejected(422, 'R422-CRASH-002') from error
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        process.stdout.close()


class ResponseWriter(io.RawIOBase):
    def __init__(self, connection):
        self.connection = connection

    def writable(self):
        return True

    def write(self, data):
        # socket.sendall uses sendto on Linux, which our outbound filter denies.
        view = memoryview(data)
        deadline = time.monotonic() + 2
        total = len(view)
        while view:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([], [self.connection], [], remaining)[1]:
                raise TimeoutError('Response write deadline exceeded')
            try:
                written = os.write(self.connection.fileno(), view)
            except BlockingIOError:
                continue
            if written == 0:
                raise ConnectionError('Response socket closed')
            view = view[written:]
        return total


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, _format, *args):
        # Raw HTTP paths/headers must never reach container logs.
        return

    def setup(self):
        super().setup()
        self.connection.settimeout(2)
        self.wfile = ResponseWriter(self.connection)
        self.header_deadline = threading.Timer(2, self.expire_headers)
        self.header_deadline.daemon = True
        self.header_deadline.start()

    def expire_headers(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            return False  # The peer or request thread already closed this socket.
        return True

    def finish(self):
        self.header_deadline.cancel()
        super().finish()

    def reply(self, status, payload):
        self.header_deadline.cancel()
        self.close_connection = True
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Connection', 'close')
        if status == 503:
            self.send_header('Retry-After', '1')
        self.end_headers()
        self.wfile.write(payload)

    def send_error(self, code, message=None, explain=None):
        self.reply(code, b'{"error":"R400-CRASH-002"}')

    def do_GET(self):
        self.header_deadline.cancel()
        if self.path == '/up':
            self.reply(200, b'{"status":"ok"}')
        elif self.path == '/version':
            self.reply(200, b'{"processor":"minidump-stackwalk","version":"0.27.0","schema_version":1,"outbound_syscalls_denied":true}')
        else:
            self.reply(404, b'{"error":"R404-CRASH-001"}')

    def do_POST(self):
        self.header_deadline.cancel()
        acquired = False
        try:
            if self.path != '/process':
                raise Rejected(404, 'R404-CRASH-001')
            if self.headers.get('Content-Type') != 'application/octet-stream':
                raise Rejected(415, 'R415-CRASH-001')
            if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Encoding'):
                raise Rejected(400, 'R400-CRASH-001')
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths) != 1 or not re.fullmatch(r'[0-9]{1,10}', lengths[0]):
                raise Rejected(411, 'R411-CRASH-001')
            length = int(lengths[0])
            if length > MAX_INPUT:
                raise Rejected(413, 'R413-CRASH-001')
            if length < 32:
                raise Rejected(422, 'R422-CRASH-001')
            acquired = PROCESS_SLOT.acquire(blocking=False)
            if not acquired:
                raise Rejected(503, 'R503-CRASH-002')
            body = bytearray()
            body_deadline = time.monotonic() + 2
            while len(body) < length:
                remaining = body_deadline - time.monotonic()
                if remaining <= 0:
                    raise Rejected(408, 'R408-CRASH-001')
                self.connection.settimeout(remaining)
                chunk = self.rfile.read1(min(65536, length - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
            if len(body) != length or body[:4] != b'MDMP':
                raise Rejected(422, 'R422-CRASH-001')
            with tempfile.TemporaryDirectory(dir='/tmp', prefix='crash-') as directory:
                path = Path(directory) / 'input.dmp'
                path.write_bytes(body)
                del body
                result = walk_dump(path)
            self.reply(200, result)
        except Rejected as error:
            self.reply(error.status, json.dumps({'error': error.code}).encode())
        except (TimeoutError, socket.timeout):
            self.reply(408, b'{"error":"R408-CRASH-001"}')
        except OSError:
            self.reply(503, b'{"error":"R503-CRASH-003"}')
        finally:
            if acquired:
                PROCESS_SLOT.release()


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, address):
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(address, Handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, request, address):
        # Never print a traceback containing parser/request data.
        print('R500-CRASH-001 request failed', flush=True)


if __name__ == '__main__':
    require_isolation()
    deny_egress()
    Server(('0.0.0.0', 8080)).serve_forever()
