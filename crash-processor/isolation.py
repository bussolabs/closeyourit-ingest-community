"""Add outbound syscall restrictions on top of Docker's existing seccomp policy."""
import ctypes
import errno
import socket
import subprocess
import sys


def verify_egress_denied():
    operations = (
        (socket.SOCK_STREAM, lambda s: s.connect(('127.0.0.1', 9))),
        (socket.SOCK_DGRAM, lambda s: s.sendto(b'check', ('127.0.0.1', 9))),
        (socket.SOCK_DGRAM, lambda s: s.sendmsg([b'check'], [], 0, ('127.0.0.1', 9))),
    )
    for kind, operation in operations:
        with socket.socket(socket.AF_INET, kind) as connection:
            try:
                operation(connection)
            except OSError as error:
                if error.errno == errno.EPERM:
                    continue
                raise RuntimeError('Outbound syscall restriction is not effective') from error
            raise RuntimeError('Outbound syscall unexpectedly succeeded')


def deny_egress():
    library = ctypes.CDLL('libseccomp.so.2', use_errno=True)
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_syscall_resolve_name.restype = ctypes.c_int
    library.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    library.seccomp_rule_add.restype = ctypes.c_int
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_load.restype = ctypes.c_int
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    library.seccomp_release.restype = None
    context = library.seccomp_init(0x7fff0000)  # SCMP_ACT_ALLOW; previous filters still apply.
    if not context:
        raise RuntimeError('Unable to initialize seccomp')
    try:
        for name in ('connect', 'sendto', 'sendmsg', 'sendmmsg',
                     'io_uring_setup', 'io_uring_enter', 'io_uring_register'):
            number = library.seccomp_syscall_resolve_name(name.encode('ascii'))
            if number < 0 or library.seccomp_rule_add(context, 0x00050000 | errno.EPERM, number, 0) != 0:
                raise RuntimeError('Unable to deny outbound syscalls')
        if library.seccomp_load(context) != 0:
            raise RuntimeError('Unable to load outbound restrictions')
    finally:
        library.seccomp_release(context)
    verify_egress_denied()
    # An actual exec must inherit the filter before any dump can be accepted.
    child = subprocess.run([sys.executable, '-I', '-B', __file__, '--verify-child'],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={'PATH': '/usr/local/bin:/usr/bin:/bin'}, timeout=2)
    if child.returncode != 0:
        raise RuntimeError('Child process did not inherit outbound restrictions')


if __name__ == '__main__' and sys.argv[1:] == ['--verify-child']:
    verify_egress_denied()
