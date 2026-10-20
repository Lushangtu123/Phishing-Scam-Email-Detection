"""Make every outbound connection, datagram and name lookup fail, and record it (tests only).

blocked_network() does it in this process. SITECUSTOMIZE does it in a child Python process: written
as sitecustomize.py into a folder on the child's PYTHONPATH, it records each attempt as a line in
the file PHISHGUARD_TEST_NETWORK_LOG names, read at start-up before an evaluator clears its
environment."""
import contextlib
import socket
from unittest.mock import patch

_TARGETS = ((socket.socket, 'connect'), (socket.socket, 'connect_ex'), (socket.socket, 'sendto'),
            (socket, 'create_connection'), (socket, 'getaddrinfo'), (socket, 'gethostbyname'))


@contextlib.contextmanager
def blocked_network():
    attempts = []

    def refuse(kind):
        def blocked(*args, **kwargs):
            attempts.append(kind)
            raise OSError(f'network blocked in tests: {kind}')
        return blocked

    with contextlib.ExitStack() as stack:
        for target, name in _TARGETS:
            stack.enter_context(patch.object(target, name, refuse(name)))
        yield attempts


SITECUSTOMIZE = '''import os
import socket

_LOG = os.environ.get('PHISHGUARD_TEST_NETWORK_LOG')


def _refuse(kind):
    def blocked(*args, **kwargs):
        with open(_LOG, 'a', encoding='utf-8') as handle:
            handle.write(kind + '\\n')
        raise OSError('network blocked in tests: ' + kind)
    return blocked


if _LOG:
    for _target, _name in ((socket.socket, 'connect'), (socket.socket, 'connect_ex'), (socket.socket, 'sendto'),
                           (socket, 'create_connection'), (socket, 'getaddrinfo'), (socket, 'gethostbyname')):
        setattr(_target, _name, _refuse(_name))
'''
