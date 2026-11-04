#!/usr/bin/python3
"""Write a TigerVNC credential from stdin, without putting secrets in argv."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def store_password(password, target):
    if len(password) != 8 or not password.isascii() or not password.isalnum():
        raise ValueError('Expected an eight-character ASCII alphanumeric GUI password')
    result = subprocess.run(['/usr/bin/tigervncpasswd', '-f'],
                            input=(password + '\n').encode('ascii'),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    if len(result.stdout) != 8:
        raise ValueError('Unexpected TigerVNC credential output')
    if target.is_file() and target.read_bytes() == result.stdout:
        target.chmod(0o600)
        return False
    fd, temporary = tempfile.mkstemp(prefix='.passwd-', dir=target.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(result.stdout)
        os.replace(temporary, target)
        target.chmod(0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


if __name__ == '__main__':
    password = sys.stdin.read().rstrip('\n')
    print('changed' if store_password(password, Path('/home/user-access/.vnc/passwd')) else 'unchanged')
