#!/usr/bin/python3
"""Persist per-VM random credentials; caller must hide stdout from Ansible logs."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import string
import subprocess
import tempfile

HASH_PATTERN = r'^[$]6[$](rounds=[0-9]+[$])?[./0-9A-Za-z]{1,16}[$][./0-9A-Za-z]{86}$'


def read_credentials(path, team):
    if path.is_symlink():
        raise ValueError('Credential state must not be a symbolic link')
    value = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value, dict) or value.get('team') != team or value.get('username') != 'user-access':
        raise ValueError('Credential state identity mismatch; refusing to replace it')
    for key, size in [('ssh_password', 24), ('vnc_password', 8)]:
        password = value.get(key)
        if not isinstance(password, str) or len(password) != size or not password.isascii() or not password.isalnum():
            raise ValueError('Invalid persisted credential; recover the state before provisioning')
    if not isinstance(value.get('ssh_password_hash'), str) or not re.fullmatch(HASH_PATTERN, value['ssh_password_hash']):
        raise ValueError('Invalid persisted password hash')
    path.chmod(0o600)
    return value


def ensure_credentials(path, team):
    if team not in ('team1', 'team2', 'team3', 'team4'):
        raise ValueError('Unknown team')
    if path.exists() or path.is_symlink():
        return read_credentials(path, team), False
    alphabet = string.ascii_letters + string.digits
    ssh_password = ''.join(secrets.choice(alphabet) for _ in range(24))
    vnc_password = ''.join(secrets.choice(alphabet) for _ in range(8))
    result = subprocess.run(['/usr/bin/openssl', 'passwd', '-6', '-stdin'],
                            input=(ssh_password + '\n').encode('ascii'),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    hashed = result.stdout.decode('ascii').strip()
    if not re.fullmatch(HASH_PATTERN, hashed):
        raise ValueError('OpenSSL did not return a SHA-512 crypt hash')
    value = {'team': team, 'username': 'user-access', 'ssh_password': ssh_password,
             'ssh_password_hash': hashed, 'vnc_password': vnc_password}
    # The helper can also run directly, without an Ansible directory task first.
    # Do not chmod an existing parent (it might be a shared system directory).
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.credentials-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            # Atomic, without overwriting another provisioning process's state.
            os.link(temporary, path)
        except FileExistsError:
            return read_credentials(path, team), False
    finally:
        os.unlink(temporary)
    return value, True


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--team', required=True, choices=('team1', 'team2', 'team3', 'team4'))
    parser.add_argument('--state-file', type=Path,
                        default=Path('/var/lib/fashion-access/credentials.json'),
                        help='Private state file; defaults to this VM\'s credential state')
    parser.add_argument('--show', action='store_true',
                        help='Show existing SSH/VNC login details without generating or changing them')
    args = parser.parse_args(argv)
    if args.show:
        try:
            credentials = read_credentials(args.state_file, args.team)
        except (OSError, ValueError) as exc:
            parser.error('Cannot read this team\'s credentials. Complete provisioning first. ' + str(exc))
        print(json.dumps({key: credentials[key] for key in
                          ('team', 'username', 'ssh_password', 'vnc_password')}, indent=2))
        return
    credentials, created = ensure_credentials(args.state_file, args.team)
    print(json.dumps({'credentials': credentials, 'created': created}))


if __name__ == '__main__':
    main()
