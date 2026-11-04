#!/usr/bin/python3
"""Inspect a VNC listener; report verified systemd owners without stopping them."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

PROTECTED = {'ssh.service', 'sshd.service', 'apache2.service', 'fashion-shop.service',
             'NetworkManager.service', 'systemd-networkd.service'}


def listener_plan(output, proc_root, allowed_units):
    stop, unknown, own = set(), [], False
    for row in output.splitlines():
        if not row.strip():
            continue
        pids = set(re.findall(r'pid=(\d+)', row))
        if not pids:
            unknown.append('Listener has no visible PID: ' + row)
        for pid in sorted(pids):
            try:
                content = (proc_root / pid / 'cgroup').read_text()
            except OSError:
                unknown.append('Cannot identify listener PID ' + pid)
                continue
            units = {part for line in content.splitlines() for part in line.split('/')
                     if re.fullmatch(r'[A-Za-z0-9_.@:-]+\.service', part)}
            if 'fashion-desktop.service' in units:
                own = True
            elif units & PROTECTED:
                unknown.append('Protected service owns listener PID ' + pid + ': ' + ','.join(sorted(units)))
            elif len(units & set(allowed_units)) == 1:
                stop.update(units & set(allowed_units))
            else:
                unknown.append('Unapproved listener PID ' + pid + ': ' + ','.join(sorted(units)))
    return {'stop_units': sorted(stop), 'unknown': unknown, 'own_listener': own}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', required=True, type=int)
    args = parser.parse_args()
    if not 5900 <= args.port <= 5999:
        parser.error('VNC port must be between 5900 and 5999')
    allowed = json.loads(sys.stdin.read())
    if not isinstance(allowed, list) or not all(isinstance(s, str) for s in allowed):
        parser.error('Expected a JSON list of approved GUI systemd services')
    result = subprocess.run(['/usr/bin/ss', '-H', '-ltnp', 'sport = :' + str(args.port)],
                            text=True, capture_output=True, check=True)
    print(json.dumps(listener_plan(result.stdout, Path('/proc'), allowed)))


if __name__ == '__main__':
    main()
