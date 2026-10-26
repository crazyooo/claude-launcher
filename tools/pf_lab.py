#!/usr/bin/env python3
"""Loopback-only PF experiment. Default prepare never loads firewall rules."""
import argparse
from contextlib import ExitStack, contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import threading
import uuid

JOURNALS = Path('/private/var/run/claude-launcher-pf-lab')
PREFIX = 'claude-launcher-lab/'
SPECS = [('inet', 'tcp', '127.0.0.1'), ('inet', 'udp', '127.0.0.1'),
         ('inet6', 'tcp', '::1'), ('inet6', 'udp', '::1')]


class LabError(Exception):
    """Only fixed diagnostic codes, never raw system output."""


def normalize(text):
    return '\n'.join(line.strip() for line in text.splitlines() if line.strip())


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def run_id(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{32}', value):
        raise LabError('invalid_run_id')
    return value


def rules(uid, ports):
    if type(uid) is not int or not 0 <= uid <= 2147483647 or not isinstance(ports, list) or len(ports) != 4:
        raise LabError('invalid_rule_scope')
    lines = []
    for (family, proto, host), port in zip(SPECS, ports):
        if type(port) is not int or not 1024 <= port <= 65535:
            raise LabError('invalid_reserved_port')
        lines.append(f'block drop out quick on lo0 {family} proto {proto} from any to {host} port {port} user {uid}')
    return '\n'.join(lines) + '\n'


class PF:
    def call(self, *args, source=None):
        try:
            result = subprocess.run(['/sbin/pfctl', *args], input=source, text=True,
                                    capture_output=True, timeout=5,
                                    env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'})
        except (OSError, subprocess.TimeoutExpired):
            raise LabError('pfctl_unavailable_or_timeout') from None
        if result.returncode:
            raise LabError('pfctl_rejected')
        if len(result.stdout) > 2 * 1024 * 1024:
            raise LabError('pfctl_output_too_large')
        return result.stdout

    def compile(self, identity, uid, ports):
        source = rules(uid, ports)
        rendered = normalize(self.call('-n', '-v', '-o', 'none', '-a', PREFIX + run_id(identity), '-f', '-', source=source))
        if len(rendered.splitlines()) != 4 or any(not line.startswith('block drop out quick on lo0 ') for line in rendered.splitlines()):
            raise LabError('canonical_rules_unrecognized')
        return {'version': 1, 'run_id': identity, 'uid': uid, 'ports': ports,
                'source_sha256': digest(source), 'canonical': rendered}

    def owned_rules(self, identity):
        anchor = PREFIX + run_id(identity)
        if self.call('-a', anchor, '-s', 'Anchors').strip():
            raise LabError('unexpected_nested_anchor')
        return normalize(self.call('-a', anchor, '-s', 'rules'))

    def prerequisites(self, identity):
        if not re.search(r'^Status: Enabled\b', self.call('-s', 'info'), re.M):
            raise LabError('pf_not_enabled')
        root_rules = self.call('-s', 'rules')
        if not re.search(r'^anchor "claude-launcher-lab/\*" all\s*$', root_rules, re.M):
            raise LabError('dedicated_root_hook_missing')
        # Unknown interface output is not evidence that lo0 filtering is active.
        if self.call('-i', 'lo0', '-s', 'Interfaces', '-v').strip() != 'lo0':
            raise LabError('loopback_skipped_or_status_unknown')
        if self.owned_rules(identity):
            raise LabError('anchor_not_empty')
        return digest(root_rules)

    def inspect(self):
        info = self.call('-s', 'info')
        root_rules = self.call('-s', 'rules')
        loopback = self.call('-i', 'lo0', '-s', 'Interfaces', '-v').strip()
        return {
            'pf_enabled': bool(re.search(r'^Status: Enabled\b', info, re.M)),
            'dedicated_root_hook_present': bool(re.search(r'^anchor "claude-launcher-lab/\*" all\s*$', root_rules, re.M)),
            'loopback_filtering_status_confirmed': loopback == 'lo0',
            'root_rules_sha256': digest(root_rules),
            'reason': 'readonly_system_inspection_only',
        }

    def load(self, intent):
        self.call('-a', PREFIX + run_id(intent['run_id']), '-o', 'none', '-R', '-f', '-',
                  source=rules(intent['uid'], intent['ports']))

    def clear(self, identity):
        self.call('-a', PREFIX + run_id(identity), '-F', 'rules')


class JournalStore:
    """Fixed root-owned directory in production; tests use a private temporary directory."""
    def __init__(self, directory=JOURNALS):
        self.directory = directory

    def check_directory(self):
        self.directory.mkdir(mode=0o700, exist_ok=True)
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise LabError('unsafe_journal_directory')

    @contextmanager
    def lock(self):
        self.check_directory()
        fd = os.open(self.directory / 'lab.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            self.check_file(os.fstat(fd))
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise LabError('lab_operation_in_progress') from None
            yield
        finally:
            os.close(fd)

    @staticmethod
    def check_file(info):
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 16384):
            raise LabError('unsafe_journal_file')

    def save(self, intent):
        path = self.directory / (run_id(intent['run_id']) + '.json')
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            self.check_file(os.fstat(stream.fileno()))
            json.dump(intent, stream)
            stream.flush()
            os.fsync(stream.fileno())
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def read(self, identity, pf):
        path = self.directory / (run_id(identity) + '.json')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd) as stream:
            self.check_file(os.fstat(stream.fileno()))
            intent = json.load(stream)
        if not isinstance(intent, dict) or intent.get('version') != 1 or intent.get('run_id') != identity or intent.get('uid') != 0:
            raise LabError('journal_identity_mismatch')
        rebuilt = pf.compile(identity, intent['uid'], intent['ports'])
        if any(intent.get(key) != value for key, value in rebuilt.items()):
            raise LabError('journal_rule_mismatch')
        return intent


def restore(intent, pf):
    current = pf.owned_rules(intent['run_id'])
    if not current:
        return
    if current != intent['canonical']:
        raise LabError('anchor_changed_recovery_refused')
    # PF has no compare-and-swap here; another privileged writer can still race us.
    pf.clear(intent['run_id'])
    if pf.owned_rules(intent['run_id']):
        raise LabError('recovery_verification_failed')


@contextmanager
def interruptible():
    def stop(*_):
        raise LabError('experiment_interrupted')
    previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


@contextmanager
def loaded_rules(intent, pf, store, recovery=None):
    store.save(intent)  # Durable intent exists before the first PF mutation.
    load_attempted = False
    try:
        if pf.owned_rules(intent['run_id']):
            raise LabError('anchor_changed_before_load')
        load_attempted = True
        if recovery is not None:
            recovery['rules_restored'] = False
        pf.load(intent)
        if pf.owned_rules(intent['run_id']) != intent['canonical']:
            raise LabError('loaded_rules_mismatch')
        yield
    finally:
        # Repeated Ctrl-C/TERM must not interrupt cleanup; SIGKILL still requires restore.
        previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            if load_attempted:
                restore(intent, pf)
                if recovery is not None:
                    recovery['rules_restored'] = True
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)


class Echo:
    def __init__(self, spec):
        self.family = socket.AF_INET6 if spec[0] == 'inet6' else socket.AF_INET
        self.kind = socket.SOCK_STREAM if spec[1] == 'tcp' else socket.SOCK_DGRAM
        self.host = spec[2]
        self.closed = threading.Event()
        self.socket = socket.socket(self.family, self.kind)
        try:
            if self.family == socket.AF_INET6:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            self.socket.bind((self.host, 0))
            self.port = self.socket.getsockname()[1]
            self.socket.settimeout(0.2)
            if self.kind == socket.SOCK_STREAM:
                self.socket.listen(8)
        except BaseException:
            self.socket.close()
            raise
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.closed.is_set():
            try:
                if self.kind == socket.SOCK_DGRAM:
                    data, address = self.socket.recvfrom(256)
                    self.socket.sendto(data, address)
                else:
                    connection, _ = self.socket.accept()
                    threading.Thread(target=self.echo_stream, args=(connection,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                return

    def echo_stream(self, connection):
        with connection:
            connection.settimeout(0.2)
            while not self.closed.is_set():
                try:
                    data = connection.recv(256)
                    if not data:
                        return
                    connection.sendall(data)
                except socket.timeout:
                    continue
                except OSError:
                    return

    def connect(self):
        client = socket.socket(self.family, self.kind)
        client.settimeout(0.7)
        try:
            client.connect((self.host, self.port))
            return client
        except BaseException:
            client.close()
            raise

    def probe(self, existing=None):
        client = existing
        try:
            client = existing if existing is not None else self.connect()
            token = os.urandom(16)
            client.sendall(token)
            answer = b''
            while len(answer) < len(token):
                part = client.recv(16 - len(answer))
                if not part:
                    break
                answer += part
            return answer == token
        except OSError:
            return False
        finally:
            if client is not None and existing is None:
                client.close()

    def close(self):
        self.closed.set()
        self.socket.close()
        self.thread.join(timeout=1)


def experiment(mode, pf, store, report):
    identity = uuid.uuid4().hex
    report['run_id'] = identity
    if mode == 'live':
        report['root_rules_sha256'] = pf.prerequisites(identity)
    with ExitStack() as stack:
        protected, controls = [], []
        for endpoints in (protected, controls):
            for spec in SPECS:
                endpoint = Echo(spec)
                stack.callback(endpoint.close)
                endpoints.append(endpoint)
        existing = {}
        for index in (0, 2):
            client = protected[index].connect()
            stack.callback(client.close)
            existing[index] = client
        report['baseline'] = {'new': [e.probe() for e in protected],
                              'controls': [e.probe() for e in controls],
                              'existing_tcp': [protected[i].probe(client) for i, client in existing.items()]}
        if not all(value for group in report['baseline'].values() for value in group):
            raise LabError('loopback_baseline_failed')
        intent = pf.compile(identity, os.geteuid(), [e.port for e in protected])
        report.update(syntax_valid=True, rule_scope=rules(intent['uid'], intent['ports']),
                      rule_sha256=intent['source_sha256'])
        if mode == 'prepare':
            report['reason'] = 'baseline_and_syntax_only'
            return True
        report['recovery_run_id'] = identity
        with loaded_rules(intent, pf, store, recovery=report):
            report['during_rules'] = {'new': [e.probe() for e in protected],
                                      'controls': [e.probe() for e in controls],
                                      'existing_tcp': [protected[i].probe(client) for i, client in existing.items()]}
        report['rules_restored'] = True
        report['after_restore'] = [e.probe() for e in protected + controls]
        observed = report['during_rules']
        passed = not any(observed['new'] + observed['existing_tcp']) and all(observed['controls'] + report['after_restore'])
        report['experiment_passed'] = passed
        report['reason'] = 'loopback_experiment_passed' if passed else 'blocking_or_recovery_not_proven'
        return passed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('prepare', 'inspect', 'live', 'restore'), nargs='?', default='prepare')
    parser.add_argument('--run-id')
    args = parser.parse_args(argv)
    report = {'mode': args.mode, 'protection_verified': False, 'launch_authorized': False,
              'coverage': 'loopback TCP/UDP IPv4/IPv6 only; no Claude, DNS, TUN or physical-egress acceptance'}
    success = False
    try:
        pf, store = PF(), JournalStore()
        if (args.mode == 'restore') != (args.run_id is not None):
            raise LabError('run_id_only_required_for_restore')
        if args.mode != 'prepare' and os.geteuid() != 0:
            raise LabError('administrator_required_no_changes')
        with interruptible():
            if args.mode == 'prepare':
                success = experiment(args.mode, pf, store, report)
            elif args.mode == 'inspect':
                report.update(pf.inspect())
                success = True
            else:
                with store.lock():
                    if args.mode == 'restore':
                        restore(store.read(args.run_id, pf), pf)
                        report.update(reason='owned_rules_restored', rules_restored=True)
                        success = True
                    else:
                        success = experiment(args.mode, pf, store, report)
    except LabError as error:
        report['reason'] = str(error)
    except (OSError, ValueError, TypeError, KeyError):
        report['reason'] = 'local_operation_failed'
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if success else 78


if __name__ == '__main__':
    raise SystemExit(main())
