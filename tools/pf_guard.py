#!/usr/bin/env python3
"""Explicit PF destination guard lifecycle. Stage is read-only with respect to PF."""
import argparse
from contextlib import contextmanager
import difflib
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import shlex
import stat
import subprocess
import time
import uuid

from pf_lab import PF as BasePF, LabError, normalize
from pf_policy import PolicyError, fingerprint, validate, same_destinations

DIRECTORY = Path('/private/var/run/claude-launcher-pf-guard')
LIMIT = 1024 * 1024


class GuardError(Exception):
    """Only fixed diagnostic codes are exposed by the CLI."""


def identity(value):
    if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{32}', value):
        raise GuardError('invalid_plan_id')
    return value


def anchor(plan):
    return 'clguard_' + identity(plan['id'])


def reference_tokens(output):
    """macOS -s References is a table, unlike the -E receipt's Token line."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if lines and lines[0] == 'TOKENS:':
        lines.pop(0)
    # macOS reports an empty starter list with puts() and exit 0. The similar
    # "No pf_enabled references" belongs to an errx(1) failure path instead.
    if lines == ['No pf starter references held']:
        return set()
    if not lines or not re.fullmatch(r'PID\s+Process Name\s+TOKEN\s+TIMESTAMP', lines[0]):
        raise GuardError('pf_reference_table_unknown')
    tokens = set()
    for line in lines[1:]:
        match = re.fullmatch(r'[0-9]+\s+.{1,28}?\s+([0-9]{1,20})\s+[0-9]+ days [0-9]{2}:[0-9]{2}:[0-9]{2}', line)
        if not match or int(match[1]) >= 2**64 or match[1] in tokens:
            raise GuardError('pf_reference_table_unknown')
        tokens.add(match[1])
    return tokens


def root_source(before, name):
    # Preserve the known Apple normalization prefix before inserting filter rules.
    # -R must not be assumed to ignore scrub: verify the complete live root later.
    lines = before.splitlines()
    apple_scrub = 'scrub-anchor "com.apple/*" all fragment reassemble'
    insertion = 1 if lines and lines[0] == apple_scrub else 0
    for line in lines[insertion:]:
        if not re.fullmatch(r'anchor "[A-Za-z0-9_./*-]+"(?: quick)? all', line):
            raise GuardError('root_baseline_requires_manual_review')
        if 'clguard_' in line:
            raise GuardError('another_destination_guard_present')
    lines.insert(insertion, f'anchor "{name}" quick all')
    return normalize('\n'.join(lines))


class PF(BasePF):
    def enabled(self):
        output = self.call('-s', 'info')
        match = re.search(r'^Status: (Enabled|Disabled)\b', output, re.M)
        if not match:
            raise GuardError('pf_status_unknown')
        return match[1] == 'Enabled'

    def root(self):
        return normalize(self.call('-s', 'rules'))

    def references(self):
        return self.call('-s', 'References')

    def own(self, plan):
        if self.call('-a', anchor(plan), '-s', 'Anchors').strip():
            raise GuardError('unexpected_nested_anchor')
        return normalize(self.call('-a', anchor(plan), '-s', 'rules'))

    def syntax(self, source):
        return normalize(self.call('-n', '-v', '-o', 'none', '-R', '-f', '-', source=source + '\n'))

    def load(self, source, name=None):
        self.call(*(['-a', name] if name else []), '-o', 'none', '-R', '-f', '-', source=source + '\n')

    def clear(self, plan):
        self.call('-a', anchor(plan), '-F', 'rules')

    def enable(self, store, plan):
        # Receipt is opened durably before pfctl starts. A missing token after
        # interruption is ambiguous: recovery never guesses a reference to release.
        fd = store.create_receipt(plan['id'])
        try:
            with os.fdopen(fd, 'wb') as receipt:
                result = subprocess.run(['/sbin/pfctl', '-E'], stdout=receipt, stderr=receipt,
                                        timeout=5, env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'})
                receipt.flush()
                os.fsync(receipt.fileno())
                if result.returncode:
                    raise GuardError('pf_enable_failed_check_receipt')
        except (OSError, subprocess.TimeoutExpired):
            raise GuardError('pf_enable_outcome_unknown') from None
        return store.receipt_token(plan['id'])

    def release(self, token):
        self.call('-X', token)

    def kill_states(self, cidr):
        self.call('-k', '::/0' if ':' in cidr else '0.0.0.0/0', '-k', cidr)


def read_fd(fd, owned):
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > LIMIT:
            raise GuardError('unsafe_or_oversized_file')
        if owned and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise GuardError('unsafe_journal_file')
        data = stream.read(LIMIT + 1)
        if len(data) > LIMIT:
            raise GuardError('oversized_file')
        return data


class Store:
    def __init__(self, directory=DIRECTORY):
        self.directory = directory

    def sync_directory(self):
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @contextmanager
    def lock(self):
        self.directory.mkdir(mode=0o700, exist_ok=True)
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise GuardError('unsafe_journal_directory')
        fd = os.open(self.directory / 'operation.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                raise GuardError('unsafe_lock_file')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise GuardError('guard_operation_in_progress') from None
            yield
        finally:
            os.close(fd)

    def path(self, plan_id, kind):
        return self.directory / (identity(plan_id) + '.' + kind)

    def read(self, plan_id, kind):
        fd = os.open(self.path(plan_id, kind), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        return json.loads(read_fd(fd, True))

    def write(self, plan_id, kind, value, exclusive=False):
        target = self.path(plan_id, kind)
        temp = target if exclusive else self.directory / (uuid.uuid4().hex + '.tmp')
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        if not exclusive:
            os.replace(temp, target)
        self.sync_directory()

    def create_receipt(self, plan_id):
        fd = os.open(self.path(plan_id, 'receipt'), os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.fchmod(fd, 0o600)
        self.sync_directory()
        return fd

    def receipt_token(self, plan_id):
        try:
            fd = os.open(self.path(plan_id, 'receipt'), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            text = read_fd(fd, True).decode('ascii')
        except (OSError, UnicodeError):
            raise GuardError('enable_reference_ownership_unknown') from None
        tokens = re.findall(r'^Token\s*:\s*([0-9]{1,20})\s*$', text, re.M)
        if len(tokens) != 1 or int(tokens[0]) >= 2**64:
            raise GuardError('enable_reference_ownership_unknown')
        return tokens[0]


def stage(policy, pf, store):
    compiled = validate(policy)
    plan = {'version': 1, 'id': uuid.uuid4().hex, 'policy': policy,
            'created_at': time.time(), 'pf_was_enabled': pf.enabled(),
            'root_before': pf.root(), 'references_before_sha256': fingerprint(sorted(reference_tokens(pf.references())))}
    if pf.own(plan):
        raise GuardError('anchor_not_empty')
    plan['root_after'] = root_source(plan['root_before'], anchor(plan))
    pf.syntax(plan['root_after'])  # Do not trust dry-run's rewritten anchor paths.
    plan['own_rules'] = pf.syntax(compiled['rules'])
    if len(plan['own_rules'].splitlines()) != len(compiled['cidrs']) or any(
            not line.startswith('block drop out quick ') for line in plan['own_rules'].splitlines()):
        raise GuardError('canonical_destination_rules_unknown')
    store.write(plan['id'], 'plan', plan, exclusive=True)
    return plan


def check_plan(plan, pf):
    if plan.get('version') != 1 or type(plan.get('pf_was_enabled')) is not bool:
        raise GuardError('invalid_plan')
    compiled = validate(plan['policy'], fresh=False)
    if (root_source(plan['root_before'], anchor(plan)) != plan['root_after'] or
            pf.syntax(compiled['rules']) != plan['own_rules']):
        raise GuardError('plan_content_mismatch')
    return compiled


def save_state(store, plan, state, **updates):
    state.update(updates)
    store.write(plan['id'], 'state', state)


def recover(plan, pf, store):
    check_plan(plan, pf)
    state = store.read(plan['id'], 'state')
    if state.get('plan_sha256') != fingerprint(plan):
        raise GuardError('journal_plan_mismatch')
    if state.get('phase') == 'restored':
        return
    root, own = pf.root(), pf.own(plan)
    if root not in (plan['root_before'], plan['root_after']) or own not in ('', plan['own_rules']):
        raise GuardError('foreign_rule_change_recovery_refused')
    # Resolve receipt before removing protection. An uncertain reference requires
    # administrator inspection, not guessing or globally disabling PF.
    token = store.receipt_token(plan['id']) if state.get('enable_attempted') else None
    if token:
        reference_tokens(pf.references())  # Unknown reference format stops before removing rules.
    if root == plan['root_after']:
        if not state.get('root_attempted'):
            raise GuardError('root_not_owned')
        pf.load(plan['root_before'])
    if pf.root() != plan['root_before']:
        raise GuardError('root_restore_verification_failed')
    if own:
        if not state.get('anchor_attempted'):
            raise GuardError('anchor_not_owned')
        pf.clear(plan)
    if pf.own(plan):
        raise GuardError('anchor_restore_verification_failed')
    if token:
        save_state(store, plan, state, phase='release_pending')
        if token in reference_tokens(pf.references()):
            save_state(store, plan, state, release_attempted=True)
            pf.release(token)
            if token in reference_tokens(pf.references()):
                raise GuardError('reference_release_verification_failed')
        elif state.get('release_attempted') is not True:
            # References can be removed externally; absence alone is not proof of
            # a release by us. No foreign reference is ever touched.
            save_state(store, plan, state, reference_already_absent=True)
    save_state(store, plan, state, phase='restored', launch_authorized=False)


def apply(plan, confirmed, pf, store):
    compiled = check_plan(plan, pf)
    if confirmed != fingerprint(plan):
        raise GuardError('reviewed_plan_digest_required')
    validate(plan['policy'])
    if time.time() - plan['created_at'] > 300 or time.time() < plan['created_at']:
        raise GuardError('plan_expired_restage_required')
    if (pf.root() != plan['root_before'] or pf.own(plan) or
            pf.enabled() != plan['pf_was_enabled'] or fingerprint(sorted(reference_tokens(pf.references()))) != plan['references_before_sha256']):
        raise GuardError('system_changed_restage_required')
    state = {'plan_sha256': fingerprint(plan), 'phase': 'prepared', 'launch_authorized': False}
    store.write(plan['id'], 'state', state, exclusive=True)
    try:
        save_state(store, plan, state, phase='anchor_pending', anchor_attempted=True)
        pf.load(plan['own_rules'], anchor(plan))
        if pf.own(plan) != plan['own_rules']:
            raise GuardError('anchor_load_verification_failed')
        if pf.root() != plan['root_before']:
            raise GuardError('root_changed_before_load')
        save_state(store, plan, state, phase='root_pending', root_attempted=True)
        pf.load(plan['root_after'])
        if pf.root() != plan['root_after']:
            raise GuardError('root_load_verification_failed')
        if not plan['pf_was_enabled']:
            # Avoid acquiring/releasing the last reference of manually enabled PF.
            if pf.enabled() or fingerprint(sorted(reference_tokens(pf.references()))) != plan['references_before_sha256']:
                raise GuardError('pf_changed_before_enable')
            save_state(store, plan, state, phase='enable_pending', enable_attempted=True)
            pf.enable(store, plan)
        if not pf.enabled():
            raise GuardError('pf_not_enabled_after_apply')
        for cidr in compiled['cidrs']:
            save_state(store, plan, state, phase='state_cleanup_pending', state_scope=cidr)
            pf.kill_states(cidr)
        if pf.root() != plan['root_after'] or pf.own(plan) != plan['own_rules']:
            raise GuardError('rules_changed_during_apply')
        validate(plan['policy'])
        save_state(store, plan, state, phase='installed_unverified', installed_at=time.time())
    except BaseException:
        # Normal failures attempt independent recovery; SIGKILL leaves the durable
        # journal for `restore`. Never hide a rollback failure from the caller.
        previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            recover(plan, pf, store)
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
        raise


def health(plan, pf, store, evidence=None):
    compiled = check_plan(plan, pf)
    if evidence is not None:
        compiled = same_destinations(plan['policy'], evidence)
    state = store.read(plan['id'], 'state')
    if state.get('plan_sha256') != fingerprint(plan):
        raise GuardError('journal_plan_mismatch')
    checks = {'installed': state.get('phase') == 'installed_unverified',
              'pf_enabled': pf.enabled(), 'root_matches': pf.root() == plan['root_after'],
              'destinations_match': pf.own(plan) == plan['own_rules'],
              'evidence_fresh': compiled['observed_at'] <= time.time() < compiled['expires_at']}
    return {'checks': checks, 'rules_present_and_fresh': all(checks.values()),
            'checked_at': time.time(), 'existing_states_verified': False,
            'proxy_transport_endpoints_verified': False,
            'protection_verified': False, 'launch_authorized': False}


def watch_once(plan, pf, store, evidence=None, before_repair=None):
    """Repair only an empty owned anchor under our still-exact root hook."""
    compiled = check_plan(plan, pf)
    if evidence is not None:
        compiled = same_destinations(plan['policy'], evidence)
    state = store.read(plan['id'], 'state')
    if state.get('plan_sha256') != fingerprint(plan):
        raise GuardError('journal_plan_mismatch')
    own = pf.own(plan)
    repairable = (state.get('phase') in ('installed_unverified', 'repair_pending') and
                  pf.enabled() and pf.root() == plan['root_after'] and compiled['expires_at'] > time.time())
    repaired = False
    if repairable and (not own or state.get('phase') == 'repair_pending'):
        if own not in ('', plan['own_rules']):
            raise GuardError('foreign_anchor_change_repair_refused')
        if before_repair is not None:
            before_repair()  # Close any retry path before the first possible mutation.
        save_state(store, plan, state, phase='repair_pending')
        if evidence is None:
            validate(plan['policy'])
        else:
            same_destinations(plan['policy'], evidence)
        if pf.own(plan) != own or pf.root() != plan['root_after'] or not pf.enabled():
            raise GuardError('rules_changed_before_repair')
        if not own:
            pf.load(plan['own_rules'], anchor(plan))
        if pf.own(plan) != plan['own_rules'] or pf.root() != plan['root_after']:
            raise GuardError('repair_rule_verification_failed')
        for cidr in compiled['cidrs']:
            pf.kill_states(cidr)
        save_state(store, plan, state, phase='installed_unverified', repaired_at=time.time())
        repaired = True
    result = health(plan, pf, store, evidence=evidence)
    result['empty_owned_anchor_repaired'] = repaired
    return result


def stop(*_):
    raise GuardError('operation_interrupted_rules_require_status_or_restore')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='mode', required=True)
    commands.add_parser('stage').add_argument('--policy', required=True, type=Path)
    for name in ('apply', 'status', 'watch', 'restore'):
        command = commands.add_parser(name)
        command.add_argument('--id', required=True)
        if name == 'apply':
            command.add_argument('--confirm', required=True, help='Exact SHA-256 from the reviewed staged plan')
    args = parser.parse_args(argv)
    report = {'mode': args.mode, 'protection_verified': False, 'launch_authorized': False}
    previous = {}
    try:
        if os.geteuid() != 0:
            raise GuardError('administrator_required_no_changes')
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(sig, stop)
        pf, store = PF(), Store()
        with store.lock():
            if args.mode == 'stage':
                fd = os.open(args.policy, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                plan = stage(json.loads(read_fd(fd, False)), pf, store)
                report.update(id=plan['id'], confirm=fingerprint(plan),
                              plan_valid_until=min(plan['created_at'] + 300, validate(plan['policy'])['expires_at']),
                              destinations=validate(plan['policy'])['cidrs'],
                              root_diff='\n'.join(difflib.unified_diff(plan['root_before'].splitlines(), plan['root_after'].splitlines(), lineterm='')),
                              own_rules=plan['own_rules'], pf_will_be_enabled=not plan['pf_was_enabled'],
                              proxy_transport_endpoints_verified=False,
                              impact='All apps to listed destinations are blocked; matching states are deleted. No routes or proxy settings change.',
                              reason='staged_only_no_pf_changes')
                command = 'sudo /usr/bin/python3 ' + shlex.quote(str(Path(__file__).resolve()))
                report['apply_command'] = f"{command} apply --id {plan['id']} --confirm {fingerprint(plan)}"
                report['restore_command'] = f"{command} restore --id {plan['id']}"
                report['watch_command'] = f"{command} watch --id {plan['id']}"
            else:
                identity(args.id)
                report['id'] = args.id
                plan = store.read(args.id, 'plan')
                if plan.get('id') != args.id:
                    raise GuardError('plan_identity_mismatch')
                if args.mode == 'apply':
                    apply(plan, args.confirm, pf, store)
                    report.update(health(plan, pf, store), reason='rules_installed_traffic_acceptance_pending')
                elif args.mode == 'restore':
                    recover(plan, pf, store)
                    report['reason'] = 'owned_rules_restored_states_cannot_be_recreated'
                elif args.mode == 'status':
                    report.update(health(plan, pf, store))
        if args.mode == 'watch':
            # Release the lock between samples so independent recovery stays usable.
            # A dead observer does not unload persistent kernel block rules.
            while True:
                started = time.monotonic()
                with store.lock():
                    report.update(watch_once(plan, pf, store))
                    store.write(plan['id'], 'health', report)
                print(json.dumps(report), flush=True)
                if not report['rules_present_and_fresh']:
                    return 78
                time.sleep(max(0, 3 - (time.monotonic() - started)))
        else:
            print(json.dumps(report, indent=2))
        return 0 if report.get('rules_present_and_fresh', True) else 78
    except (GuardError, PolicyError, LabError) as error:
        report['reason'] = str(error)
        report['rules_present_and_fresh'] = False
    except (OSError, ValueError, TypeError, KeyError):
        report['reason'] = 'local_operation_failed_review_journal'
        report['rules_present_and_fresh'] = False
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    print(json.dumps(report, indent=2))
    return 78


if __name__ == '__main__':
    raise SystemExit(main())
