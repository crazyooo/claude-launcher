#!/usr/bin/env python3
"""Retire owned launch integration; preserve the application and user data.

plan/status are read-only. apply requires a matching fresh plan fingerprint.
Root operations execute only the verified installed root-owned PF runtime.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import shlex
import stat
import subprocess
import tempfile
import time

SCRIPTS = ('claude-safe', 'claude-vscode-preflight', 'claude-process-wrapper')
CONNECTOR_LABEL = 'local.crazyooo.claude-connector'
PF_LABEL = 'local.crazyooo.claude-pf-observer'
# Pre-public namespace kept so retirement still finds leftover installs.
LEGACY_CONNECTOR_LABELS = (CONNECTOR_LABEL, 'local.crazymax.claude-connector')
LEGACY_LAUNCHER_AGENTS = (
    'local.crazyooo.claude-launcher.plist',
    'local.crazymax.claude-launcher.plist',
)
PF_FILES = ('pf_service.py', 'pf_guard.py', 'pf_policy.py', 'pf_lab.py',
            'pf_runtime_identity.py', 'pf_recovery_receipt.py', 'pf_control.py')
LAYOUTS = (set(PF_FILES[:4]), set(PF_FILES[:6]), set(PF_FILES))
LIMIT = 2_000_000


class RetirementError(Exception):
    pass


def require(value, reason):
    if not value:
        raise RetirementError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def fingerprint(value):
    # Matches the installed PF runtime's canonical fingerprints.
    return digest(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode())


def snapshot(path, owner=None, root=False):
    """Absent is only ENOENT; links, special files and unstable reads fail closed."""
    require(path.resolve() == path.absolute(), 'symlink_path_preserved')
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= LIMIT,
            'unsupported_file_preserved')
    require(owner is None or before.st_uid == owner, 'foreign_file_preserved')
    require(not root or not before.st_mode & 0o022, 'writable_root_file_preserved')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino), 'file_changed')
        data = stream.read(LIMIT + 1)
        after = os.fstat(stream.fileno())
    linked = path.lstat()
    stamp = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
                           value.st_ctime_ns, value.st_mode, value.st_uid, value.st_nlink)
    require(len(data) <= LIMIT and stamp(before) == stamp(after) == stamp(linked), 'file_changed')
    return {'data': data, 'sha256': digest(data), 'stamp': list(stamp(before))}


def json_object(record):
    if record is None:
        return {}
    try:
        value = json.loads(record['data'])
    except (ValueError, UnicodeError):
        raise RetirementError('jsonc_or_invalid_json_preserved') from None
    require(isinstance(value, dict), 'json_object_required')
    return value


def same(path, record, owner=None, root=False):
    current = snapshot(path, owner, root)
    require(current == record, 'file_changed_before_write')


def output_directory(path, owner=None):
    require(path.resolve() == path.absolute(), 'symlink_directory_preserved')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == (os.geteuid() if owner is None else owner)
            and not info.st_mode & 0o022, 'untrusted_output_directory')


def atomic(path, data, mode=0o600, expected=None, check=False, owner=None, root=False):
    output_directory(path.parent, owner)
    original = snapshot(path, os.geteuid() if owner is None else owner, root)
    fd, name = tempfile.mkstemp(prefix='.retirement-', dir=path.parent)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    # An unlinked staged file is retained on failure for inspection, never overwrites
    # a concurrently changed configuration. The installation lock serializes us.
    if check:
        same(path, expected, owner, root)
    else:
        same(path, original, os.geteuid() if owner is None else owner, root)
    os.replace(name, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def run(argv, timeout=20, cwd=None):
    return subprocess.run(argv, capture_output=True, timeout=timeout, cwd=cwd,
                          env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'})


class Retirement:
    def __init__(self, home=None, pf_root=None, pf_store=None, launchdaemons=None,
                 uid=None, root_uid=0, runner=run, connector=None, process_gone=None, environment=None):
        self.home = Path(home or Path.home()).absolute()
        self.root = self.home / 'Library/Application Support/ClaudeLauncher'
        self.manifest = self.root / 'installation.json'
        self.bin = self.home / '.local/bin'
        self.app = self.home / 'Applications/Claude Launcher.app'
        self.uid = os.getuid() if uid is None else uid
        self.root_uid = root_uid
        self.pf_root = Path(pf_root or '/Library/Application Support/Claude Launcher PF')
        self.pf_store = Path(pf_store or '/private/var/run/claude-launcher-pf-guard')
        self.daemons = Path(launchdaemons or '/Library/LaunchDaemons')
        self.runner = runner
        self.connector = connector
        self.process_gone = process_gone or self._process_gone
        self.environment = dict(os.environ if environment is None else environment)

    @staticmethod
    def _process_gone(pid):
        try:
            os.kill(pid, 0)
            return False
        except ProcessLookupError:
            return True
        except PermissionError:
            return False

    @contextmanager
    def lock(self, scope):
        directory = self.root if scope == 'user' else self.pf_root
        owner = self.uid if scope == 'user' else self.root_uid
        require(directory.resolve() == directory.absolute(), 'symlink_directory_preserved')
        directory.mkdir(parents=True, exist_ok=True, mode=0o700 if scope == 'user' else 0o755)
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner and not info.st_mode & 0o022,
                'untrusted_directory')
        name = 'installation.lock' if scope == 'user' else 'install.lock'
        fd = os.open(directory / name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            # Legacy user install.py used open('a') with the normal umask,
            # creating 0644 locks. Root installer locks have always been 0600.
            accepted_modes = (0o600, 0o644) if scope == 'user' else (0o600,)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == owner and info.st_nlink == 1 and
                    stat.S_IMODE(info.st_mode) in accepted_modes, 'untrusted_lock')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    def known_settings(self):
        files = [self.home / '.claude/settings.json', self.home / '.claude/settings.local.json',
                 self.home / 'Library/Application Support/Code/User/settings.json',
                 self.home / 'Library/Application Support/Claude/claude_desktop_config.json']
        profiles = self.home / 'Library/Application Support/Code/User/profiles'
        if profiles.exists() or profiles.is_symlink():
            require(profiles.resolve() == profiles.absolute() and profiles.is_dir(), 'profile_directory_untrusted')
            entries = sorted(profiles.iterdir())
            require(len(entries) <= 128, 'too_many_profiles')
            files += [entry / 'settings.json' for entry in entries if entry.is_dir()]
        return files

    def connector_module(self):
        if self.connector is not None:
            return self.connector
        path = Path(__file__).with_name('connector_service.py')
        spec = importlib.util.spec_from_file_location('retirement_connector', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # Only user-layer operations load this helper. Root never imports it.
        module.ROOT = self.root
        module.MANIFEST = self.root / 'connector-installation.json'
        module.PLIST = self.home / 'Library/LaunchAgents' / (CONNECTOR_LABEL + '.plist')
        module.TOOL = self.app / 'Contents/MacOS/launcher-tool'
        module.DOMAIN = 'gui/' + str(self.uid)
        return module

    def user_plan(self):
        require(self.root.resolve() == self.root.absolute(), 'symlink_directory_preserved')
        manifest_record = snapshot(self.manifest, self.uid)
        manifest = json_object(manifest_record)
        require(not manifest or type(manifest.get('installed')) is bool, 'installation_not_owned')
        no_legacy_metadata = not manifest or (manifest.get('mode') == 'detector' and manifest.get('scripts') == {} and
            not manifest.get('pendingPreviousScripts') and manifest.get('integration') is False and manifest.get('vscodeIntegration') is False)
        absent = lambda path: not path.exists() and not path.is_symlink()
        if no_legacy_metadata and all(absent(self.bin / name) for name in SCRIPTS) and \
                absent(self.root / 'connector-installation.json') and \
                all(absent(self.home / 'Library/LaunchAgents' / (label + '.plist'))
                    for label in LEGACY_CONNECTOR_LABELS) and \
                all(absent(self.home / 'Library/LaunchAgents' / name)
                    for name in LEGACY_LAUNCHER_AGENTS):
            report = self.report('user', 'not_needed')
            report['fingerprint'] = fingerprint({'installation': None if manifest_record is None else manifest_record['sha256']})
            return report, {'manifest': manifest, 'manifest_record': manifest_record, 'changes': [], 'wrappers': {}, 'connector': False}
        scripts = manifest.get('scripts', {})
        previous = manifest.get('pendingPreviousScripts', {})
        require(isinstance(scripts, dict) and isinstance(previous, dict) and
                set(scripts) | set(previous) <= set(SCRIPTS), 'unknown_script_ownership')
        wrappers, inventory, blockers = {}, {}, []
        for name in SCRIPTS:
            record = snapshot(self.bin / name, self.uid)
            allowed = {scripts.get(name), previous.get(name)} - {None}
            require(all(re.fullmatch('[0-9a-f]{64}', value or '') for value in allowed), 'invalid_script_digest')
            owned = record is not None and record['sha256'] in allowed
            wrappers[name] = {'record': record, 'owned': owned}
            inventory['script:' + name] = None if record is None else record['sha256']
            if record is not None and not owned:
                blockers.append('script_modified_or_unowned:' + name)
        changes, objects, references = [], {}, []
        default_code = self.home / 'Library/Application Support/Code/User/settings.json'
        default_claude = self.home / '.claude/settings.json'
        for path in self.known_settings():
            key = str(path.relative_to(self.home))
            record = snapshot(path, self.uid)
            inventory['settings:' + key] = None if record is None else record['sha256']
            try:
                value = json_object(record)
            except RetirementError:
                blockers.append('settings_unreadable:' + key)
                continue
            next_value = dict(value)
            candidate = None
            if path == default_claude:
                candidate = ('processWrapper', 'claude-process-wrapper', 'integration')
            elif path == default_code:
                candidate = ('claudeCode.claudeProcessWrapper', 'claude-vscode-preflight', 'vscodeIntegration')
            if candidate:
                field, name, flag = candidate
                expected = str(self.bin / name)
                if field in value and value[field] == expected:
                    if manifest.get(flag) is True and wrappers[name]['owned']:
                        del next_value[field]
                        changes.append((path, record, next_value, field, expected))
                    else:
                        blockers.append('wrapper_field_not_owned:' + key)
            text = json.dumps(next_value)
            if any(str(self.bin / name) in text for name in SCRIPTS):
                references.append('wrapper_reference:' + key)
            objects[key] = next_value
        blockers += references
        proxy_keys = ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy',
                      'CLAUDE_CODE_PROCESS_WRAPPER')
        environment = {key: self.environment[key] for key in proxy_keys if key in self.environment}
        inventory['environment'] = fingerprint(environment)
        if any(str(self.bin / name) in value for name in SCRIPTS for value in environment.values()):
            blockers.append('wrapper_environment_reference')
        connector_record = snapshot(self.root / 'connector-installation.json', self.uid)
        connector_plist = self.home / 'Library/LaunchAgents' / (CONNECTOR_LABEL + '.plist')
        connector_present = connector_record is not None or connector_plist.exists() or connector_plist.is_symlink()
        inventory['manifest'] = None if manifest_record is None else manifest_record['sha256']
        inventory['connector'] = None if connector_record is None else connector_record['sha256']
        if connector_present:
            module = self.connector_module()
            try:
                module.ownership()
                pid = module.job()
            except Exception:
                raise RetirementError('connector_identity_unconfirmed') from None
            inventory['connector_job'] = pid
            # Local gateway references cannot be inferred from a successful upstream probe.
            config = json_object(snapshot(self.root / 'connector.json', self.uid))
            inventory['connector_config'] = fingerprint(config)
            port = config.get('listenPort')
            ports = {port} if type(port) is int and port > 0 else set()
            if pid is not None:
                response = self.runner([str(self.app / 'Contents/MacOS/launcher-tool'), 'connector', 'status'], timeout=6)
                try:
                    state = json.loads(response.stdout)
                    require(response.returncode == 0 and module.healthy(state),
                            'gateway_port_unconfirmed')
                    ports.add(state['port'])
                except (ValueError, RetirementError):
                    blockers.append('gateway_port_unconfirmed')
            inventory['gateway_ports'] = sorted(ports)
            for key, value in list(objects.items()) + [('process_environment', environment)]:
                for match in re.finditer(r'(?:127\.0\.0\.1|localhost|\[::1\]):([0-9]{1,5})', json.dumps(value)):
                    observed = int(match[1])
                    if observed in ports or not ports and observed != config.get('upstreamPort'):
                        blockers.append('gateway_reference:' + key)
        for name in LEGACY_LAUNCHER_AGENTS:
            legacy_agent = self.home / 'Library/LaunchAgents' / name
            if legacy_agent.exists() or legacy_agent.is_symlink():
                blockers.append('legacy_guard_requires_explicit_review')
                break
        public = self.report('user', 'blocked' if blockers else 'planned', blockers)
        public.update(fingerprint=fingerprint(inventory), scope_description='Known global Claude, VS Code and Code profile files only; project and shell overrides are not rewritten.')
        public['steps'] = [self.step('detach_wrappers', 'blocked' if blockers else 'ready'),
                           self.step('stop_connector', 'ready' if connector_present else 'not_needed'),
                           self.step('archive_wrappers', 'ready' if any(w['record'] for w in wrappers.values()) else 'not_needed')]
        if not changes and not connector_present and not any(w['record'] for w in wrappers.values()):
            public['status'] = 'not_needed' if not blockers else 'blocked'
        return public, {'manifest': manifest, 'manifest_record': manifest_record, 'changes': changes,
                        'wrappers': wrappers, 'connector': connector_present}

    @staticmethod
    def step(name, status, reason=None):
        return {'id': name, 'status': status, 'reason': reason or status}

    @staticmethod
    def report(scope, status, blockers=()):
        return {'version': 1, 'product_mode': 'detector', 'scope': scope, 'status': status,
                'blockers': list(dict.fromkeys(blockers)), 'steps': [],
                'launch_authorized': False, 'protection_verified': False}

    def archive(self, path, record, directory, owner, root=False):
        same(path, record, owner, root)
        output_directory(directory, owner)
        target = directory / (path.name + '.' + record['sha256'])
        if target.exists() or target.is_symlink():
            require(snapshot(target, owner, root)['data'] == record['data'], 'archive_conflict')
            # Keep both when an identical prior archive exists; a fresh suffix is recoverable.
            target = directory / (target.name + '.' + str(time.time_ns()))
        same(path, record, owner, root)
        os.replace(path, target)

    def apply_user(self, confirmed):
        require(os.geteuid() != 0, 'run_user_retirement_without_sudo')
        with self.lock('user'):
            plan, work = self.user_plan()
            require(plan['fingerprint'] == confirmed, 'plan_changed')
            require(not plan['blockers'], 'retirement_review_required')
            archive = self.root / 'retired' / plan['fingerprint']
            state = self.report('user', 'partial')
            status_path = self.root / 'retirement-status.json'
            atomic(status_path, encoded(state))
            for path, record, value, field, removed in work['changes']:
                same(path, record, self.uid)
                updated = encoded(value)
                undo = {'version': 1, 'relative_path': str(path.relative_to(self.home)),
                        'field': field, 'removed_value': removed,
                        'before_sha256': record['sha256'], 'after_sha256': digest(updated)}
                backup = archive / (digest(str(path).encode()) + '.field-undo.json')
                atomic(backup, encoded(undo))
                atomic(path, updated, expected=record, check=True, owner=self.uid)
            # Rebuild references and ownership after edits, before removing any dependency.
            after, _ = self.user_plan()
            require(not after['blockers'], 'references_or_ownership_changed')
            state['steps'].append(self.step('detach_wrappers', 'complete'))
            atomic(status_path, encoded(state))
            if work['connector']:
                try:
                    self.connector_module().operate('uninstall')
                except Exception:
                    raise RetirementError('connector_retirement_incomplete') from None
                state['steps'].append(self.step('stop_connector', 'complete'))
                atomic(status_path, encoded(state))
                connector_path = self.root / 'connector-installation.json'
                stopped_record = snapshot(connector_path, self.uid)
                if stopped_record is not None:
                    self.archive(connector_path, stopped_record, archive, self.uid)
            for name, wrapper in work['wrappers'].items():
                if wrapper['owned']:
                    # A new reference after service shutdown still preserves the executable.
                    fresh, _ = self.user_plan()
                    require(not fresh['blockers'], 'references_or_ownership_changed')
                    self.archive(self.bin / name, wrapper['record'], archive, self.uid)
            manifest = dict(work['manifest'])
            manifest.update(integration=False, vscodeIntegration=False, legacyRetired=True)
            if work['manifest_record'] is not None:
                atomic(archive / 'installation-manifest-backup.json', work['manifest_record']['data'])
                atomic(self.manifest, encoded(manifest), expected=work['manifest_record'], check=True, owner=self.uid)
            state['status'] = 'complete'
            state['steps'].append(self.step('archive_wrappers', 'complete'))
            atomic(status_path, encoded(state))
            return state

    def trusted_directory(self, path):
        for item in [*reversed(path.parents), path]:
            info = item.lstat()
            # macOS owns this one system ancestor as root:daemon 0775. It is not
            # our state directory; no other group-writable directory is accepted.
            system_run = (str(item) == '/private/var/run' and self.root_uid == 0 and
                          info.st_uid == 0 and info.st_gid == 1 and stat.S_IMODE(info.st_mode) == 0o775)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == self.root_uid and
                    (not info.st_mode & 0o022 or system_run),
                    'untrusted_root_directory')
            if item == self.pf_store:
                require(stat.S_IMODE(info.st_mode) == 0o700, 'guard_store_not_private')

    def root_plan(self):
        if not self.pf_root.exists() and not self.pf_root.is_symlink():
            plist = self.daemons / (PF_LABEL + '.plist')
            require(not plist.exists() and not plist.is_symlink(), 'observer_without_manifest')
            report = self.report('root', 'not_needed')
            report['fingerprint'] = fingerprint({'absent': True})
            return report, None
        self.trusted_directory(self.pf_root)
        manifest_path = self.pf_root / 'installation.json'
        record = snapshot(manifest_path, self.root_uid, True)
        require(record is not None, 'root_manifest_missing')
        manifest = json_object(record)
        files = manifest.get('files', {})
        require(isinstance(files, dict) and set(files) in LAYOUTS and
                all(isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value) for value in files.values()),
                'invalid_root_runtime_manifest')
        plan_id = manifest.get('plan_id')
        require(isinstance(plan_id, str) and re.fullmatch('[a-f0-9]{32}', plan_id), 'invalid_root_plan_id')
        runtime = self.pf_root / ('runtime-' + fingerprint(files))
        require(manifest.get('version') == 1 and manifest.get('runtime') == str(runtime) and
                manifest.get('phase') in ('installed', 'bootstrap_pending', 'install_pending', 'uninstalled'),
                'invalid_root_runtime_manifest')
        self.trusted_directory(runtime)
        require({p.name for p in runtime.iterdir()} == set(files), 'runtime_layout_changed')
        for name, expected in files.items():
            item = snapshot(runtime / name, self.root_uid, True)
            require(item is not None and item['sha256'] == expected, 'runtime_digest_changed')
        control = snapshot(self.pf_root / 'pf_control.py', self.root_uid, True)
        if control is not None:
            require('pf_control.py' in files and control['sha256'] == files['pf_control.py'], 'root_control_entry_changed')
        elif 'pf_control.py' in files and manifest['phase'] != 'uninstalled':
            raise RetirementError('root_control_entry_missing')
        self.trusted_directory(self.pf_store)
        plan_record = snapshot(self.pf_store / (plan_id + '.plan'), self.root_uid, True)
        plan = json_object(plan_record)
        require(plan.get('id') == plan_id and fingerprint(plan) == manifest.get('plan_sha256'), 'root_plan_changed')
        state_record = snapshot(self.pf_store / (plan_id + '.state'), self.root_uid, True)
        guard_state = json_object(state_record)
        require(guard_state.get('plan_sha256') == manifest['plan_sha256'], 'root_state_changed')
        plist = self.daemons / (PF_LABEL + '.plist')
        plist_record = snapshot(plist, self.root_uid, True)
        argv = ['/usr/bin/python3', '-E', '-s', '-B', str(runtime / 'pf_service.py'), 'run', '--id', plan_id]
        if plist_record is not None:
            require(plist_record['sha256'] == manifest.get('plist_sha256'), 'observer_plist_changed')
            definition = plistlib.loads(plist_record['data'])
            require(definition.get('Label') == PF_LABEL and definition.get('ProgramArguments') == argv and
                    definition.get('WorkingDirectory') == str(runtime), 'observer_definition_changed')
        job = self.root_job(runtime, argv)
        require(job is None or plist_record is not None, 'loaded_observer_without_plist')
        journal_record = snapshot(self.pf_root / 'retirement-status.json', self.root_uid, True)
        journal = json_object(journal_record)
        old_pids = manifest.get('stop_pids', [])
        pending_pids = journal.get('pending_pids', [])
        require(isinstance(old_pids, list) and isinstance(pending_pids, list) and
                len(old_pids) <= 16 and len(pending_pids) <= 16 and
                all(type(pid) is int and pid > 1 for pid in old_pids + pending_pids),
                'retirement_pid_record_invalid')
        require(not pending_pids or journal.get('plan_id') == plan_id, 'retirement_pid_plan_mismatch')
        pending_pids = sorted(set(old_pids + pending_pids))
        stopped = all(self.process_gone(pid) for pid in pending_pids)
        inventory = {'manifest': record['sha256'], 'plan': plan_record['sha256'],
                     'state': state_record['sha256'], 'plist': None if plist_record is None else plist_record['sha256'], 'job': job,
                     'journal': None if journal_record is None else journal_record['sha256']}
        report = self.report('root', 'complete' if stopped and job is None and plist_record is None and guard_state.get('phase') == 'restored' else 'planned')
        if report['status'] == 'complete':
            # A historical restored journal alone cannot establish current kernel state.
            expected_root = plan.get('root_before')
            require(isinstance(expected_root, str), 'root_baseline_missing')
            live = self.runner(['/sbin/pfctl', '-s', 'rules'], timeout=5)
            own = self.runner(['/sbin/pfctl', '-a', 'clguard_' + plan_id, '-s', 'rules'], timeout=5)
            normalize = lambda raw: '\n'.join(line.strip() for line in raw.decode('utf-8').splitlines() if line.strip())
            require(live.returncode == 0 and own.returncode == 0 and normalize(live.stdout) == expected_root and
                    not normalize(own.stdout), 'restored_rules_not_current')
        report.update(fingerprint=fingerprint(inventory))
        report['steps'] = [self.step('stop_pf_observer', 'not_needed' if job is None else 'ready'),
                           self.step('restore_owned_pf', 'complete' if guard_state.get('phase') == 'restored' else 'ready')]
        return report, dict(manifest=manifest, record=record, runtime=runtime, plan=plan_record,
                            plan_id=plan_id, plist=plist, plist_record=plist_record, job=job, argv=argv,
                            pending_pids=pending_pids)

    def root_job(self, runtime, argv):
        result = self.runner(['/bin/launchctl', 'print', 'system/' + PF_LABEL], timeout=5)
        absent = 'Could not find service "' + PF_LABEL + '" in domain for system'
        if result.returncode == 113 and absent in result.stderr.decode('utf-8', errors='replace').splitlines():
            return None
        require(result.returncode == 0, 'observer_query_unknown')
        text = result.stdout.decode('utf-8', errors='strict')
        require(len(text) <= 65536 and text.startswith('system/' + PF_LABEL + ' = {'), 'observer_identity_unknown')
        values = {}
        for key in ('path', 'program', 'working directory', 'state', 'active count'):
            found = re.findall(r'^\t' + re.escape(key) + r' = (.+)$', text, re.M)
            require(len(found) == 1, 'observer_identity_unknown')
            values[key] = found[0].strip()
        args = re.findall(r'^\targuments = \{\n((?:\t\t[^\n]*\n)*)\t\}', text, re.M)
        pids = re.findall(r'^\tpid = ([1-9][0-9]*)$', text, re.M)
        require(len(args) == 1 and len(pids) <= 1 and values['active count'].isdigit(), 'observer_identity_unknown')
        require(values['path'] == str(self.daemons / (PF_LABEL + '.plist')) and
                values['program'] == '/usr/bin/python3' and values['working directory'] == str(runtime) and
                [line.strip() for line in args[0].splitlines()] == argv, 'observer_identity_mismatch')
        require((pids and int(pids[0]) > 1) or not pids and values['state'] != 'running' and values['active count'] == '0', 'observer_pid_unknown')
        return int(pids[0]) if pids else 0

    def apply_root(self, confirmed):
        require(os.geteuid() == self.root_uid, 'administrator_required')
        if not self.pf_root.exists():
            report, _ = self.root_plan()
            require(report['fingerprint'] == confirmed, 'plan_changed')
            return report
        with self.lock('root'):
            report, work = self.root_plan()
            require(report['fingerprint'] == confirmed, 'plan_changed')
            if work is None:
                return report
            journal_path = self.pf_root / 'retirement-status.json'
            if report['status'] == 'complete':
                # A prior attempt may have restored PF and then stopped before
                # persisting its public attestation. A fresh kernel check above
                # allows this retry to finish the record without any PF mutation.
                report.update(checked_at=time.time(), manifest_sha256=work['record']['sha256'])
                atomic(journal_path, encoded(report), mode=0o644)
                return report
            pids = work['pending_pids']
            if work['job']:
                pids = sorted(set(pids + [work['job']]))
            state = self.report('root', 'partial')
            state.update(pending_pids=pids, plan_id=work['plan_id'])
            atomic(journal_path, encoded(state), mode=0o644)
            if work['job'] is not None:
                self.runner(['/bin/launchctl', 'bootout', 'system/' + PF_LABEL], timeout=20)
            deadline = time.monotonic() + 15
            while True:
                job = self.root_job(work['runtime'], work['argv'])
                if job and job not in pids:
                    require(len(pids) < 16, 'too_many_observer_processes')
                    pids = sorted(set(pids + [job]))
                    state['pending_pids'] = pids
                    atomic(journal_path, encoded(state), mode=0o644)
                if job is None and all(self.process_gone(pid) for pid in pids):
                    break
                require(time.monotonic() < deadline, 'observer_stop_pending')
                time.sleep(.1)
            state['steps'].append(self.step('stop_pf_observer', 'complete'))
            state['pending_pids'] = []
            atomic(journal_path, encoded(state), mode=0o644)
            # Verify trusted files again after the asynchronous stop boundary.
            self.reverify_root(work)
            if work['plist_record'] is not None:
                self.archive(work['plist'], work['plist_record'], self.pf_root / 'retired', self.root_uid, True)
            manifest = dict(work['manifest'])
            manifest.update(phase='uninstalled', stop_requested=False, stop_pids=[])
            atomic(self.pf_root / 'installation.json', encoded(manifest), mode=0o644, expected=work['record'],
                   check=True, owner=self.root_uid, root=True)
            # Only this verified installed runtime may restore the original owned plan.
            self.reverify_root(work)
            result = self.runner(['/usr/bin/python3', '-E', '-s', '-B', str(work['runtime'] / 'pf_guard.py'),
                                  'restore', '--id', work['plan_id']], timeout=45, cwd=str(work['runtime']))
            try:
                restored = json.loads(result.stdout)
            except (ValueError, UnicodeError):
                restored = {}
            require(result.returncode == 0 and restored.get('reason') == 'owned_rules_restored_states_cannot_be_recreated',
                    'owned_pf_restore_incomplete')
            final, _ = self.root_plan()
            require(final['status'] == 'complete', 'owned_pf_restore_unconfirmed')
            final['steps'] = state['steps'] + [self.step('restore_owned_pf', 'complete')]
            final.update(checked_at=time.time(), manifest_sha256=snapshot(self.pf_root / 'installation.json', self.root_uid, True)['sha256'])
            atomic(journal_path, encoded(final), mode=0o644)
            return final

    def reverify_root(self, original):
        _, current = self.root_plan()
        require(current is not None and current['runtime'] == original['runtime'] and
                current['plan_id'] == original['plan_id'] and current['plan'] == original['plan'] and
                current['manifest']['files'] == original['manifest']['files'], 'root_identity_changed_during_retirement')

    def recorded_root_status(self):
        """Root-owned completion attestation, explicitly not a live kernel inspection."""
        self.trusted_directory(self.pf_root)
        report = json_object(snapshot(self.pf_root / 'retirement-status.json', self.root_uid, True))
        manifest_record = snapshot(self.pf_root / 'installation.json', self.root_uid, True)
        require(report.get('version') == 1 and report.get('status') == 'complete' and
                report.get('manifest_sha256') == manifest_record['sha256'] and
                type(report.get('checked_at')) in (int, float), 'root_retirement_record_unconfirmed')
        manifest = json_object(manifest_record)
        require(manifest.get('phase') == 'uninstalled', 'root_retirement_record_unconfirmed')
        plist = self.daemons / (PF_LABEL + '.plist')
        require(not plist.exists() and not plist.is_symlink(), 'observer_reappeared')
        value = self.report('root', 'complete')
        value.update(evidence='administrator_record', checked_at=report['checked_at'], live_pf_verified=False,
                     steps=[self.step('restore_owned_pf', 'complete', 'administrator_record_not_live_kernel_inspection')])
        return value

    def status(self):
        parts = {}
        for scope, inspect in [('user', self.user_plan), ('root', self.root_plan)]:
            try:
                parts[scope] = inspect()[0]
            except PermissionError:
                try:
                    require(scope == 'root', 'not_root_scope')
                    parts[scope] = self.recorded_root_status()
                except Exception:
                    parts[scope] = self.report(scope, 'unknown', ['administrator_inspection_required'])
            except RetirementError as error:
                parts[scope] = self.report(scope, 'blocked', [str(error)])
            except Exception:
                parts[scope] = self.report(scope, 'unknown', ['inspection_failed'])
        complete = lambda part: part['status'] in ('complete', 'not_needed')
        result = self.report('all', 'complete' if all(map(complete, parts.values())) else 'partial')
        result.update(overall=result['status'], user_complete=complete(parts['user']), root_complete=complete(parts['root']),
                      user=parts['user'], root=parts['root'], steps=parts['user']['steps'] + parts['root']['steps'])
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('status', 'plan', 'apply'))
    parser.add_argument('--scope', choices=('user', 'root'), default='user')
    parser.add_argument('--confirm')
    args = parser.parse_args(argv)
    tool = Retirement()
    try:
        if args.action == 'status':
            result = tool.status()
        elif args.action == 'plan':
            result = (tool.user_plan() if args.scope == 'user' else tool.root_plan())[0]
            if not result['blockers']:
                prefix = ['sudo'] if args.scope == 'root' else []
                result['apply_command'] = shlex.join(prefix + ['/usr/bin/python3', '-I', '-B', str(Path(__file__).absolute()),
                    'apply', '--scope', args.scope, '--confirm', result['fingerprint']])
        else:
            require(isinstance(args.confirm, str) and re.fullmatch('[a-f0-9]{64}', args.confirm), 'reviewed_plan_required')
            result = tool.apply_user(args.confirm) if args.scope == 'user' else tool.apply_root(args.confirm)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result['status'] in ('complete', 'not_needed', 'planned') else 78
    except RetirementError as error:
        reason = str(error)
    except PermissionError:
        reason = 'administrator_inspection_required' if args.scope == 'root' else 'file_permission_denied'
    except Exception:
        reason = 'retirement_incomplete_files_preserved'
    print(json.dumps(tool.report(args.scope, 'blocked', [reason])))
    return 78


if __name__ == '__main__':
    raise SystemExit(main())
