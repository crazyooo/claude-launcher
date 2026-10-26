#!/usr/bin/env python3
"""Install network preflight and migrate owned legacy isolation infrastructure."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shlex
import shutil
import subprocess
import tempfile
import time
import signal
import uuid
import importlib.util

PROJECT=Path(__file__).resolve().parents[1]
HOME=Path.home()
ROOT=HOME/'Library/Application Support/ClaudeLauncher'
APP=HOME/'Applications/Claude Launcher.app'
BIN=HOME/'.local/bin'
AGENT=HOME/'Library/LaunchAgents/local.crazymax.claude-launcher.plist'
SETTINGS=HOME/'.claude/settings.json'
MANIFEST=ROOT/'installation.json'
TOOL=APP/'Contents/MacOS/launcher-tool'
WRAPPER=BIN/'claude-process-wrapper'
VSCODE_SETTINGS=HOME/'Library/Application Support/Code/User/settings.json'
VSCODE_FIELD='claudeCode.claudeProcessWrapper'

def vscode_change(enable,manifest,dry_run=False,expected=None):
    original=VSCODE_SETTINGS.read_bytes() if VSCODE_SETTINGS.exists() else b'{}'
    if expected is not None and original!=expected:raise RuntimeError('VS Code settings changed concurrently; preserved')
    # Preserve unsupported JSONC verbatim instead of stripping comments on write.
    try:settings=json.loads(original)
    except Exception:raise RuntimeError('VS Code settings contain JSONC or invalid JSON; preserved, resolve before installation')
    if not isinstance(settings,dict):raise RuntimeError('VS Code settings must be an object')
    wrapper=str(BIN/'claude-vscode-preflight')
    if enable:
        if VSCODE_FIELD in settings and not (manifest.get('vscodeIntegration') and settings[VSCODE_FIELD]==wrapper):
            raise RuntimeError('Existing VS Code wrapper is not owned; preserved')
        settings[VSCODE_FIELD]=wrapper
    elif manifest.get('vscodeIntegration') and settings.get(VSCODE_FIELD)==wrapper:
        del settings[VSCODE_FIELD]
    if not enable and wrapper in json.dumps(settings):raise RuntimeError('VS Code still references wrapper; preserve installation')
    if (VSCODE_SETTINGS.read_bytes() if VSCODE_SETTINGS.exists() else b'{}')!=original:raise RuntimeError('VS Code settings changed concurrently')
    if dry_run:return original
    if settings!=json.loads(original):atomic(VSCODE_SETTINGS,(json.dumps(settings,ensure_ascii=False,indent=2)+'\n').encode())

def atomic(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(dir=path.parent,prefix='.launcher-')
    try:
        with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.chmod(name,0o600);os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)

def settings_change(enable,manifest,dry_run=False,expected=None):
    original=SETTINGS.read_bytes() if SETTINGS.exists() else b'{}'
    if expected is not None and original!=expected:raise RuntimeError('Settings changed during integration activation')
    settings=json.loads(original)
    if not isinstance(settings,dict):raise RuntimeError('settings.json must be an object')
    field=str(WRAPPER)
    if enable:
        env=settings.get('env',{})
        if isinstance(env,dict) and env.get('CLAUDE_CODE_PROCESS_WRAPPER') not in (None,field):raise RuntimeError('Existing environment wrapper conflict; nothing overwritten')
        if 'processWrapper' in settings and not (manifest.get('integration') and settings['processWrapper']==field):raise RuntimeError('Existing processWrapper is not owned by this installer')
        settings['processWrapper']=field
    elif manifest.get('integration') and settings.get('processWrapper')==field:
        del settings['processWrapper']
    # Never remove binaries still referenced by user-edited settings.
    if not enable and field in json.dumps(settings):raise RuntimeError('Settings still reference wrapper; preserve installation and resolve that reference first')
    current=SETTINGS.read_bytes() if SETTINGS.exists() else b'{}'
    if current!=original:raise RuntimeError('Settings changed concurrently; retry')
    if dry_run:return original
    if settings!=json.loads(original):atomic(SETTINGS,(json.dumps(settings,ensure_ascii=False,indent=2)+'\n').encode())

def trash(path):
    if path.exists() or path.is_symlink():
        # User's deletion protocol: Finder Trash, recoverable; no rm.
        script='tell application "Finder" to delete POSIX file '+json.dumps(str(path))
        subprocess.run(['/usr/bin/osascript','-e',script],check=True,capture_output=True)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def verify_owned(manifest):
    if AGENT.exists() and (not manifest.get('installed') or manifest.get('agentDigest') != digest(AGENT)):
        raise RuntimeError('LaunchAgent is unowned or user-modified; installation preserved')
    for name in set(manifest.get('scripts',{})) | set(manifest.get('pendingPreviousScripts',{})):
        old_digest=manifest.get('scripts',{}).get(name)
        path=BIN/name
        acceptable={old_digest,manifest.get('pendingPreviousScripts',{}).get(name)}
        if path.exists() and digest(path) not in acceptable and str(TOOL) in path.read_text():
            raise RuntimeError(f'Modified entry still depends on installed tool: {path}; installation preserved')

def stop_owned(manifest):
    if not manifest.get('installed'):return
    if (ROOT/'connector-installation.json').exists():
        subprocess.run(['/usr/bin/python3', '-E', '-s', '-B', str(PROJECT/'tools/connector_service.py'), 'stop'],
                       check=True, capture_output=True, timeout=30)
    stop_monitor()
    if manifest.get('mode')=='preflight':return
    query=subprocess.run(['/bin/launchctl','print',f'gui/{os.getuid()}/local.crazymax.claude-launcher'],capture_output=True)
    if query.returncode==0:
        block=subprocess.run([str(TOOL),'block'],capture_output=True,text=True,timeout=4)
        if block.returncode or json.loads(block.stdout).get('networkAllowed'):
            raise RuntimeError('Cannot confirm gateway blocked; installation preserved')
        subprocess.run(['/bin/launchctl','bootout',f'gui/{os.getuid()}',str(AGENT)],check=True,capture_output=True,timeout=5)
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        query=subprocess.run(['/bin/launchctl','print',f'gui/{os.getuid()}/local.crazymax.claude-launcher'],capture_output=True)
        processes=subprocess.run(['/bin/ps','-axo','comm='],capture_output=True,text=True,check=True)
        if query.returncode!=0 and str(TOOL) not in processes.stdout.splitlines():return
        time.sleep(.1)
    raise RuntimeError('Guard/gateway did not stop; files preserved')

def monitor_pids():
    expected=str(APP/'Contents/MacOS/ClaudeLauncher')
    result=subprocess.run(['/bin/ps','-axo','pid=,comm='],check=True,capture_output=True,text=True)
    found=[]
    for line in result.stdout.splitlines():
        fields=line.strip().split(None,1)
        if len(fields)==2 and fields[1]==expected:found.append(int(fields[0]))
    return found

def stop_monitor():
    for pid in monitor_pids():
        try:os.kill(pid,signal.SIGTERM)
        except ProcessLookupError:pass
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        if not monitor_pids():return
        time.sleep(.1)
    raise RuntimeError('Network checker did not stop; app preserved')

def stage_app(source):
    APP.parent.mkdir(parents=True,exist_ok=True)
    stage=APP.parent/('.ClaudeLauncher-stage-'+str(uuid.uuid4())+'.app')
    shutil.copytree(source,stage)
    subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(stage)],check=True,capture_output=True)
    return stage

def retirement_tool():
    path = Path(__file__).with_name('retire_legacy.py')
    spec = importlib.util.spec_from_file_location('installer_retirement', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module.Retirement(home=HOME)

def install_detector():
    """Replace only the owned application. Never install wrappers or bootstrap jobs."""
    retirement = retirement_tool()
    with retirement.lock('user'):
        plan, evidence = retirement.user_plan()
        if plan['blockers'] or plan['status'] not in ('not_needed', 'complete'):
            raise RuntimeError('legacy_user_retirement_required')
        manifest = dict(evidence['manifest'])
        if APP.exists() and manifest.get('installed') is not True:
            raise RuntimeError('destination_app_not_owned')
        if APP.is_symlink():raise RuntimeError('destination_app_is_symlink')
        previous_backup = Path(manifest['appBackup']) if manifest.get('appBackup') else None
        if previous_backup is not None:
            if previous_backup.parent != APP.parent or not previous_backup.name.startswith('.ClaudeLauncher-backup-') or previous_backup.is_symlink():
                raise RuntimeError('invalid_bundle_recovery_path')
            if not APP.exists() and previous_backup.exists():os.replace(previous_backup, APP)
        source = PROJECT/'dist/Claude Launcher.app'
        if not source.exists():
            packaged = Path(__file__).resolve().parents[2]
            if packaged.suffix == '.app':source = packaged
        if not source.exists():raise RuntimeError('detector_build_required')
        stage = stage_app(source)
        # Recheck before replacing the tool on which old wrappers might depend.
        current, _ = retirement.user_plan()
        if current['fingerprint'] != plan['fingerprint'] or current['blockers']:
            raise RuntimeError('retirement_state_changed')
        if manifest.get('installed'):stop_monitor()
        backup = APP.parent/('.ClaudeLauncher-backup-'+str(uuid.uuid4())+'.app')
        evidence_archive = ROOT/'retired'/('detector-install-'+uuid.uuid4().hex)
        atomic(evidence_archive/'installation-before.json', json.dumps(manifest,sort_keys=True).encode())
        manifest.update(installed=True, mode='detector', integration=False, vscodeIntegration=False,
                        scripts={}, pendingPreviousScripts={}, appBackup=str(backup))
        atomic(MANIFEST,json.dumps(manifest,sort_keys=True).encode())
        if APP.exists():os.replace(APP,backup)
        try:
            os.replace(stage,APP)
            subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(APP)],check=True,capture_output=True)
        except Exception:
            if APP.exists():os.replace(APP,stage)
            if backup.exists():os.replace(backup,APP)
            raise
        archives = list(manifest.get('retiredApps', []))
        for item in (backup, previous_backup):
            if item is not None and item.exists() and str(item) not in archives:archives.append(str(item))
        manifest['retiredApps'] = archives
        manifest.pop('appBackup',None); manifest.pop('pendingPreviousScripts',None)
        atomic(MANIFEST,json.dumps(manifest,sort_keys=True).encode())
        print(json.dumps({'version':1,'reason':'detector_app_installed','mode':'detector',
                          'wrappers_created':False,'services_started':False,
                          'root_retirement':'inspect_separately','launch_authorized':False}))

def main():
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['install','uninstall','enable-integration'])
    parser.add_argument('--mode',choices=['detector','preflight'],default='detector');args=parser.parse_args()
    if args.action=='install' and args.mode=='detector':return install_detector()
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
    with (ROOT/'installation.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        manifest=json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}
        verify_owned(manifest)
        previous_backup=Path(manifest['appBackup']) if manifest.get('appBackup') else None
        if previous_backup is not None:
            if previous_backup.parent!=APP.parent or not previous_backup.name.startswith('.ClaudeLauncher-backup-'):
                raise RuntimeError('Invalid recovery path; installation preserved')
            if args.action=='install' and manifest.get('installed') and not APP.exists() and previous_backup.exists():os.replace(previous_backup,APP)
        if args.action=='enable-integration':
            if manifest.get('mode') in ('preflight','detector'):raise RuntimeError('Global integration is disabled in this installation mode')
            if not manifest.get('installed'):raise RuntimeError('Install the app first')
            result=subprocess.run([str(TOOL),'status'],check=True,capture_output=True,text=True)
            state=json.loads(result.stdout)
            if not state.get('networkAllowed') or not state.get('cliCompatible'):raise RuntimeError('CLI acceptance and preflight must pass before activating processWrapper')
            original=settings_change(True,manifest,dry_run=True)
            previous=manifest.get('integration',False)
            manifest['integration']=True;atomic(MANIFEST,json.dumps(manifest).encode())
            try:settings_change(True,manifest,expected=original)
            except Exception:
                manifest['integration']=previous;atomic(MANIFEST,json.dumps(manifest).encode());raise
            print('processWrapper enabled; restart existing Claude Code supervisors manually.');return
        if args.action=='uninstall':
            if not manifest.get('installed'):print('No owned installation; nothing changed.');return
            settings_change(False,manifest,dry_run=True)
            vscode_change(False,manifest,dry_run=True)
            settings_change(False,manifest)
            vscode_change(False,manifest)
            stop_owned(manifest)
            if (ROOT/'connector-installation.json').exists():
                subprocess.run(['/usr/bin/python3', '-E', '-s', '-B', str(PROJECT/'tools/connector_service.py'), 'uninstall'],
                               check=True, capture_output=True, timeout=30)
            for name in set(manifest.get('scripts',{})) | set(manifest.get('pendingPreviousScripts',{})):
                path=BIN/name
                accepted={manifest.get('scripts',{}).get(name),manifest.get('pendingPreviousScripts',{}).get(name)}
                if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() in accepted:trash(path)
                elif path.exists():print(f'Preserved user-modified entry: {path}')
            if manifest.get('installed'):
                trash(AGENT);trash(APP)
                if previous_backup is not None:trash(previous_backup)
            manifest.pop('appBackup',None);manifest.pop('pendingPreviousScripts',None)
            manifest['installed']=False;manifest['integration']=False;manifest['vscodeIntegration']=False;atomic(MANIFEST,json.dumps(manifest).encode())
            print('Uninstalled. User config, diagnostics and Keychain credential retained.');return
        source=PROJECT/'dist/Claude Launcher.app'
        if not source.exists():raise RuntimeError('Run tools/build.sh first')
        if APP.exists() and not manifest.get('installed'):raise RuntimeError('Destination app exists and is not owned by this installer')
        scripts={
            'claude-safe':f'#!/bin/sh\nexec {shlex.quote(str(TOOL))} run "$@"\n',
            'claude-vscode-preflight':f'#!/bin/sh\nexec {shlex.quote(str(TOOL))} preflight-wrap "$@"\n',
        }
        for name,content in scripts.items():
            path=BIN/name
            if path.is_symlink():raise RuntimeError(f'Entry is a symbolic link: {name}; preserved')
            accepted={manifest.get('scripts',{}).get(name),manifest.get('pendingPreviousScripts',{}).get(name)}
            if path.exists() and path.read_text()!=content and digest(path) not in accepted:raise RuntimeError(f'Entry already exists: {name}; not overwritten')
        original_vscode=vscode_change(True,manifest,dry_run=True)
        settings_change(False,manifest,dry_run=True)
        stage=stage_app(source)
        stop_owned(manifest)
        settings_change(False,manifest)
        if AGENT.exists():trash(AGENT)
        for name,old_digest in manifest.get('scripts',{}).items():
            path=BIN/name
            if name not in scripts and path.exists() and digest(path)==old_digest:trash(path)
        # Record exact ownership before materializing files, so interrupted installs can retry.
        backup=APP.parent/('.ClaudeLauncher-backup-'+str(uuid.uuid4())+'.app')
        prior_scripts={**manifest.get('scripts',{}),**manifest.get('pendingPreviousScripts',{})}
        manifest.update(installed=True,mode='preflight',integration=False,vscodeIntegration=True,appBackup=str(backup),pendingPreviousScripts=prior_scripts,scripts={name:hashlib.sha256(content.encode()).hexdigest() for name,content in scripts.items()})
        atomic(MANIFEST,json.dumps(manifest).encode())
        if APP.exists():os.replace(APP,backup)
        try:
            os.replace(stage,APP)
            subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(APP)],check=True,capture_output=True)
        except Exception:
            if APP.exists():os.replace(APP,stage)
            if backup.exists():os.replace(backup,APP)
            raise
        BIN.mkdir(parents=True,exist_ok=True)
        for name,content in scripts.items():atomic(BIN/name,content.encode());os.chmod(BIN/name,0o700)
        vscode_change(True,manifest,expected=original_vscode)
        if backup.exists():trash(backup)
        if previous_backup is not None and previous_backup.exists():trash(previous_backup)
        manifest.pop('appBackup',None);manifest.pop('pendingPreviousScripts',None);atomic(MANIFEST,json.dumps(manifest).encode())
        print(f'Installed: {APP}\nNative claude unchanged. claude-safe and VS Code entries remain locked by strict acceptance; global processWrapper is not enabled.')
if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit('Installation stopped; existing files preserved. Inspect the retirement status and ownership conflicts.')
