#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess

spec=importlib.util.spec_from_file_location('installer',Path(__file__).with_name('install.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        module.PROJECT=self.root;module.ROOT=self.root/'support';module.APP=self.root/'apps/launcher.app';module.MANIFEST=module.ROOT/'installation.json'
        module.SETTINGS=self.root/'settings.json';module.WRAPPER=self.root/'claude-process-wrapper';module.AGENT=self.root/'agent.plist';module.BIN=self.root;module.TOOL=self.root/'app/tool'
        module.VSCODE_SETTINGS=self.root/'vscode-settings.json'
    def tearDown(self):self.temp.cleanup()
    def test_merge_restore_unknown_fields(self):
        original={'theme':'dark','env':{'OTHER':'keep'},'permissions':{'allow':['Read']}}
        module.SETTINGS.write_text(json.dumps(original))
        module.settings_change(True,{})
        installed=json.loads(module.SETTINGS.read_text());self.assertEqual(installed['theme'],'dark');self.assertEqual(installed['processWrapper'],str(module.WRAPPER))
        installed['theme']='light';installed['new']='user change';module.SETTINGS.write_text(json.dumps(installed))
        module.settings_change(False,{'integration':True})
        result=json.loads(module.SETTINGS.read_text());self.assertNotIn('processWrapper',result);self.assertEqual(result['theme'],'light');self.assertEqual(result['new'],'user change');self.assertEqual(result['env'],original['env'])
    def test_foreign_wrapper_conflict(self):
        for value in [{'processWrapper':'foreign'},{'env':{'CLAUDE_CODE_PROCESS_WRAPPER':'foreign'}}]:
            module.SETTINGS.write_text(json.dumps(value));before=module.SETTINGS.read_bytes()
            with self.assertRaises(RuntimeError):module.settings_change(True,{})
            self.assertEqual(module.SETTINGS.read_bytes(),before)
    def test_user_changed_field_preserved(self):
        module.SETTINGS.write_text(json.dumps({'processWrapper':'user-new'}));module.settings_change(False,{'integration':True})
        self.assertEqual(json.loads(module.SETTINGS.read_text())['processWrapper'],'user-new')
    def test_modified_reference_blocks_uninstall(self):
        module.SETTINGS.write_text(json.dumps({'processWrapper':str(module.WRAPPER)+' --custom'}))
        with self.assertRaises(RuntimeError):module.settings_change(False,{'integration':True})
    def test_unowned_agent_rejected(self):
        module.AGENT.write_text('foreign')
        with self.assertRaises(RuntimeError):module.verify_owned({})
        with self.assertRaises(RuntimeError):module.verify_owned({'installed':True,'agentDigest':'wrong'})
        module.verify_owned({'installed':True,'agentDigest':module.digest(module.AGENT)})
    def test_modified_dependent_script_preserves_app(self):
        module.WRAPPER.write_text(str(module.TOOL)+' custom')
        with self.assertRaises(RuntimeError):module.verify_owned({'scripts':{module.WRAPPER.name:'old'}})
    def test_same_value_without_ownership_is_conflict(self):
        module.SETTINGS.write_text(json.dumps({'processWrapper':str(module.WRAPPER)}))
        before=module.SETTINGS.read_bytes()
        with self.assertRaises(RuntimeError):module.settings_change(True,{},dry_run=True)
        self.assertEqual(module.SETTINGS.read_bytes(),before)
    def test_full_install_and_uninstall_main(self):
        native=module.BIN/'claude';native.write_text('native-install-sentinel')
        source=self.root/'dist/Claude Launcher.app';source.mkdir(parents=True);(source/'fixture').write_text('build')
        success=subprocess.CompletedProcess([],0,stdout='',stderr='')
        with patch('sys.argv',['install.py','install','--mode','preflight']),patch.object(module.subprocess,'run',return_value=success):
            module.main()
        manifest=json.loads(module.MANIFEST.read_text());self.assertTrue(manifest['installed']);self.assertEqual(manifest['mode'],'preflight');self.assertFalse(module.AGENT.exists())
        self.assertEqual(json.loads(module.VSCODE_SETTINGS.read_text())[module.VSCODE_FIELD],str(module.BIN/'claude-vscode-preflight'))
        self.assertTrue((module.APP/'fixture').exists());self.assertFalse(module.SETTINGS.exists())
        safe=module.BIN/'claude-safe'
        self.assertIn(' run "$@"',safe.read_text())
        self.assertEqual(module.digest(safe),manifest['scripts']['claude-safe'])
        self.assertEqual(safe.stat().st_mode & 0o777,0o700)
        self.assertEqual(native.read_text(),'native-install-sentinel');self.assertFalse(manifest['integration'])
        # Mutation of user settings stays intact across uninstall.
        module.SETTINGS.write_text(json.dumps({'theme':'user','processWrapper':str(module.WRAPPER)}))
        manifest['integration']=True;module.MANIFEST.write_text(json.dumps(manifest))
        with patch('sys.argv',['install.py','uninstall']),patch.object(module,'stop_owned'),patch.object(module,'trash') as trash:
            module.main()
            self.assertIn(module.APP,[call.args[0] for call in trash.call_args_list])
            self.assertIn(safe,[call.args[0] for call in trash.call_args_list])
            self.assertNotIn(native,[call.args[0] for call in trash.call_args_list])
        self.assertEqual(json.loads(module.SETTINGS.read_text()),{'theme':'user'})
        self.assertFalse(json.loads(module.MANIFEST.read_text())['installed'])
        self.assertNotIn(module.VSCODE_FIELD,json.loads(module.VSCODE_SETTINGS.read_text()))
        self.assertEqual(native.read_text(),'native-install-sentinel')
    def test_safe_wrapper_preserves_arguments_directory_environment(self):
        source=self.root/'dist/Claude Launcher.app';source.mkdir(parents=True)
        success=subprocess.CompletedProcess([],0,stdout='',stderr='')
        with patch('sys.argv',['install.py','install','--mode','preflight']),patch.object(module.subprocess,'run',return_value=success):module.main()
        module.TOOL.parent.mkdir(parents=True,exist_ok=True)
        module.TOOL.write_text('#!/bin/sh\nprintf "<%s>\\n" "$@"\nprintf "cwd=%s\\nfixture=%s\\n" "$PWD" "$LAUNCHER_TEST_VALUE"\nexit 78\n')
        module.TOOL.chmod(0o700)
        result=subprocess.run([str(module.BIN/'claude-safe'),'space value','$HOME','*.txt',''],cwd=self.root,env={'LAUNCHER_TEST_VALUE':'retained'},capture_output=True,text=True)
        self.assertEqual(result.returncode,78)
        self.assertEqual(result.stdout,f'<run>\n<space value>\n<$HOME>\n<*.txt>\n<>\ncwd={self.root.resolve()}\nfixture=retained\n')
    def test_safe_entry_conflict_is_not_overwritten(self):
        source=self.root/'dist/Claude Launcher.app';source.mkdir(parents=True)
        safe=module.BIN/'claude-safe';safe.write_text('foreign-owner')
        with patch('sys.argv',['install.py','install','--mode','preflight']),patch.object(module,'stage_app') as stage:
            with self.assertRaises(RuntimeError):module.main()
            stage.assert_not_called()
        self.assertEqual(safe.read_text(),'foreign-owner')
    def test_global_integration_remains_disabled(self):
        module.ROOT.mkdir();module.MANIFEST.write_text(json.dumps({'installed':True,'mode':'preflight'}))
        with patch('sys.argv',['install.py','enable-integration']),patch.object(module.subprocess,'run') as run:
            with self.assertRaises(RuntimeError):module.main()
            run.assert_not_called()
        self.assertFalse(module.SETTINGS.exists())
    def test_dangling_safe_entry_is_preserved(self):
        source=self.root/'dist/Claude Launcher.app';source.mkdir(parents=True)
        safe=module.BIN/'claude-safe';safe.symlink_to(self.root/'missing-owned-elsewhere')
        with patch('sys.argv',['install.py','install','--mode','preflight']),patch.object(module,'stage_app') as stage:
            with self.assertRaises(RuntimeError):module.main()
            stage.assert_not_called()
        self.assertTrue(safe.is_symlink())
    def test_vscode_preserves_other_fields_and_user_changes(self):
        module.VSCODE_SETTINGS.write_text(json.dumps({'editor.fontSize':14,'claudeCode.environmentVariables':[{'name':'CUSTOM','value':'keep'}]}))
        module.vscode_change(True,{})
        d=json.loads(module.VSCODE_SETTINGS.read_text());d['editor.fontSize']=16;module.VSCODE_SETTINGS.write_text(json.dumps(d))
        module.vscode_change(False,{'vscodeIntegration':True})
        d=json.loads(module.VSCODE_SETTINGS.read_text());self.assertEqual(d['editor.fontSize'],16);self.assertEqual(d['claudeCode.environmentVariables'][0]['value'],'keep')
    def test_vscode_foreign_wrapper_and_jsonc_are_not_overwritten(self):
        for text in [json.dumps({module.VSCODE_FIELD:'/foreign'}),'{//comment\n"theme":"keep"}']:
            module.VSCODE_SETTINGS.write_text(text)
            with self.assertRaises(RuntimeError):module.vscode_change(True,{})
            self.assertEqual(module.VSCODE_SETTINGS.read_text(),text)
    def test_vscode_concurrent_change_and_dangling_reference(self):
        module.VSCODE_SETTINGS.write_text('{}');original=module.vscode_change(True,{},dry_run=True)
        module.VSCODE_SETTINGS.write_text('{"new":true}')
        with self.assertRaises(RuntimeError):module.vscode_change(True,{},expected=original)
        module.VSCODE_SETTINGS.write_text(json.dumps({module.VSCODE_FIELD:str(module.BIN/'claude-vscode-preflight')+' custom'}))
        with self.assertRaises(RuntimeError):module.vscode_change(False,{'vscodeIntegration':True})
    def test_monitor_stop_only_uses_exact_owned_executable(self):
        output=f'111 {module.APP}/Contents/MacOS/ClaudeLauncher\n222 /Applications/Claude.app/Contents/MacOS/Claude\n333 /Other/ClaudeLauncher\n'
        with patch.object(module.subprocess,'run',return_value=subprocess.CompletedProcess([],0,stdout=output)):
            self.assertEqual(module.monitor_pids(),[111])
        with patch.object(module,'monitor_pids',side_effect=[[111],[]]),patch.object(module.os,'kill') as kill:
            module.stop_owned({'installed':True,'mode':'preflight'})
            kill.assert_called_once_with(111,module.signal.SIGTERM)
    def test_staging_failure_preserves_installed_app(self):
        module.APP.mkdir(parents=True);(module.APP/'keep').write_text('old')
        with patch.object(module.shutil,'copytree',side_effect=OSError('interrupted')):
            with self.assertRaises(OSError):module.stage_app(self.root/'source')
        self.assertEqual((module.APP/'keep').read_text(),'old')
    def test_upgrade_replaces_bundle_without_old_resource(self):
        source=self.root/'dist/Claude Launcher.app';source.mkdir(parents=True);(source/'new').write_text('new')
        module.APP.mkdir(parents=True);(module.APP/'stale').write_text('stale')
        module.ROOT.mkdir();module.MANIFEST.write_text(json.dumps({'installed':True,'mode':'preflight'}))
        with patch('sys.argv',['install.py','install','--mode','preflight']),patch.object(module,'stop_owned'),patch.object(module,'trash'),patch.object(module.subprocess,'run',return_value=subprocess.CompletedProcess([],0,stdout='')):
            module.main()
        self.assertTrue((module.APP/'new').exists());self.assertFalse((module.APP/'stale').exists())
    def test_interrupted_script_update_accepts_only_recorded_old_or_new(self):
        p=module.BIN/'claude-vscode-preflight';p.write_text(str(module.TOOL)+' old')
        old=module.digest(p)
        manifest={'scripts':{p.name:'new-digest'},'pendingPreviousScripts':{p.name:old}}
        module.verify_owned(manifest)
        p.write_text(str(module.TOOL)+' unexpected-user-edit')
        with self.assertRaises(RuntimeError):module.verify_owned(manifest)
    def test_interrupted_bundle_replacement_can_retry(self):
        source=self.root/'dist/Claude Launcher.app';source.mkdir(parents=True);(source/'new').write_text('new')
        module.APP.mkdir(parents=True);(module.APP/'old').write_text('old')
        module.ROOT.mkdir();module.MANIFEST.write_text(json.dumps({'installed':True,'mode':'preflight'}))
        original=module.os.replace
        def fail_stage(src,dst):
            if Path(src).name.startswith('.ClaudeLauncher-stage-') and Path(dst)==module.APP:raise OSError('injected interruption')
            return original(src,dst)
        with patch('sys.argv',['install.py','install','--mode','preflight']),patch.object(module,'stop_owned'),patch.object(module.subprocess,'run',return_value=subprocess.CompletedProcess([],0,stdout='')),patch.object(module.os,'replace',side_effect=fail_stage):
            with self.assertRaises(OSError):module.main()
        self.assertTrue((module.APP/'old').exists())
        with patch('sys.argv',['install.py','install','--mode','preflight']),patch.object(module,'stop_owned'),patch.object(module,'trash'),patch.object(module.subprocess,'run',return_value=subprocess.CompletedProcess([],0,stdout='')):
            module.main()
        self.assertTrue((module.APP/'new').exists());self.assertFalse((module.APP/'old').exists())
        self.assertNotIn('pendingPreviousScripts',json.loads(module.MANIFEST.read_text()))
    def test_interrupted_update_uninstall_removes_old_owned_wrapper_and_never_resurrects(self):
        module.ROOT.mkdir();module.APP.parent.mkdir(parents=True)
        backup=module.APP.parent/'.ClaudeLauncher-backup-fixture.app';backup.mkdir();(backup/'old').write_text('old')
        wrapper=module.BIN/'claude-vscode-preflight';wrapper.write_text(str(module.TOOL)+' old')
        manifest={'installed':True,'mode':'preflight','vscodeIntegration':True,'appBackup':str(backup),
                  'scripts':{wrapper.name:'new-digest'},'pendingPreviousScripts':{wrapper.name:module.digest(wrapper)}}
        module.MANIFEST.write_text(json.dumps(manifest));module.VSCODE_SETTINGS.write_text(json.dumps({module.VSCODE_FIELD:str(wrapper)}))
        def move_to_test_trash(path):
            if path.exists():path.rename(path.with_name(path.name+'.trashed'))
        with patch('sys.argv',['install.py','uninstall']),patch.object(module,'stop_owned'),patch.object(module,'trash',side_effect=move_to_test_trash):
            module.main();module.main()
        self.assertFalse(wrapper.exists());self.assertFalse(module.APP.exists());self.assertFalse(backup.exists())
        result=json.loads(module.MANIFEST.read_text());self.assertNotIn('appBackup',result);self.assertNotIn('pendingPreviousScripts',result)
if __name__=='__main__':unittest.main()
