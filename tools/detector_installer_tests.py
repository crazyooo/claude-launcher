#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('detector_installer', Path(__file__).with_name('install.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class DetectorInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.base = Path(self.temp.name).resolve()
        m.HOME = self.base/'home'; m.PROJECT = self.base/'project'
        m.ROOT = m.HOME/'Library/Application Support/ClaudeLauncher'
        m.MANIFEST = m.ROOT/'installation.json'
        m.APP = m.HOME/'Applications/Claude Launcher.app'
        m.BIN = m.HOME/'.local/bin'
        m.TOOL = m.APP/'Contents/MacOS/launcher-tool'
        m.SETTINGS = m.HOME/'.claude/settings.json'
        m.VSCODE_SETTINGS = m.HOME/'Library/Application Support/Code/User/settings.json'
        m.AGENT = m.HOME/'Library/LaunchAgents/local.crazymax.claude-launcher.plist'
        m.WRAPPER = m.BIN/'claude-process-wrapper'
        self.source = m.PROJECT/'dist/Claude Launcher.app'
        self.source.mkdir(parents=True); (self.source/'new').write_text('detector')
        self.commands = []

    def tearDown(self):self.temp.cleanup()

    def command(self, argv, **kwargs):
        self.commands.append(argv)
        self.assertEqual(argv[0],'/usr/bin/codesign','Only isolated signature checks may execute')
        return subprocess.CompletedProcess(argv,0,b'',b'')

    def install(self):
        with patch('sys.argv',['install.py','install']), patch.object(m.subprocess,'run',side_effect=self.command), \
                patch.object(m,'stop_monitor') as stop, patch.object(m,'stop_owned') as old_stop, \
                patch.object(m,'settings_change') as settings, patch.object(m,'vscode_change') as vscode:
            m.main()
            old_stop.assert_not_called(); settings.assert_not_called(); vscode.assert_not_called()
            return stop.call_count

    def test_default_install_is_detector_and_preserves_settings_without_wrappers(self):
        m.VSCODE_SETTINGS.parent.mkdir(parents=True)
        original = b'{// user JSONC\n"editor.fontSize":18}'
        m.VSCODE_SETTINGS.write_bytes(original)
        self.assertEqual(self.install(),0)
        manifest=json.loads(m.MANIFEST.read_bytes())
        self.assertEqual(manifest['mode'],'detector');self.assertEqual(manifest['scripts'],{})
        self.assertFalse(manifest['integration']);self.assertFalse(manifest['vscodeIntegration'])
        self.assertFalse(m.BIN.exists());self.assertFalse(m.AGENT.exists())
        self.assertEqual(m.VSCODE_SETTINGS.read_bytes(),original)
        self.assertEqual((m.APP/'new').read_text(),'detector')
        self.assertFalse(any('launchctl' in arg for command in self.commands for arg in command))

    def test_detector_upgrade_preserves_old_app_archive_and_can_repeat(self):
        self.install()
        (m.APP/'private-old-sentinel').write_text('preserve')
        self.assertEqual(self.install(),1)
        manifest=json.loads(m.MANIFEST.read_bytes())
        self.assertEqual(len(manifest['retiredApps']),1)
        archive=Path(manifest['retiredApps'][0])
        self.assertEqual((archive/'private-old-sentinel').read_text(),'preserve')
        self.assertFalse((m.APP/'private-old-sentinel').exists())

    def test_uninstall_then_reinstall_detector(self):
        self.install()
        def archive(path):
            if path.exists():path.rename(path.with_name(path.name+'.fixture-retired'))
        with patch('sys.argv', ['install.py','uninstall']), patch.object(m,'stop_owned'), patch.object(m,'trash',side_effect=archive):
            m.main()
        self.assertFalse(json.loads(m.MANIFEST.read_bytes())['installed'])
        self.install()
        self.assertTrue(json.loads(m.MANIFEST.read_bytes())['installed'])
        self.assertEqual(json.loads(m.MANIFEST.read_bytes())['mode'], 'detector')

    def test_legacy_uninstalled_manifest_reinstalls_after_dependency_check(self):
        m.ROOT.mkdir(parents=True,mode=0o700)
        m.atomic(m.MANIFEST,json.dumps({'installed':False,'mode':'preflight','integration':False,
            'vscodeIntegration':False,'scripts':{'claude-safe':'a'*64}}).encode())
        self.install()
        self.assertEqual(json.loads(m.MANIFEST.read_bytes())['mode'], 'detector')

    def test_legacy_integration_blocks_bundle_replacement(self):
        m.ROOT.mkdir(parents=True,mode=0o700);m.BIN.mkdir(parents=True)
        wrapper=m.BIN/'claude-vscode-preflight';wrapper.write_text('owned');wrapper.chmod(0o700)
        m.atomic(m.MANIFEST,json.dumps({'installed':True,'mode':'preflight','vscodeIntegration':True,
            'scripts':{wrapper.name:m.digest(wrapper)}}).encode())
        m.VSCODE_SETTINGS.parent.mkdir(parents=True)
        m.VSCODE_SETTINGS.write_text(json.dumps({m.VSCODE_FIELD:str(wrapper)}))
        m.APP.mkdir(parents=True);(m.APP/'keep').write_text('old')
        with patch.object(m,'stage_app') as stage:
            with self.assertRaisesRegex(RuntimeError,'legacy_user_retirement_required'):self.install()
            stage.assert_not_called()
        self.assertEqual((m.APP/'keep').read_text(),'old');self.assertTrue(wrapper.exists())

    def test_foreign_app_is_never_replaced(self):
        m.APP.mkdir(parents=True);(m.APP/'keep').write_text('foreign')
        with self.assertRaisesRegex(RuntimeError,'destination_app_not_owned'):self.install()
        self.assertEqual((m.APP/'keep').read_text(),'foreign')

    def test_interrupted_replacement_rolls_back_and_retry_remains_detector(self):
        self.install();(m.APP/'keep').write_text('old')
        original=m.os.replace
        def fail(src,dst):
            if Path(src).name.startswith('.ClaudeLauncher-stage-') and Path(dst)==m.APP:
                raise OSError('fixture interrupted')
            return original(src,dst)
        with patch.object(m.os,'replace',side_effect=fail):
            with self.assertRaises(OSError):self.install()
        self.assertEqual((m.APP/'keep').read_text(),'old')
        self.install()
        self.assertEqual(json.loads(m.MANIFEST.read_bytes())['mode'],'detector')
        self.assertFalse(m.BIN.exists())


if __name__=='__main__':unittest.main()
