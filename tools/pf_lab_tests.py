#!/usr/bin/env python3
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pf_lab as p


IDENTITY = 'a' * 32
PORTS = [51001, 51002, 51003, 51004]


class FakePF(p.PF):
    def __init__(self):
        self.calls = []
        self.active = ''
        self.hook = True
        self.enabled = True
        self.interfaces = 'lo0'
        self.children = ''
        self.load_error = False

    def call(self, *args, source=None):
        self.calls.append((args, source))
        if '-n' in args:
            return source
        if args == ('-s', 'info'):
            return 'Status: Enabled' if self.enabled else 'Status: Disabled'
        if args == ('-s', 'rules'):
            return 'anchor "claude-launcher-lab/*" all' if self.hook else 'anchor "com.apple/*" all'
        if args == ('-i', 'lo0', '-s', 'Interfaces', '-v'):
            return self.interfaces
        if args[-2:] == ('-s', 'Anchors'):
            return self.children
        if args[-2:] == ('-s', 'rules'):
            return self.active
        if '-R' in args:
            self.active = p.normalize(source)
            if self.load_error:
                raise p.LabError('simulated_partial_load')
            return ''
        if args[-2:] == ('-F', 'rules'):
            self.active = ''
            return ''
        raise AssertionError(args)


class MemoryStore:
    def __init__(self, pf):
        self.pf, self.saved = pf, False

    def save(self, intent):
        assert not any('-R' in args for args, _ in self.pf.calls)
        self.saved = True


class PFLabTests(unittest.TestCase):
    def intent(self, pf):
        return pf.compile(IDENTITY, 0, PORTS)

    def testGeneratedScopeIsOnlyReservedLoopbackEndpointsAndUID(self):
        text = p.rules(501, PORTS)
        self.assertEqual(len(text.splitlines()), 4)
        self.assertEqual(text.count('on lo0'), 4)
        self.assertEqual(text.count('user 501'), 4)
        self.assertIn('inet6 proto udp from any to ::1 port 51004', text)
        for ports in [PORTS[:3], [True, *PORTS[1:]], [80, *PORTS[1:]], ['1;inject', *PORTS[1:]]]:
            with self.assertRaises(p.LabError):
                p.rules(501, ports)
        with self.assertRaises(p.LabError):
            p.rules(True, PORTS)

    def testPrepareRunsRealEchoBaselineButOnlyDryRunPF(self):
        pf, report = FakePF(), {}
        self.assertTrue(p.experiment('prepare', pf, None, report))
        self.assertTrue(all(v for group in report['baseline'].values() for v in group))
        self.assertTrue(report['syntax_valid'])
        self.assertTrue(all('-n' in args for args, _ in pf.calls))
        self.assertNotIn('experiment_passed', report)

    def testPrerequisitesRefuseUnknownOrUnsafeGlobalState(self):
        for attribute, value in [('hook', False), ('enabled', False), ('interfaces', 'lo0 (skip)'),
                                 ('interfaces', 'unknown'), ('children', 'foreign'), ('active', 'foreign rule')]:
            pf = FakePF(); setattr(pf, attribute, value)
            with self.assertRaises(p.LabError):
                pf.prerequisites(IDENTITY)
            self.assertFalse(any('-F' in args or '-R' in args for args, _ in pf.calls))
        self.assertEqual(len(FakePF().prerequisites(IDENTITY)), 64)

    def testWriteAheadAndCleanupOnSuccessOrProbeFailure(self):
        for fail in [False, True]:
            pf = FakePF(); store = MemoryStore(pf); intent = self.intent(pf)
            try:
                with p.loaded_rules(intent, pf, store):
                    self.assertTrue(store.saved)
                    self.assertEqual(pf.active, intent['canonical'])
                    if fail:
                        raise p.LabError('probe_failure')
            except p.LabError as error:
                self.assertEqual(str(error), 'probe_failure')
            self.assertEqual(pf.active, '')
            self.assertIn((('-a', p.PREFIX + IDENTITY, '-F', 'rules'), None), pf.calls)

    def testPartialLoadFailureStillRestoresExactOwnedRules(self):
        pf = FakePF(); pf.load_error = True
        with self.assertRaisesRegex(p.LabError, 'simulated_partial_load'):
            with p.loaded_rules(self.intent(pf), pf, MemoryStore(pf)):
                self.fail('must not probe after load failure')
        self.assertEqual(pf.active, '')

    def testConflictBeforeLoadNeverClearsEvenMatchingRules(self):
        pf = FakePF(); intent = self.intent(pf); pf.active = intent['canonical']
        with self.assertRaisesRegex(p.LabError, 'anchor_changed_before_load'):
            with p.loaded_rules(intent, pf, MemoryStore(pf)):
                self.fail('must not load')
        self.assertEqual(pf.active, intent['canonical'])
        self.assertFalse(any('-F' in args for args, _ in pf.calls))

    def testForeignReplacementAfterLoadIsPreserved(self):
        pf = FakePF()
        with self.assertRaisesRegex(p.LabError, 'anchor_changed_recovery_refused'):
            with p.loaded_rules(self.intent(pf), pf, MemoryStore(pf)):
                pf.active = 'foreign rule'
        self.assertEqual(pf.active, 'foreign rule')
        self.assertFalse(any('-F' in args for args, _ in pf.calls))

    def testJournalRejectsTraversalSymlinksAndTampering(self):
        with tempfile.TemporaryDirectory() as folder:
            store = p.JournalStore(Path(folder)); pf = FakePF(); intent = self.intent(pf)
            with store.lock():
                store.save(intent)
                self.assertEqual(store.read(IDENTITY, pf), intent)
                with self.assertRaises(p.LabError):
                    store.read('../elsewhere', pf)
                target = Path(folder) / (IDENTITY + '.json')
                changed = dict(intent, ports=[52001, *PORTS[1:]])
                target.write_text(json.dumps(changed))
                with self.assertRaises(p.LabError):
                    store.read(IDENTITY, pf)
                other = 'b' * 32
                (Path(folder) / (other + '.json')).symlink_to(target)
                with self.assertRaises(OSError):
                    store.read(other, pf)

    def testNonrootLiveAndRestoreDoNotCallPFOrCreateJournal(self):
        for args in [['inspect'], ['live'], ['restore', '--run-id', IDENTITY]]:
            output = io.StringIO()
            with patch.object(p.os, 'geteuid', return_value=501), patch.object(p.PF, 'call') as call, \
                    patch.object(p.JournalStore, 'lock') as lock, contextlib.redirect_stdout(output):
                self.assertEqual(p.main(args), 78)
            call.assert_not_called(); lock.assert_not_called()
            report = json.loads(output.getvalue())
            self.assertEqual(report['reason'], 'administrator_required_no_changes')
            self.assertFalse(report['protection_verified'])

    def testSignalDuringExerciseRestoresRulesAndHandlers(self):
        pf = FakePF()
        before = p.signal.getsignal(p.signal.SIGTERM)
        with self.assertRaisesRegex(p.LabError, 'experiment_interrupted'):
            with p.interruptible(), p.loaded_rules(self.intent(pf), pf, MemoryStore(pf)):
                p.signal.getsignal(p.signal.SIGTERM)(p.signal.SIGTERM, None)
        self.assertEqual(pf.active, '')
        self.assertEqual(p.signal.getsignal(p.signal.SIGTERM), before)

    def testFIFOJournalDoesNotBlockRecovery(self):
        with tempfile.TemporaryDirectory() as folder:
            store = p.JournalStore(Path(folder))
            os.mkfifo(Path(folder) / (IDENTITY + '.json'), 0o600)
            with self.assertRaisesRegex(p.LabError, 'unsafe_journal_file'):
                store.read(IDENTITY, FakePF())

    def testRecoveryStatusSurvivesExperimentFailure(self):
        pf, report = FakePF(), {}
        with self.assertRaisesRegex(p.LabError, 'probe_failure'):
            with p.loaded_rules(self.intent(pf), pf, MemoryStore(pf), recovery=report):
                raise p.LabError('probe_failure')
        self.assertTrue(report['rules_restored'])

    def testInspectionUsesOnlyReadonlyCommandsAndRedactsRules(self):
        pf = FakePF(); pf.hook = False
        output = pf.inspect()
        self.assertTrue(output['pf_enabled'])
        self.assertFalse(output['dedicated_root_hook_present'])
        self.assertNotIn('com.apple', json.dumps(output))
        self.assertTrue(all('-s' in args and '-F' not in args and '-R' not in args for args, _ in pf.calls))


if __name__ == '__main__':
    unittest.main()
