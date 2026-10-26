#!/usr/bin/env python3
"""Real files + simulated PF mutations; never loads host firewall rules."""
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import pf_guard as g
import pf_policy as p

APPLE_SCRUB = 'scrub-anchor "com.apple/*" all fragment reassemble'
APPLE_FILTER = 'anchor "com.apple/*" all'
APPLE_ROOT = APPLE_SCRUB + '\n' + APPLE_FILTER


def policy():
    now = time.time()
    return {'version': 1, 'transport_exclusions': [], 'entries': [
        {'cidr': '160.79.104.10/32', 'source': 'test fixture', 'observed_at': now - 1, 'expires_at': now + 300},
        {'cidr': '2606:4700::1/128', 'source': 'test fixture', 'observed_at': now - 1, 'expires_at': now + 300}]}


class FakePF:
    def __init__(self, enabled=False):
        self.active = enabled
        self.root_rules = APPLE_ROOT
        self.own_rules = ''
        self.refs = 'No pf starter references held\n'
        self.mutations = []
        self.fail = None

    def enabled(self):
        return self.active

    def root(self):
        return self.root_rules

    def references(self):
        return self.refs

    def own(self, plan):
        return self.own_rules

    def syntax(self, source):
        return g.normalize(source)

    def load(self, source, name=None):
        self.mutations.append(('load', name, source))
        if name:
            self.own_rules = source
        else:
            self.root_rules = source
        if self.fail == 'load':
            self.fail = None
            raise g.GuardError('simulated_post_load_failure')

    def clear(self, plan):
        self.mutations.append(('clear', g.anchor(plan)))
        self.own_rules = ''

    def enable(self, store, plan):
        fd = store.create_receipt(plan['id'])
        with os.fdopen(fd, 'wb') as stream:
            if self.fail != 'missing_receipt':
                stream.write(b'pf enabled\nToken : 12345\n')
        self.active = True
        self.refs = 'PID      Process Name                 TOKEN                    TIMESTAMP\n44       pfctl                        12345                    0 days 00:00:01\n'
        self.mutations.append(('enable',))
        if self.fail in ('missing_receipt', 'after_enable'):
            raise g.GuardError('simulated_enable_failure')
        return '12345'

    def release(self, token):
        self.mutations.append(('release', token))
        self.refs = 'No pf starter references held\n'
        self.active = False

    def kill_states(self, cidr):
        self.mutations.append(('kill', cidr))
        if self.fail == 'kill':
            raise g.GuardError('simulated_kill_failure')


class PolicyTests(unittest.TestCase):
    def test_public_v4_v6_have_only_block_rules(self):
        result = p.validate(policy())
        self.assertEqual(len(result['cidrs']), 2)
        self.assertTrue(all(line.startswith('block drop out quick ') for line in result['rules'].splitlines()))

    def test_nonpublic_and_broad_ranges_rejected(self):
        for cidr in ('198.18.0.36/32', '127.0.0.1/32', '0.0.0.0/0', '10.0.0.0/24',
                     '224.1.1.1/32', '::1/128', 'ff00::1/128', '160.79.0.0/16', '2606::/16'):
            value = policy()
            value['entries'][0]['cidr'] = cidr
            with self.subTest(cidr=cidr), self.assertRaises(p.PolicyError):
                p.validate(value)

    def test_invalid_expiry_and_provenance(self):
        for field, value in [('expires_at', 0), ('observed_at', float('nan')), ('source', 'secret://value'),
                             ('observed_at', time.time() + 100)]:
            item = policy()
            item['entries'][0][field] = value
            with self.assertRaises(p.PolicyError):
                p.validate(item)

    def test_transport_exclusion_validation_and_overlap(self):
        for value in ('1.2.3.4', None, [1], ['not-ip'], ['160.79.104.10'], ['2606:4700::1']):
            item = policy()
            item['transport_exclusions'] = value
            with self.assertRaises(p.PolicyError):
                p.validate(item)

    def test_cname_ttl_and_unrelated_answers(self):
        body = {'Status': 0, 'TC': False, 'Question': [{'name': 'claude.ai.', 'type': 1}], 'Answer': [
            {'name': 'claude.ai.', 'type': 5, 'TTL': 20, 'data': 'target.example.'},
            {'name': 'target.example.', 'type': 1, 'TTL': 300, 'data': '160.79.104.10'},
            {'name': 'other.example.', 'type': 1, 'TTL': 300, 'data': '1.1.1.1'}]}
        result = p.parse_answer(body, 'claude.ai', 1, 100)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['expires_at'], 120)
        for field, value in [('Status', 3), ('TC', True), ('Question', [])]:
            invalid = copy.deepcopy(body)
            invalid[field] = value
            with self.assertRaises(p.PolicyError):
                p.parse_answer(invalid, 'claude.ai', 1, 100)

    def test_dns_family_and_loop_rejected(self):
        body = {'Status': 0, 'TC': False, 'Question': [{'name': 'claude.ai.', 'type': 1}],
                'Answer': [{'name': 'claude.ai.', 'type': 1, 'TTL': 300, 'data': '::1'}]}
        with self.assertRaises(p.PolicyError):
            p.parse_answer(body, 'claude.ai', 1, 100)
        body['Answer'][0].update(type=5, data='claude.ai.')
        with self.assertRaises(p.PolicyError):
            p.parse_answer(body, 'claude.ai', 1, 100)


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = g.Store(Path(self.temp.name))
        self.pf = FakePF()

    def stage(self):
        with self.store.lock():
            return g.stage(policy(), self.pf, self.store)

    def apply(self, plan):
        with self.store.lock():
            g.apply(plan, p.fingerprint(plan), self.pf, self.store)

    def restore(self, plan):
        with self.store.lock():
            g.recover(plan, self.pf, self.store)

    def test_stage_never_mutates_pf_and_preserves_apple_hook(self):
        plan = self.stage()
        self.assertEqual(self.pf.mutations, [])
        self.assertEqual(plan['root_after'].splitlines(),
                         [APPLE_SCRUB, f'anchor "{g.anchor(plan)}" quick all', APPLE_FILTER])
        self.assertIn('anchor "clguard_', plan['root_after'])
        self.assertEqual(self.store.read(plan['id'], 'plan'), plan)

    def test_filter_only_root_still_supported(self):
        self.pf.root_rules = APPLE_FILTER
        plan = self.stage()
        self.assertEqual(plan['root_after'].splitlines(),
                         [f'anchor "{g.anchor(plan)}" quick all', APPLE_FILTER])
        self.apply(plan)
        self.restore(plan)
        self.assertEqual(self.pf.root_rules, APPLE_FILTER)

    def test_scrub_must_be_exact_unique_and_first(self):
        for source in (APPLE_SCRUB + '\n' + APPLE_ROOT,
                       APPLE_FILTER + '\n' + APPLE_SCRUB,
                       APPLE_ROOT.replace('fragment reassemble', 'no-df'),
                       APPLE_ROOT.replace('scrub-anchor "com.apple/*"', 'scrub-anchor "foreign/*"')):
            self.pf.root_rules = source
            with self.subTest(source=source), self.assertRaises(g.GuardError):
                self.stage()
        self.assertEqual(self.pf.mutations, [])

    def test_reference_table_formats(self):
        self.assertEqual(g.reference_tokens('No pf starter references held\n'), set())
        self.assertEqual(g.reference_tokens('TOKENS:\nPID Process Name TOKEN TIMESTAMP\n4 pfctl 123 0 days 00:00:01\n'), {'123'})
        for text in ('', 'No pf_enabled references\n', 'Token : 123',
                     'No pf starter references held\nPID Process Name TOKEN TIMESTAMP',
                     'PID Process Name TOKEN TIMESTAMP\nunknown',
                     'PID Process Name TOKEN TIMESTAMP\n4 pfctl 123 0 days 00:00:01\n5 pfctl 123 0 days 00:00:02'):
            with self.assertRaises(g.GuardError):
                g.reference_tokens(text)

    def test_real_adapter_parses_successful_empty_reference_output(self):
        result = subprocess.CompletedProcess(['/sbin/pfctl', '-s', 'References'], 0,
                                             stdout='No pf starter references held\n',
                                             stderr='No ALTQ support in kernel\nALTQ related functions disabled\n')
        with patch('pf_lab.subprocess.run', return_value=result) as run:
            self.assertEqual(g.reference_tokens(g.PF().references()), set())
        self.assertEqual(run.call_args.args[0], ['/sbin/pfctl', '-s', 'References'])

    def test_real_adapter_parses_reference_table(self):
        output = 'PID      Process Name                 TOKEN                    TIMESTAMP\n44       pfctl                        12345                    0 days 00:00:01\n'
        result = subprocess.CompletedProcess([], 0, stdout=output, stderr='')
        with patch('pf_lab.subprocess.run', return_value=result):
            self.assertEqual(g.reference_tokens(g.PF().references()), {'12345'})

    def test_real_adapter_rejects_errx_and_unknown_output(self):
        for code, stdout, stderr in (
                (1, '', 'pfctl: No pf_enabled references\n'),
                (1, 'No pf starter references held\n', ''),
                (0, '', 'No pf starter references held\n'),
                (0, '', ''), (0, 'unknown format\n', '')):
            result = subprocess.CompletedProcess([], code, stdout=stdout, stderr=stderr)
            with self.subTest(code=code, stdout=stdout, stderr=stderr), \
                    patch('pf_lab.subprocess.run', return_value=result), \
                    self.assertRaises((g.GuardError, g.LabError)):
                g.reference_tokens(g.PF().references())

    def test_unknown_root_shape_refused_without_mutation(self):
        for source in ('pass all', 'anchor "nested" all {\n}', 'anchor "clguard_existing" all'):
            self.pf.root_rules = source
            with self.assertRaises(g.GuardError):
                self.stage()
        self.assertEqual(self.pf.mutations, [])

    def test_apply_and_restore_scoped_rules_and_own_reference(self):
        plan = self.stage()
        self.apply(plan)
        result = g.health(plan, self.pf, self.store)
        self.assertTrue(result['rules_present_and_fresh'])
        self.assertFalse(result['launch_authorized'])
        self.assertEqual([x[1] for x in self.pf.mutations if x[0] == 'kill'], p.validate(plan['policy'])['cidrs'])
        self.restore(plan)
        self.assertEqual(self.pf.root_rules, plan['root_before'])
        self.assertFalse(self.pf.active)
        self.assertFalse(self.pf.own_rules)
        count = len(self.pf.mutations)
        self.restore(plan)
        self.assertEqual(count, len(self.pf.mutations))

    def test_previously_enabled_pf_never_acquires_or_releases_reference(self):
        self.pf.active = True
        plan = self.stage()
        self.apply(plan)
        self.restore(plan)
        self.assertTrue(self.pf.active)
        self.assertFalse(any(x[0] in ('enable', 'release') for x in self.pf.mutations))

    def test_reference_age_changes_do_not_invalidate_plan(self):
        self.pf.active = True
        self.pf.refs = 'PID Process Name TOKEN TIMESTAMP\n4 other 99 0 days 00:00:01'
        plan = self.stage()
        self.pf.refs = 'PID Process Name TOKEN TIMESTAMP\n4 other 99 0 days 00:00:02'
        self.apply(plan)
        self.restore(plan)
        self.assertTrue(self.pf.active)

    def test_clock_rollback_does_not_block_independent_recovery(self):
        plan = self.stage()
        self.apply(plan)
        with patch('pf_guard.time.time', return_value=time.time() - 60):
            self.assertFalse(g.health(plan, self.pf, self.store)['rules_present_and_fresh'])
            self.restore(plan)
        self.assertFalse(self.pf.own_rules)

    def test_digest_expiry_or_baseline_change_prevents_mutation(self):
        plan = self.stage()
        with self.assertRaises(g.GuardError):
            g.apply(plan, 'bad-digest', self.pf, self.store)
        self.pf.root_rules += '\nanchor "foreign" all'
        with self.assertRaises(g.GuardError):
            self.apply(plan)
        self.assertEqual(self.pf.mutations, [])
        self.pf.root_rules = plan['root_before']
        with patch('pf_guard.time.time', return_value=time.time() + 301), self.assertRaises(p.PolicyError):
            self.apply(plan)

    def test_partial_load_failure_recovers_from_journal(self):
        plan = self.stage()
        self.pf.fail = 'load'
        with self.assertRaises(g.GuardError):
            self.apply(plan)
        self.assertEqual(self.pf.root_rules, plan['root_before'])
        self.assertFalse(self.pf.own_rules)
        self.assertEqual(self.store.read(plan['id'], 'state')['phase'], 'restored')

    def test_enable_receipt_recovers_after_error(self):
        plan = self.stage()
        self.pf.fail = 'after_enable'
        with self.assertRaises(g.GuardError):
            self.apply(plan)
        self.assertFalse(self.pf.active)
        self.assertIn(('release', '12345'), self.pf.mutations)

    def test_missing_enable_receipt_preserves_rules_and_does_not_guess(self):
        plan = self.stage()
        self.pf.fail = 'missing_receipt'
        with self.assertRaisesRegex(g.GuardError, 'ownership_unknown'):
            self.apply(plan)
        self.assertEqual(self.pf.root_rules, plan['root_after'])
        self.assertFalse(any(x[0] == 'release' for x in self.pf.mutations))

    def test_foreign_change_refuses_recovery(self):
        plan = self.stage()
        self.apply(plan)
        self.pf.root_rules += '\nanchor "foreign" all'
        count = len(self.pf.mutations)
        with self.assertRaisesRegex(g.GuardError, 'foreign_rule'):
            self.restore(plan)
        self.assertEqual(count, len(self.pf.mutations))

    def test_watch_repairs_empty_owned_anchor_only(self):
        plan = self.stage()
        self.apply(plan)
        self.pf.own_rules = ''
        result = g.watch_once(plan, self.pf, self.store)
        self.assertTrue(result['empty_owned_anchor_repaired'])
        self.assertTrue(self.pf.own_rules)
        self.pf.own_rules = 'pass all'
        count = len(self.pf.mutations)
        self.assertFalse(g.watch_once(plan, self.pf, self.store)['rules_present_and_fresh'])
        self.assertEqual(count, len(self.pf.mutations))
        self.pf.own_rules = ''
        self.pf.root_rules += '\nanchor "foreign" all'
        self.assertFalse(g.watch_once(plan, self.pf, self.store)['rules_present_and_fresh'])
        self.assertEqual(count, len(self.pf.mutations))

    def test_cli_status_readonly_and_watch_repairs(self):
        plan = self.stage()
        self.apply(plan)
        self.pf.own_rules = ''
        count = len(self.pf.mutations)
        actual_uid = os.geteuid()
        for mode in ('status', 'watch'):
            with patch('pf_guard.os.geteuid', side_effect=[0] + [actual_uid] * 100), \
                    patch('pf_guard.PF', return_value=self.pf), patch('pf_guard.Store', return_value=self.store), \
                    patch('pf_guard.time.sleep', side_effect=g.GuardError('test_stop')), redirect_stdout(io.StringIO()):
                self.assertEqual(g.main([mode, '--id', plan['id']]), 78)
            if mode == 'status':
                self.assertEqual(count, len(self.pf.mutations))
            else:
                self.assertEqual(self.pf.own_rules, plan['own_rules'])

    def test_watch_expired_policy_does_not_repair(self):
        plan = self.stage()
        self.apply(plan)
        self.pf.own_rules = ''
        count = len(self.pf.mutations)
        with patch('pf_guard.time.time', return_value=time.time() + 301):
            self.assertFalse(g.watch_once(plan, self.pf, self.store)['rules_present_and_fresh'])
        self.assertEqual(count, len(self.pf.mutations))

    def test_watch_rechecks_after_journal_write(self):
        plan = self.stage()
        self.apply(plan)
        self.pf.own_rules = ''
        count = len(self.pf.mutations)
        original = self.store.write

        def write(*args, **kwargs):
            original(*args, **kwargs)
            if args[1] == 'state' and args[2].get('phase') == 'repair_pending':
                self.pf.own_rules = 'pass all'

        with patch.object(self.store, 'write', side_effect=write), self.assertRaisesRegex(g.GuardError, 'before_repair'):
            g.watch_once(plan, self.pf, self.store)
        self.assertEqual(count, len(self.pf.mutations))

    def test_unknown_reference_format_does_not_claim_restored(self):
        plan = self.stage()
        self.apply(plan)
        self.pf.refs = 'unknown output'
        with self.assertRaisesRegex(g.GuardError, 'reference_table_unknown'):
            self.restore(plan)
        self.assertNotEqual(self.store.read(plan['id'], 'state')['phase'], 'restored')

    def test_expiry_and_missing_rules_report_unhealthy_but_do_not_unblock(self):
        plan = self.stage()
        self.apply(plan)
        with patch('pf_guard.time.time', return_value=time.time() + 301):
            result = g.health(plan, self.pf, self.store)
        self.assertFalse(result['rules_present_and_fresh'])
        self.assertFalse(result['checks']['evidence_fresh'])
        self.assertTrue(self.pf.own_rules)
        self.pf.active = False
        self.assertFalse(g.health(plan, self.pf, self.store)['rules_present_and_fresh'])

    def test_repeated_apply_never_adds_second_reference(self):
        plan = self.stage()
        self.apply(plan)
        count = len(self.pf.mutations)
        with self.assertRaises(g.GuardError):
            self.apply(plan)
        self.assertEqual(count, len(self.pf.mutations))

    def test_malicious_journal_files_rejected(self):
        plan = self.stage()
        for suffix in ('a' * 32, '../bad', '1' * 31):
            if suffix != 'a' * 32:
                with self.assertRaises(g.GuardError):
                    self.store.read(suffix, 'plan')
        path = self.store.path(plan['id'], 'state')
        os.mkfifo(path, 0o600)
        with self.assertRaises(g.GuardError):
            self.store.read(plan['id'], 'state')
        os.chmod(self.store.path(plan['id'], 'plan'), 0o644)
        with self.assertRaises(g.GuardError):
            self.store.read(plan['id'], 'plan')

    def test_nonroot_refuses_before_pf_or_store_access(self):
        with patch('pf_guard.os.geteuid', return_value=501), patch('pf_guard.PF') as pf, redirect_stdout(io.StringIO()):
            self.assertEqual(g.main(['status', '--id', 'a' * 32]), 78)
        pf.assert_not_called()


if __name__ == '__main__':
    unittest.main()
