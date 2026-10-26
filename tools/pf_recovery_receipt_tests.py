"""U2 protocol fixtures only: no real PF, accounts, network or observer writes."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pf_guard as guard
import pf_recovery_receipt as receipt


class ReceiptFixture:
    def setUp(self):
        self.binding = {'plan_id': '1'*32, 'plan_sha256': '2'*64,
                        'runtime_sha256': '3'*64, 'service_instance': '4'*32}
        self.request_id, self.generation = '5'*32, '6'*32
        self.received = receipt.submit(None, request_id=self.request_id, expected_revision=0,
                                       binding=self.binding, now=100)
        self.checking = receipt.begin(self.received, generation=self.generation, **self.identity(101))
        self.passed = receipt.finish(self.checking, **self.outcome(), **self.identity(103))

    def identity(self, now, **changes):
        return dict(request_id=self.request_id, receipt_revision=1, binding=self.binding, now=now, **changes)

    def outcome(self):
        return dict(generation=self.generation, status='passed', reason='checks_passed',
                    checks={key: True for key in receipt.CHECKS}, checked_at=102, evidence_expires_at=130)


class ReceiptTests(ReceiptFixture, unittest.TestCase):
    def test_received_is_not_passed_and_history_never_renews(self):
        for value in (self.received, self.checking):
            self.assertFalse(receipt.evidence_current(value, generation=self.generation, **self.identity(104)))
        self.assertTrue(receipt.evidence_current(self.passed, generation=self.generation, **self.identity(104)))
        self.assertFalse(receipt.evidence_current(self.passed, generation=self.generation, **self.identity(130)))
        self.assertEqual(self.passed['evidence_expires_at'], 130)
        self.assertEqual(self.received['status'], 'received')
        self.assertEqual(self.checking['status'], 'checking')

    def test_submit_retry_preserves_receipt_and_new_action_uses_new_revision(self):
        for value in (self.received, self.checking, self.passed):
            retry = receipt.submit(value, request_id=self.request_id, expected_revision=0,
                                   binding=self.binding, now=200)
            self.assertEqual(retry, value)
            self.assertIsNot(retry, value)
        newer = receipt.submit(self.passed, request_id='7'*32, expected_revision=1,
                               binding=self.binding, now=104)
        self.assertEqual(newer['revision'], 2)
        with self.assertRaisesRegex(receipt.ReceiptError, 'revision_conflict'):
            receipt.submit(newer, request_id=self.request_id, expected_revision=0,
                           binding=self.binding, now=105)

    def test_reusing_id_with_new_revision_is_a_new_action_not_a_retry(self):
        value = receipt.submit(self.passed, request_id=self.request_id, expected_revision=1,
                               binding=self.binding, now=104)
        self.assertEqual(value['revision'], 2)
        self.assertEqual(value['status'], 'received')
        self.assertEqual(value['received_at'], 104)

    def test_active_request_conflict_and_retry_binding_change_are_rejected(self):
        with self.assertRaisesRegex(receipt.ReceiptError, 'in_progress'):
            receipt.submit(self.checking, request_id='7'*32, expected_revision=1,
                           binding=self.binding, now=104)
        with self.assertRaisesRegex(receipt.ReceiptError, 'binding_mismatch'):
            receipt.submit(self.checking, request_id=self.request_id, expected_revision=0,
                           binding=dict(self.binding, runtime_sha256='8'*64), now=104)

    def test_fractional_request_timeout_remains_idempotent(self):
        first = receipt.submit(None, request_id=self.request_id, expected_revision=0,
                               binding=self.binding, now=1792230000.123, timeout=.1)
        self.assertEqual(receipt.submit(first, request_id=self.request_id, expected_revision=0,
                                       binding=self.binding, now=1792230001, timeout=.1), first)

    def test_success_requires_all_boolean_checks_and_current_evidence(self):
        bad_checks = [{}, dict(self.outcome()['checks'], extra=True)]
        for value in (False, 1, None, 'true'):
            bad_checks.append(dict(self.outcome()['checks'], installed=value))
        for checks in bad_checks:
            with self.subTest(checks=checks), self.assertRaises(receipt.ReceiptError):
                receipt.finish(self.checking, **dict(self.outcome(), checks=checks), **self.identity(103))
        for update in ({'checked_at': 100}, {'checked_at': 104}, {'evidence_expires_at': 103},
                       {'evidence_expires_at': 148}, {'evidence_expires_at': float('nan')},
                       {'checked_at': True}, {'evidence_expires_at': 10**1000}):
            with self.subTest(keys=list(update)), self.assertRaises(receipt.ReceiptError):
                receipt.finish(self.checking, **dict(self.outcome(), **update), **self.identity(103))

    def test_no_direct_pass_from_received_or_second_finish(self):
        with self.assertRaises(receipt.ReceiptError):
            receipt.finish(self.received, **dict(self.outcome(), generation=None), **self.identity(103))
        with self.assertRaises(receipt.ReceiptError):
            receipt.finish(self.passed, **self.outcome(), **self.identity(104))

    def test_old_request_revision_binding_generation_cannot_finish_new_work(self):
        for update in ({'request_id': '7'*32}, {'receipt_revision': 2}, {'receipt_revision': True},
                       {'binding': dict(self.binding, plan_id='8'*32)},
                       {'binding': dict(self.binding, plan_sha256='8'*64)},
                       {'binding': dict(self.binding, runtime_sha256='8'*64)},
                       {'binding': dict(self.binding, service_instance='8'*32)}):
            identity = dict(self.identity(103), **update)
            with self.subTest(keys=list(update)), self.assertRaises(receipt.ReceiptError):
                receipt.finish(self.checking, **self.outcome(), **identity)
        with self.assertRaises(receipt.ReceiptError):
            receipt.finish(self.checking, **dict(self.outcome(), generation='8'*32), **self.identity(103))

    def test_deadline_and_clock_reversal_preserve_existing_record(self):
        for now in (99, 190, float('inf'), float('nan'), True, 10**1000):
            with self.subTest(type=type(now).__name__), self.assertRaises(receipt.ReceiptError):
                receipt.begin(self.received, generation=self.generation, **self.identity(now))
        with self.assertRaises(receipt.ReceiptError):
            receipt.finish(self.checking, generation=self.generation, status='failed',
                           reason='request_expired', **self.identity(103))
        expired = receipt.finish(self.checking, generation=self.generation, status='failed',
                                 reason='request_expired', **self.identity(190))
        self.assertEqual(expired['status'], 'failed')
        self.assertEqual(self.checking['status'], 'checking')

    def test_restart_interrupts_active_work_but_never_rewrites_passed_history(self):
        for current in (self.received, self.checking):
            interrupted = receipt.interrupt_on_restart(current, new_service_instance='8'*32, now=104)
            self.assertEqual(interrupted['status'], 'interrupted')
            self.assertEqual(interrupted['service_instance'], self.binding['service_instance'])
            self.assertEqual(receipt.interrupt_on_restart(current,
                new_service_instance=self.binding['service_instance'], now=104), current)
        self.assertEqual(receipt.interrupt_on_restart(self.passed, new_service_instance='8'*32, now=104), self.passed)
        identity = dict(self.identity(104), binding=dict(self.binding, service_instance='8'*32))
        self.assertFalse(receipt.evidence_current(self.passed, generation=self.generation, **identity))

    def test_schema_rejects_private_unknown_or_malformed_fields(self):
        updates = [{'launch_authorized': True}, {'protection_verified': True}, {'secret': 'private-secret'},
                   {'reason': 'private-secret'}, {'reason': []}, {'status': []}, {'revision': True},
                   {'version': True}, {'generation': None}, {'started_at': None}, {'received_at': -1},
                   {'checked_at': float('inf')}, {'request_deadline': 1000}]
        for update in updates:
            with self.subTest(keys=list(update)), self.assertRaises(receipt.ReceiptError) as caught:
                receipt.validate(dict(self.passed, **update))
            self.assertNotIn('private-secret', str(caught.exception))
        changed = receipt.submit(self.passed, request_id='7'*32, expected_revision=1,
                                 binding=self.binding, now=104)
        changed['plan_id'] = '9'*32
        self.assertEqual(self.binding['plan_id'], '1'*32)


class ReceiptJournalTests(ReceiptFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store = guard.Store(Path(temporary.name)/'journal')
        self.plan_id = self.binding['plan_id']

    def test_real_journal_cas_catches_same_revision_transition(self):
        with self.store.lock():
            self.assertIsNone(receipt.load_locked(self.store, self.plan_id))
            receipt.commit_locked(self.store, self.plan_id, None, self.received)
            receipt.commit_locked(self.store, self.plan_id, self.received, self.checking)
            with self.assertRaisesRegex(receipt.ReceiptError, 'receipt_changed'):
                receipt.commit_locked(self.store, self.plan_id, self.received, self.passed)
            self.assertEqual(receipt.load_locked(self.store, self.plan_id), self.checking)
            receipt.commit_locked(self.store, self.plan_id, self.checking, self.passed)
            with patch.object(self.store, 'write') as write:
                receipt.commit_locked(self.store, self.plan_id, self.passed, self.passed)
                write.assert_not_called()
        self.assertEqual(self.store.path(self.plan_id, receipt.JOURNAL_KIND).stat().st_mode & 0o777, 0o600)

    def test_write_failure_before_and_after_replace_must_be_resolved_by_reread(self):
        with self.store.lock():
            with patch.object(self.store, 'write', side_effect=OSError('private-secret')):
                with self.assertRaisesRegex(receipt.ReceiptError, 'write_outcome_unknown') as caught:
                    receipt.commit_locked(self.store, self.plan_id, None, self.received)
                self.assertNotIn('private-secret', str(caught.exception))
            self.assertIsNone(receipt.load_locked(self.store, self.plan_id))
            real_write = self.store.write
            def write_then_fail(*args, **kwargs):
                real_write(*args, **kwargs)
                raise OSError('private-secret')
            with patch.object(self.store, 'write', side_effect=write_then_fail):
                with self.assertRaisesRegex(receipt.ReceiptError, 'write_outcome_unknown'):
                    receipt.commit_locked(self.store, self.plan_id, None, self.received)
            current = receipt.load_locked(self.store, self.plan_id)
            retry = receipt.submit(current, request_id=self.request_id, expected_revision=0,
                                   binding=self.binding, now=105)
            with patch.object(self.store, 'write') as write:
                receipt.commit_locked(self.store, self.plan_id, current, retry)
                write.assert_not_called()

    def test_invalid_json_and_insecure_files_are_preserved(self):
        with self.store.lock():
            receipt.commit_locked(self.store, self.plan_id, None, self.received)
            path = self.store.path(self.plan_id, receipt.JOURNAL_KIND)
            path.write_text('private-secret-not-json')
            with self.assertRaisesRegex(receipt.ReceiptError, 'journal_unreadable') as caught:
                receipt.load_locked(self.store, self.plan_id)
            self.assertNotIn('private-secret', str(caught.exception))
            self.assertEqual(path.read_text(), 'private-secret-not-json')
            path.write_text(json.dumps(self.received))
            path.chmod(0o644)
            with self.assertRaisesRegex(receipt.ReceiptError, 'journal_unreadable'):
                receipt.load_locked(self.store, self.plan_id)
            path.chmod(0o600)
            saved = path.with_suffix('.saved')
            path.rename(saved)
            path.symlink_to(saved)
            with self.assertRaisesRegex(receipt.ReceiptError, 'journal_unreadable'):
                receipt.load_locked(self.store, self.plan_id)
            self.assertTrue(path.is_symlink())

    def test_hard_link_and_wrong_plan_cannot_be_loaded(self):
        with self.store.lock():
            receipt.commit_locked(self.store, self.plan_id, None, self.received)
            path = self.store.path(self.plan_id, receipt.JOURNAL_KIND)
            os.link(path, path.with_suffix('.hardlink'))
            with self.assertRaisesRegex(receipt.ReceiptError, 'journal_unreadable'):
                receipt.load_locked(self.store, self.plan_id)
        with self.store.lock():
            other_id = '9'*32
            self.store.write(other_id, receipt.JOURNAL_KIND, self.received)
            with self.assertRaisesRegex(receipt.ReceiptError, 'plan_mismatch'):
                receipt.load_locked(self.store, other_id)


if __name__ == '__main__':
    unittest.main()
