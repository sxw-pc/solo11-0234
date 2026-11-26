import tempfile
import unittest
from pathlib import Path

from cloudlab.store import connect, replay
from cloudlab import fiber_map, fiber_trace, fiber_splice, fiber_repair


INDEX = 1.4682
DRAWING = 'dwg-2026-11'


class FiberRepairTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / 'fiber.sqlite')
        self.db = connect(self.path)
        for branch, shaft in (('north', 'shaft-n'), ('south', 'shaft-s')):
            fiber_map.register(self.db, branch, 'p', 12, shaft,
                               refractive_index=INDEX, drawing_version=DRAWING)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def open_event(self, incident='inc-1', trace='forward', at=0):
        observed = fiber_trace.observe(
            self.db, trace, 'p', 12, 8,
            direction='forward', splitter_port='p',
            refractive_index=INDEX, drawing_version=DRAWING,
            calibration={'id': 'cal-1', 'meter': 'otdr-1', 'valid_until': 100},
            at=at,
        )
        self.assertEqual(observed['candidates'], ['north', 'south'])
        result = fiber_repair.open_incident(
            self.db, incident, trace_id=trace, circuit_id='uplink-1',
            customer_id='cust-1', at=at,
        )
        self.assertEqual(result['decision'], 'opened')
        self.assertEqual(result['candidates'], ['north', 'south'])
        self.assertFalse(result['located'])
        return result

    def identify_north(self, incident='inc-1', suffix='n', **overrides):
        trace_args = dict(
            direction='reverse', branch='north', splitter_port='p',
            refractive_index=INDEX, drawing_version=DRAWING,
            calibration_valid=True, at=5, independent=True, observer='far-otdr',
            loss=1,
        )
        trace_args.update(overrides.pop('trace', {}))
        fiber_trace.observe(self.db, f'rt-{suffix}', 'p', 12,
                            trace_args.pop('loss', 1), **trace_args)
        fiber_repair.record_loopback(
            self.db, f'lb-near-{suffix}', incident, 'north', 'near',
            passed=True, independent=True, observer='local-crew', at=5,
        )
        fiber_repair.record_loopback(
            self.db, f'lb-far-{suffix}', incident, 'north', 'far',
            passed=True, independent=True, observer='remote-dc', at=6,
        )
        return fiber_repair.identify_branch(
            self.db, incident, 'north',
            reverse_trace_id=f'rt-{suffix}',
            near_loopback_id=f'lb-near-{suffix}',
            far_loopback_id=f'lb-far-{suffix}',
            **overrides,
        )

    def permit_and_repair_north(self, incident='inc-1', suffix='n', at=10,
                                authorization='auth-a', permit='permit-n',
                                order='wo-n', replacement='rep-n',
                                new_core='core-n', extent=None):
        fiber_repair.issue_permit(
            self.db, permit, incident, 'north',
            authorization_id=authorization, at=7,
        )
        fiber_repair.assign_crew(
            self.db, order, incident, 'north', permit_id=permit,
            worker='alice', crew='crew-n', accepted=True, at=8,
            accept_deadline=9,
        )
        fiber_splice.submit(
            self.db, f'splice-{suffix}', 'north', 'alice',
            incident_id=incident, permit_id=permit, work_order_id=order, at=9,
        )
        return fiber_repair.repair_segment(
            self.db, replacement, incident, 'north',
            permit_id=permit, work_order_id=order,
            splice_id=f'splice-{suffix}', new_core_id=new_core,
            at=at, extent_km=extent,
        )

    def passing_post_tests_north(self, suffix='n', loss=1):
        fiber_trace.observe(
            self.db, f'fwd-post-{suffix}', 'p', 12, loss,
            direction='forward', branch='north', splitter_port='p',
            refractive_index=INDEX, drawing_version=DRAWING,
            calibration_valid=True, at=12,
        )
        fiber_trace.observe(
            self.db, f'rev-post-{suffix}', 'p', 12, loss,
            direction='reverse', branch='north', splitter_port='p',
            refractive_index=INDEX, drawing_version=DRAWING,
            calibration_valid=True, at=13, independent=True,
        )

    def accept_and_restore_north(self):
        self.open_event()
        fiber_repair.activate_backup(
            self.db, 'backup-1', 'inc-1', path_id='backup-uplink', at=4,
        )
        fiber_repair.authorize_route(
            self.db, 'auth-a', 'inc-1', owner='line-owner',
            route='targeted', valid_until=60,
        )
        located = self.identify_north()
        self.assertEqual(located['decision'], 'located', located)
        repaired = self.permit_and_repair_north()
        self.assertEqual(repaired['decision'], 'recorded', repaired)
        self.passing_post_tests_north()
        accepted = fiber_repair.accept_segment(
            self.db, 'acc-n', 'inc-1', 'north', max_loss=3, at=14,
        )
        self.assertEqual(accepted['decision'], 'accepted', accepted)
        fiber_repair.record_customer_reading(
            self.db, 'cr-n', 'inc-1', up=True, branch_id='north',
            core_id='core-n', loss=1, at=15,
            far_measurement_id='lb-far-n',
        )
        restored = fiber_repair.restore_uplink(
            self.db, 'rest-1', 'inc-1', customer_reading_id='cr-n',
            far_measurement_id='lb-far-n', at=20,
        )
        self.assertEqual(restored['decision'], 'restored', restored)
        return restored

    # ------------------------------------------------------------------
    # Seed invariants and trajectory identity
    # ------------------------------------------------------------------

    def test_forward_trace_retains_full_optical_trajectory(self):
        self.open_event()
        row = self.db.execute('SELECT * FROM fiber_traces WHERE id=?', ('forward',)).fetchone()
        self.assertEqual(row['splitter_port'], 'p')
        self.assertAlmostEqual(row['refractive_index'], INDEX)
        self.assertEqual(row['drawing_version'], DRAWING)
        self.assertEqual(row['direction'], 'forward')
        self.assertEqual(row['calibration_id'], 'cal-1')
        self.assertEqual(row['calibration_valid'], 1)

    def test_old_north_splice_does_not_locate_branch_or_become_acceptance(self):
        self.open_event()
        received = fiber_splice.submit(self.db, 'old-splice', 'north', 'bob', at=-2)
        self.assertEqual(received['decision'], 'received')
        self.assertFalse(received['accepted_as_verification'])

        ambiguous = fiber_repair.identify_branch(self.db, incident_id='inc-1')
        self.assertEqual(ambiguous['decision'], 'blocked')
        self.assertEqual(ambiguous['reason'], 'ambiguous_candidates')
        self.assertEqual(ambiguous['candidates'], ['north', 'south'])

        status = fiber_repair.status(self.db, 'inc-1')
        self.assertFalse(status['located'])
        self.assertEqual(status['candidates'], ['north', 'south'])

        # A retroactive "north fixed" claim without valid construction evidence
        # must not remove the optical candidate.
        claim = fiber_repair.run(self.db, {
            'op': 'claim_repaired', 'incident_id': 'inc-1',
            'branch': 'north', 'reported_by': 'clerk',
        })
        self.assertEqual(claim['decision'], 'blocked')
        self.assertEqual(fiber_repair.status(self.db, 'inc-1')['candidates'],
                         ['north', 'south'])

    # ------------------------------------------------------------------
    # Legal targeted route
    # ------------------------------------------------------------------

    def test_targeted_route_restores_exact_repaired_segment(self):
        restored = self.accept_and_restore_north()
        self.assertEqual(restored['served_branch'], 'north')
        self.assertEqual(restored['repaired_branches'], ['north'])
        self.assertEqual(restored['replacement_ids'], ['rep-n'])
        self.assertEqual(restored['far_measurement_id'], 'lb-far-n')
        self.assertEqual(restored['customer_recovery_minutes'], 4)
        self.assertEqual(restored['restoration_minutes'], 20)

        row = self.db.execute('SELECT * FROM fiber_restorations WHERE id=?',
                              ('rest-1',)).fetchone()
        self.assertEqual(row['served_branch_id'], 'north')
        self.assertEqual(row['far_measurement_id'], 'lb-far-n')
        self.assertEqual(self.db.execute(
            "SELECT state FROM fiber_incidents WHERE id='inc-1'").fetchone()[0],
            'restored')

    def test_targeted_authorization_forbids_permit_before_identification(self):
        self.open_event()
        fiber_repair.authorize_route(
            self.db, 'auth-a', 'inc-1', route='targeted', valid_until=60)
        result = fiber_repair.issue_permit(
            self.db, 'permit-n', 'inc-1', 'north', authorization_id='auth-a')
        self.assertEqual(result['decision'], 'blocked')
        self.assertEqual(result['reason'], 'branch_not_identified')

    def test_north_permit_cannot_be_lent_to_south_work_order(self):
        self.open_event()
        fiber_repair.authorize_route(
            self.db, 'auth-b', 'inc-1', route='both',
            branches=['north', 'south'], valid_until=60)
        fiber_repair.issue_permit(
            self.db, 'permit-n', 'inc-1', 'north', authorization_id='auth-b')
        wrong = fiber_repair.assign_crew(
            self.db, 'order-s', 'inc-1', 'south', permit_id='permit-n',
            worker='charlie', accepted=True, at=8)
        self.assertEqual(wrong['decision'], 'blocked')
        self.assertIn(wrong['reason'], {'permit_scope_mismatch', 'wrong_shaft'})

        same_id = fiber_repair.issue_permit(
            self.db, 'permit-n', 'inc-1', 'south', authorization_id='auth-b')
        self.assertEqual(same_id['decision'], 'blocked')
        self.assertEqual(same_id['reason'], 'permit_branch_mismatch')

    # ------------------------------------------------------------------
    # Route B and per-segment acceptance
    # ------------------------------------------------------------------

    def seed_both_repaired(self, south_far_loopback=True):
        self.open_event('inc-b', trace='forward-b')
        fiber_repair.authorize_route(
            self.db, 'auth-b', 'inc-b', owner='owner', route='both',
            branches=['north', 'south'], valid_until=100)
        for branch, shaft, worker, core in (
            ('north', 'shaft-n', 'crew-n', 'core-n'),
            ('south', 'shaft-s', 'crew-s', 'core-s'),
        ):
            suffix = branch[0]
            fiber_repair.issue_permit(
                self.db, f'pm-{suffix}', 'inc-b', branch,
                authorization_id='auth-b', shaft=shaft, at=10)
            fiber_repair.assign_crew(
                self.db, f'wo-{suffix}', 'inc-b', branch,
                permit_id=f'pm-{suffix}', worker=worker, accepted=True, at=11)
            fiber_repair.repair_segment(
                self.db, f'rep-{suffix}', 'inc-b', branch,
                permit_id=f'pm-{suffix}', work_order_id=f'wo-{suffix}',
                new_core_id=core, at=12)
            fiber_trace.observe(
                self.db, f'fwd-{suffix}', 'p', 12, 1, direction='forward',
                branch=branch, refractive_index=INDEX,
                drawing_version=DRAWING, calibration_valid=True, at=13)
            fiber_trace.observe(
                self.db, f'rev-{suffix}', 'p', 12, 1, direction='reverse',
                branch=branch, refractive_index=INDEX,
                drawing_version=DRAWING, calibration_valid=True, at=14)
            fiber_repair.record_loopback(
                self.db, f'near-{suffix}', 'inc-b', branch, 'near',
                passed=True, independent=True, observer='local')
            if branch != 'south' or south_far_loopback:
                fiber_repair.record_loopback(
                    self.db, f'far-{suffix}', 'inc-b', branch, 'far',
                    passed=True, independent=True, observer='remote')

    def test_route_b_does_not_infer_south_from_north_loopback(self):
        self.seed_both_repaired(south_far_loopback=False)
        north = fiber_repair.accept_segment(
            self.db, 'acc-bn', 'inc-b', 'north', max_loss=3)
        self.assertEqual(north['decision'], 'accepted', north)

        south_without_far = fiber_repair.run(self.db, {
            'op': 'accept_segment', 'acceptance_id': 'acc-bs-bad',
            'incident_id': 'inc-b', 'branch': 'south',
            'forward_trace_id': 'fwd-s', 'reverse_trace_id': 'rev-s',
            'near_loopback_id': 'near-s', 'max_loss': 3,
        })
        self.assertEqual(south_without_far['decision'], 'blocked')
        self.assertEqual(south_without_far['reason'], 'missing_far_loopback')

        self.assertEqual(fiber_repair.pending_acceptance(self.db, 'inc-b'),
                         ['south'])
        fiber_repair.record_customer_reading(
            self.db, 'cr-bn', 'inc-b', up=True, branch='north',
            core_id='core-n', far_measurement_id='far-n')
        incomplete = fiber_repair.restore_uplink(
            self.db, 'rest-bad', 'inc-b', customer_reading_id='cr-bn',
            far_measurement_id='far-n', require_all=True, at=30)
        self.assertEqual(incomplete['decision'], 'blocked')
        self.assertEqual(incomplete['reason'], 'acceptance_incomplete')
        self.assertEqual(incomplete['missing_branches'], ['south'])

        # A explicitly north-bound restoration may serve traffic on north, but
        # its conclusion must not contain south as restored.
        partial = fiber_repair.restore_uplink(
            self.db, 'rest-partial', 'inc-b', customer_reading_id='cr-bn',
            far_measurement_id='far-n', at=31)
        self.assertEqual(partial['decision'], 'restored', partial)
        self.assertEqual(partial['served_branch'], 'north')
        self.assertEqual(partial['repaired_branches'], ['north'])
        self.assertEqual(fiber_repair.pending_acceptance(self.db, 'inc-b'),
                         ['south'])

    def test_route_b_completes_after_independent_south_acceptance(self):
        self.seed_both_repaired()
        self.assertEqual(fiber_repair.accept_segment(
            self.db, 'acc-bn', 'inc-b', 'north', max_loss=3)['decision'], 'accepted')
        self.assertEqual(fiber_repair.accept_segment(
            self.db, 'acc-bs', 'inc-b', 'south', max_loss=3)['decision'], 'accepted')
        fiber_repair.record_customer_reading(
            self.db, 'cr-bs', 'inc-b', up=True, branch='south',
            core_id='core-s', far_measurement_id='far-s', loss=1)
        result = fiber_repair.restore_uplink(
            self.db, 'rest-b', 'inc-b', customer_reading_id='cr-bs',
            far_measurement_id='far-s', require_all=True, at=40)
        self.assertEqual(result['decision'], 'restored', result)
        self.assertEqual(result['served_branch'], 'south')
        self.assertEqual(result['repaired_branches'], ['north', 'south'])
        self.assertEqual(fiber_repair.pending_acceptance(self.db, 'inc-b'), [])

    # ------------------------------------------------------------------
    # Invalid evidence and authorization
    # ------------------------------------------------------------------

    def test_forged_far_loopback_cannot_identify_branch(self):
        self.open_event()
        fiber_trace.observe(
            self.db, 'rt-forged', 'p', 12, 1, direction='reverse',
            branch='north', refractive_index=INDEX,
            drawing_version=DRAWING, calibration_valid=True)
        fiber_repair.record_loopback(
            self.db, 'near-good', 'inc-1', 'north', 'near',
            passed=True, independent=True, observer='local')
        fiber_repair.record_loopback(
            self.db, 'far-forged', 'inc-1', 'north', 'far',
            passed=True, independent=True, forged=True)
        result = fiber_repair.identify_branch(
            self.db, 'inc-1', 'north', reverse_trace_id='rt-forged',
            near_loopback_id='near-good', far_loopback_id='far-forged')
        self.assertEqual(result['decision'], 'blocked')
        self.assertEqual(result['reason'], 'loopback_forged')
        row = self.db.execute('SELECT status,authentic FROM fiber_loopbacks WHERE id=?',
                              ('far-forged',)).fetchone()
        self.assertEqual(row['status'], 'forged')
        self.assertEqual(row['authentic'], 0)

    def test_refractive_index_port_and_calibration_conflicts_block(self):
        self.open_event()
        cases = [
            ('ri-bad', {'refractive_index': 1.5}, 'refractive_index_mismatch'),
            ('port-bad', {'port': 'q', 'splitter_port': 'q'}, 'splitter_port_mismatch'),
            ('cal-bad', {'calibration_valid': False}, 'meter_calibration_invalid'),
        ]
        for trace_id, changes, expected_reason in cases:
            args = dict(direction='reverse', branch='north', loss=1,
                        refractive_index=INDEX, drawing_version=DRAWING,
                        calibration_valid=True)
            args.update(changes)
            fiber_trace.observe(self.db, trace_id, args.pop('port', 'p'), 12,
                                args.pop('loss'), **args)
            result = fiber_repair._validate_trace(
                self.db, trace_id, {'id': 'inc-1', 'port': 'p'}, 'north',
                require_direction='reverse')
            self.assertIn(expected_reason, result[0], trace_id)

    def test_revoked_permit_blocks_future_construction_but_keeps_record(self):
        self.open_event()
        fiber_repair.authorize_route(
            self.db, 'auth-b', 'inc-1', route='both', valid_until=100)
        fiber_repair.issue_permit(
            self.db, 'pm-r', 'inc-1', 'north', authorization_id='auth-b', at=5)
        revoked = fiber_repair.revoke_permit(
            self.db, 'pm-r', reason='rainstorm', at=6)
        self.assertEqual(revoked['decision'], 'permit_revoked')
        blocked = fiber_repair.assign_crew(
            self.db, 'wo-r', 'inc-1', 'north', permit_id='pm-r',
            worker='alice', accepted=True, at=7)
        self.assertEqual(blocked['decision'], 'blocked')
        self.assertEqual(blocked['reason'], 'permit_revoked')
        row = self.db.execute('SELECT status,revoke_reason FROM fiber_permits WHERE id=?',
                              ('pm-r',)).fetchone()
        self.assertEqual(row['status'], 'revoked')
        self.assertEqual(row['revoke_reason'], 'rainstorm')

    def test_permit_and_crew_deadlines_are_enforced(self):
        self.open_event()
        fiber_repair.authorize_route(
            self.db, 'auth-d', 'inc-1', route='both', valid_until=10)
        fiber_repair.issue_permit(
            self.db, 'pm-d', 'inc-1', 'north', authorization_id='auth-d',
            valid_until=10, at=1)
        expired = fiber_repair.repair_segment(
            self.db, 'rep-d', 'inc-1', 'north', permit_id='pm-d', at=11)
        self.assertEqual(expired['decision'], 'blocked')
        self.assertEqual(expired['reason'], 'permit_expired')

        fiber_repair.assign_crew(
            self.db, 'wo-d', 'inc-1', 'north', permit_id='pm-d',
            worker='alice', accept_deadline=5, at=1)
        late = fiber_repair.accept_work_order(self.db, 'wo-d', worker='alice', at=6)
        self.assertEqual(late['decision'], 'blocked')
        self.assertEqual(late['reason'], 'acceptance_deadline_expired')

    def test_drawing_revision_invalidates_old_permit(self):
        self.open_event()
        fiber_repair.authorize_route(
            self.db, 'auth-draw', 'inc-1', route='both', valid_until=100)
        fiber_repair.issue_permit(
            self.db, 'pm-draw', 'inc-1', 'north', authorization_id='auth-draw')
        revised = fiber_map.revise_drawing(
            self.db, 'north', 'dwg-new', revision_id='rev-new', at=8)
        self.assertEqual(revised['decision'], 'drawing_revised')
        blocked = fiber_repair.repair_segment(
            self.db, 'rep-draw', 'inc-1', 'north', permit_id='pm-draw', at=9)
        self.assertEqual(blocked['decision'], 'blocked')
        self.assertEqual(blocked['reason'], 'drawing_version_mismatch')
        self.assertTrue(self.db.execute(
            "SELECT 1 FROM fiber_drawing_revisions WHERE id='rev-new'").fetchone())
        self.assertEqual(self.db.execute(
            "SELECT drawing_version FROM fiber_permits WHERE id='pm-draw'").fetchone()[0],
            DRAWING)

    def test_duplicate_and_conflicting_splice_receipts_keep_one_original(self):
        first = fiber_splice.submit(self.db, 'sp-1', 'north', 'alice')
        second = fiber_splice.submit(self.db, 'sp-1', 'north', 'alice', note='repeat')
        conflict = fiber_splice.submit(self.db, 'sp-1', 'south', 'mallory')
        self.assertEqual(first['decision'], 'received')
        self.assertEqual(second['decision'], 'replay')
        self.assertEqual(conflict['decision'], 'splice_conflict')
        self.assertEqual(self.db.execute(
            'SELECT COUNT(*) FROM fiber_splices WHERE id=?', ('sp-1',)).fetchone()[0], 1)

    def test_high_post_repair_loss_is_rejected_and_retry_keeps_old_record(self):
        self.open_event()
        fiber_repair.authorize_route(
            self.db, 'auth-h', 'inc-1', route='both', valid_until=60)
        self.identify_north()
        self.permit_and_repair_north(authorization='auth-h')
        self.passing_post_tests_north(loss=8)
        bad = fiber_repair.accept_segment(
            self.db, 'acc-high', 'inc-1', 'north', max_loss=3)
        self.assertEqual(bad['decision'], 'blocked')
        self.assertEqual(bad['reason'], 'loss_above_threshold')
        row = self.db.execute('SELECT result,reason FROM fiber_acceptances WHERE id=?',
                              ('acc-high',)).fetchone()
        self.assertEqual(row['result'], 'rejected')
        self.assertEqual(row['reason'], 'loss_above_threshold')

        self.passing_post_tests_north(suffix='ok', loss=1)
        good = fiber_repair.accept_segment(
            self.db, 'acc-ok', 'inc-1', 'north',
            forward_trace_id='fwd-post-ok', reverse_trace_id='rev-post-ok',
            max_loss=3)
        self.assertEqual(good['decision'], 'accepted', good)
        self.assertEqual(self.db.execute(
            'SELECT COUNT(*) FROM fiber_acceptances').fetchone()[0], 2)

    def test_half_segment_repair_leaves_acceptance_pending(self):
        self.open_event()
        fiber_repair.authorize_route(
            self.db, 'auth-half', 'inc-1', route='both', valid_until=60)
        repaired = self.permit_and_repair_north(
            authorization='auth-half', replacement='rep-half', extent=6)
        self.assertTrue(repaired['partial'])
        self.assertEqual(repaired['status'], 'partially_repaired')
        self.passing_post_tests_north(suffix='half')
        result = fiber_repair.accept_segment(
            self.db, 'acc-half', 'inc-1', 'north',
            forward_trace_id='fwd-post-half', reverse_trace_id='rev-post-half',
            max_loss=3)
        self.assertEqual(result['decision'], 'blocked')
        self.assertEqual(result['reason'], 'partial_segment_repair')
        pending = fiber_repair.pending_acceptance(self.db, 'inc-1')
        self.assertEqual(pending, ['north'])
        details = fiber_repair.acceptance_gaps(self.db, 'inc-1')
        self.assertEqual(details[0]['missing'], ['partial_segment_repair'])

    def test_customer_reading_must_bind_accepted_actual_core(self):
        self.accept_and_restore_north()
        fiber_repair.record_customer_reading(
            self.db, 'cr-unbound', 'inc-1', up=True, loss=1)
        unbound = fiber_repair.restore_uplink(
            self.db, 'rest-unbound', 'inc-1', customer_reading_id='cr-unbound',
            far_measurement_id='lb-far-n')
        self.assertEqual(unbound['decision'], 'blocked')
        self.assertEqual(unbound['reason'], 'customer_path_unbound')

        fiber_repair.record_customer_reading(
            self.db, 'cr-south', 'inc-1', up=True, branch='south', core_id='core-s')
        wrong = fiber_repair.restore_uplink(
            self.db, 'rest-wrong', 'inc-1', customer_reading_id='cr-south',
            far_measurement_id='far-s')
        self.assertEqual(wrong['decision'], 'blocked')
        self.assertIn(wrong['reason'],
                      {'accepted_segment_required', 'unknown_far_measurement'})

    def test_fiber_repair_decisions_replay_without_divergence(self):
        restored = self.accept_and_restore_north()
        self.assertEqual(restored['decision'], 'restored')
        result = replay(self.path, {'fiber_repair': fiber_repair})
        self.assertTrue(result['verified'], result['divergences'])


if __name__ == '__main__':
    unittest.main()
