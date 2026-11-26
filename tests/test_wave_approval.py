"""Acceptance tests for accountable risk approval -> effective budget -> wave.

These tests act out the "night R" facts from the operations contract:

* minute 18: Lin's proxy for seat B is revoked (receipt arrives late);
* minute 19: a signed equipment-maintenance revision lowers z1 to zero;
* minute 20: R asks 1 -> 2 on the stale base version;
* minute 21: independent seat C becomes valid;
* emergency route: a verified incident lets an authorized duty lead add ONE
  interruptible slot until minute 22, followed by customer review;
* formal route: re-baseline on the zero head and obtain signatures from
  controllers that are independent of each other.

Every implemented occupancy must be attributable to the group of real,
mutually-independent persons (or the emergency issuer) that authorized it.
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from cloudlab.store import connect
from cloudlab import inventory, wave, risk_request, risk_sign
from cloudlab import wave_approval as wa


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

def fresh_db():
    tmp = tempfile.TemporaryDirectory()
    db = connect(str(Path(tmp.name) / 'approval.sqlite'))
    return tmp, db


def seed_nodes(db, *names):
    for name in names:
        inventory.run(db, dict(op='node', id=name, architecture='amd64',
                               features=['cgroup2'], generation=1, observed_at=10,
                               version='1.29', zone='z1'))
        inventory.run(db, dict(op='verify', id=name, now=12, max_age=10,
                               architecture='amd64', features=['cgroup2'],
                               deprecated_api='old/v1'))


def seed_night(db, *, revoke_b_at=18, revoke_received_at=21):
    """Principals/seats/proxy + genesis(1) and minute-19 revision(0)."""
    wa.add_principal(db, 'lin', 'Lin', 'person', 'lin')
    wa.add_principal(db, 'b-corp', 'B Corporate Account', 'corporate', 'lin')
    wa.add_principal(db, 'cheng', 'C (customer representative)', 'person', 'cheng')
    wa.add_principal(db, 'shen', 'S (security lead)', 'person', 'shen')
    wa.add_principal(db, 'qin', 'Q (duty lead)', 'person', 'qin')

    wa.add_seat(db, 'A', holder_id='lin', role='security_lead',
                valid_from=0, valid_to=100, cap=2, zones=['z1'], device_key='kA')
    wa.add_seat(db, 'B', holder_id='b-corp', role='customer_rep',
                valid_from=0, valid_to=100, cap=2, zones=['z1'], device_key='kB')
    # C's tenure only starts at minute 21 ("can only confirm at 21").
    wa.add_seat(db, 'C', holder_id='cheng', role='customer_rep',
                valid_from=21, valid_to=100, cap=2, zones=['z1'], device_key='kC')
    wa.add_seat(db, 'S', holder_id='shen', role='security_lead',
                valid_from=0, valid_to=100, cap=2, zones=['z1'], device_key='kS')
    wa.add_seat(db, 'Q', holder_id='qin', role='duty_lead',
                valid_from=0, valid_to=100, cap=3, zones=['z1'], device_key='kQ')

    wa.add_proxy(db, 'dAB', grantor_seat='B', agent_id='lin', granted_at=15,
                 scope={'zones': ['z1']})
    if revoke_b_at is not None:
        wa.revoke_proxy(db, 'dAB', revoked_at=revoke_b_at,
                        received_at=revoke_received_at)

    wa.record_revision(db, 'bv1', service='svcR', zone='z1', quota=1, at=0,
                       kind='genesis')
    wa.record_revision(db, 'm19', service='svcR', zone='z1', quota=0, at=19,
                       kind='maintenance',
                       accountable=[{'seat': 'M19', 'decision': 'equipment'}])


def code(key, digest, seat, at):
    return wa.device_code(key, digest, seat, at)


class NightCase(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db = fresh_db()
        seed_night(self.db)
        seed_nodes(self.db, 'n1', 'n2')

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def propose_R(self, rid='R', base_version=1, old=1, new=2, at=20, **kw):
        return risk_request.propose(
            self.db, rid, 'w', 'lin', old, new, at,
            service='svcR', base_version=base_version, zone='z1',
            window=(20, 26), customers=['BenefitingCustomer'], **kw)

    def sign_AB(self, rid='R'):
        digest = self.db.execute(
            'SELECT digest FROM risk_requests WHERE id=?', (rid,)).fetchone()[0]
        a = risk_sign.sign(self.db, 'sA', rid, 'A', 20,
                           signature=code('kA', digest, 'A', 20))
        b = risk_sign.sign(self.db, 'sB', rid, 'B', 20,
                           signature=code('kB', digest, 'B', 20),
                           delegation_id='dAB', agent_id='lin')
        return digest, a, b


# ---------------------------------------------------------------------------
# 0. original seed contract stays exactly runnable
# ---------------------------------------------------------------------------

class OriginalSeedContract(unittest.TestCase):
    def test_missing_request_draft_signed_replay_single_row(self):
        tmp, db = fresh_db()
        try:
            # Exact historical decision contract (see test_approval_seed).
            self.assertEqual(risk_sign.sign(db, 's', 'r', 'A', 12)['decision'],
                             'missing_request')
            self.assertEqual(risk_request.propose(db, 'r', 'w', 'Lin', 1, 2, 10),
                             {'decision': 'draft'})
            self.assertEqual(risk_sign.sign(db, 's', 'r', 'A', 12)['decision'],
                             'signed')
            self.assertEqual(risk_sign.sign(db, 's', 'r', 'A', 12)['decision'],
                             'replay')
            self.assertEqual(db.execute(
                'SELECT count(*) FROM risk_signatures').fetchone()[0], 1)
        finally:
            db.close(); tmp.cleanup()

    def test_wave_quota_one_blocks_second_release_as_before(self):
        tmp, db = fresh_db()
        try:
            seed_nodes(db, 'n1', 'n2')
            wave.run(db, dict(op='plan', id='w', target='1.30',
                              max_unavailable=1, zone_budgets={'z1': 1}))
            self.assertEqual(wave.run(db, dict(
                op='release', id='w', transition='t1', node='n1', zone='z1')
            )['decision'], 'released')
            second = wave.run(db, dict(
                op='release', id='w', transition='t2', node='n2', zone='z1'))
            self.assertEqual(second['decision'], 'blocked')
            self.assertEqual(second['reason'], 'availability_budget')
        finally:
            db.close(); tmp.cleanup()


# ---------------------------------------------------------------------------
# 1. the request locks the original instrument; signatures pin its digest
# ---------------------------------------------------------------------------

class DocumentLocking(NightCase):
    def test_locked_fields_are_stored_and_digest_is_stable(self):
        r = self.propose_R()
        self.assertEqual(r['decision'], 'draft')
        self.assertRegex(r['digest'], r'^[0-9a-f]{64}$')
        row = dict(self.db.execute(
            'SELECT * FROM risk_requests WHERE id=?', ('R',)).fetchone())
        self.assertEqual(row['service'], 'svcR')
        self.assertEqual(row['base_version'], '1')
        self.assertEqual(row['zone'], 'z1')
        self.assertEqual((row['window_start'], row['window_end']), (20, 26))
        self.assertIn('BenefitingCustomer', row['customers'])
        self.assertEqual(row['digest'], r['digest'])
        # Canonical digest is deterministic.
        self.assertEqual(wa.request_digest(row), r['digest'])

    def test_changing_any_original_field_changes_digest(self):
        d1 = wa.document_digest({'request_id': 'R', 'zone': 'z1',
                                 'new_budget': 2, 'base_version': '1'})
        d2 = wa.document_digest({'request_id': 'R', 'zone': 'z2',
                                 'new_budget': 2, 'base_version': '1'})
        d3 = wa.document_digest({'request_id': 'R', 'zone': 'z1',
                                 'new_budget': 2, 'base_version': '2'})
        self.assertEqual(len({d1, d2, d3}), 3)

    def test_same_request_id_with_changed_content_is_conflict(self):
        self.propose_R()
        changed = risk_request.propose(
            self.db, 'R', 'w', 'lin', 1, 3, 20,
            service='svcR', base_version=1, zone='z1')
        self.assertEqual(changed['decision'], 'request_conflict')

    def test_signature_on_other_digest_is_rejected_and_not_stored(self):
        r = self.propose_R()
        out = risk_sign.sign(self.db, 'bad', 'R', 'A', 20, digest='0' * 64)
        self.assertEqual(out['decision'], 'digest_mismatch')
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM risk_signatures WHERE id='bad'").fetchone()[0], 0)

    def test_device_signature_is_verified_against_digest_seat_time(self):
        r = self.propose_R()
        out = risk_sign.sign(self.db, 'dev', 'R', 'A', 20, signature='forged')
        self.assertEqual(out['decision'], 'invalid_device_signature')
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM risk_signatures WHERE id='dev'").fetchone()[0], 0)
        good = risk_sign.sign(
            self.db, 'dev2', 'R', 'A', 20,
            signature=code('kA', r['digest'], 'A', 20))
        self.assertEqual(good['decision'], 'signed')
        self.assertTrue(good['qualified'])


# ---------------------------------------------------------------------------
# 2. real independence: controllers, proxies, tenure/cap/scope, duplicates
# ---------------------------------------------------------------------------

class Independence(NightCase):
    def test_A_and_revoked_proxy_B_collapse_to_lin(self):
        self.propose_R()
        _, a, b = self.sign_AB()
        self.assertTrue(a['qualified'])
        self.assertEqual(a['controller_id'], 'lin')
        # The external B signature is accepted and preserved ...
        self.assertEqual(b['decision'], 'signed')
        self.assertFalse(b['qualified'])
        self.assertIn('proxy_revoked', b['reasons'])
        self.assertEqual(b['controller_id'], 'lin')
        verdict = wa.approval_breakdown(self.db, 'R')
        self.assertEqual(verdict['independent_controllers'], ['lin'])
        self.assertFalse(verdict['sufficient'])

    def test_two_technical_accounts_same_controller_are_one(self):
        # A direct Lin seat plus a VALID proxy for B (same ultimate
        # controller) must still be a single independent responsible group.
        wa.add_proxy(self.db, 'dGood', grantor_seat='B', agent_id='lin',
                     granted_at=10, scope={'zones': ['z1']})
        self.propose_R('Rg')
        d = self.db.execute(
            "SELECT digest FROM risk_requests WHERE id='Rg'").fetchone()[0]
        risk_sign.sign(self.db, 'gA', 'Rg', 'A', 20,
                       signature=code('kA', d, 'A', 20))
        risk_sign.sign(self.db, 'gB', 'Rg', 'B', 20,
                       signature=code('kB', d, 'B', 20),
                       delegation_id='dGood', agent_id='lin')
        verdict = wa.approval_breakdown(self.db, 'Rg')
        self.assertEqual(verdict['independent_controllers'], ['lin'])
        self.assertEqual(verdict['controller_count'], 1)

    def test_late_revocation_receipt_uses_effective_revocation_time(self):
        self.propose_R('Rl')
        d = self.db.execute(
            "SELECT digest FROM risk_requests WHERE id='Rl'").fetchone()[0]
        wa.add_proxy(self.db, 'dLate', grantor_seat='B', agent_id='lin',
                     granted_at=15)
        # Signature arrives and is qualified BEFORE the revocation receipt.
        first = risk_sign.sign(
            self.db, 'lateB', 'Rl', 'B', 20,
            signature=code('kB', d, 'B', 20),
            delegation_id='dLate', agent_id='lin')
        self.assertTrue(first['qualified'])
        # Receipt arrives at minute 25, but revocation was effective at 18.
        rev = wa.revoke_proxy(self.db, 'dLate', revoked_at=18, received_at=25)
        self.assertEqual(rev['decision'], 'revoked')
        verdict = wa.approval_breakdown(self.db, 'Rl')
        rejected_ids = [r['signature_id'] for r in verdict['rejected']]
        self.assertIn('lateB', rejected_ids)
        self.assertIn('proxy_revoked',
                      next(r for r in verdict['rejected']
                           if r['signature_id'] == 'lateB')['reasons'])
        # The old external signature row survives untouched.
        row = self.db.execute(
            "SELECT * FROM risk_signatures WHERE id='lateB'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row['at'], 20)

    def test_layered_proxy_chain_collapses_to_root_grantor(self):
        wa.add_proxy(self.db, 'd1', grantor_seat='B', agent_id='mid',
                     granted_at=10)
        wa.add_proxy(self.db, 'd2', grantor_id='mid', agent_id='leaf',
                     parent_id='d1', granted_at=12)
        self.propose_R('Rp')
        d = self.db.execute(
            "SELECT digest FROM risk_requests WHERE id='Rp'").fetchone()[0]
        risk_sign.sign(self.db, 'pA', 'Rp', 'A', 20,
                       signature=code('kA', d, 'A', 20))
        layered = risk_sign.sign(
            self.db, 'pL', 'Rp', 'B', 20, delegation_id='d2', agent_id='leaf')
        self.assertTrue(layered['qualified'])
        self.assertEqual(layered['principal_id'], 'b-corp')
        self.assertEqual(layered['controller_id'], 'lin')
        verdict = wa.approval_breakdown(self.db, 'Rp')
        self.assertEqual(verdict['independent_controllers'], ['lin'])

    def test_seat_tenure_cap_and_zone_scope_are_checked(self):
        self.propose_R('Rt')
        d = self.db.execute(
            "SELECT digest FROM risk_requests WHERE id='Rt'").fetchone()[0]
        early = risk_sign.sign(self.db, 'c20', 'Rt', 'C', 20,
                               signature=code('kC', d, 'C', 20))
        self.assertFalse(early['qualified'])
        self.assertIn('seat_not_yet_valid', early['reasons'])

        wa.add_seat(self.db, 'TINY', holder_id='qin', role='security_lead',
                    valid_from=0, valid_to=100, cap=1, zones=['z1'])
        capped = risk_sign.sign(self.db, 'tiny', 'Rt', 'TINY', 20)
        self.assertFalse(capped['qualified'])
        self.assertIn('seat_cap_exceeded', capped['reasons'])

        wa.add_seat(self.db, 'OTHER', holder_id='qin', role='security_lead',
                    valid_from=0, valid_to=100, cap=5, zones=['other-zone'])
        scoped = risk_sign.sign(self.db, 'oz', 'Rt', 'OTHER', 20)
        self.assertFalse(scoped['qualified'])
        self.assertIn('seat_zone_denied', scoped['reasons'])

    def test_proxy_scope_is_enforced(self):
        wa.add_proxy(self.db, 'dScope', grantor_seat='B', agent_id='lin',
                     granted_at=10, scope={'zones': ['other-zone'],
                                           'max_increase': 0})
        self.propose_R('Rsc')
        d = self.db.execute(
            "SELECT digest FROM risk_requests WHERE id='Rsc'").fetchone()[0]
        out = risk_sign.sign(self.db, 'sc', 'Rsc', 'B', 20,
                             signature=code('kB', d, 'B', 20),
                             delegation_id='dScope', agent_id='lin')
        self.assertFalse(out['qualified'])
        self.assertIn('proxy_zone_denied', out['reasons'])

    def test_bare_sign_on_unknown_seat_keeps_transport_contract_but_not_authority(self):
        self.propose_R()
        out = risk_sign.sign(self.db, 'ghost', 'R', 'GHOST', 20)
        self.assertEqual(out['decision'], 'signed')
        self.assertFalse(out['qualified'])
        verdict = wa.approval_breakdown(self.db, 'R')
        self.assertEqual(verdict['qualified'], [])

    def test_duplicate_and_replayed_signatures_preserved_counted_once(self):
        self.propose_R('Rd')
        # identical resend -> replay, still one row
        risk_sign.sign(self.db, 'dup', 'Rd', 'A', 20)
        again = risk_sign.sign(self.db, 'dup', 'Rd', 'A', 20)
        self.assertEqual(again['decision'], 'replay')
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM risk_signatures WHERE id='dup'").fetchone()[0], 1)
        # same technical seat signs again with a new id: both external rows
        # survive but the controller group is counted once.
        risk_sign.sign(self.db, 'dup2', 'Rd', 'A', 21)
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM risk_signatures WHERE request_id='Rd'"
        ).fetchone()[0], 2)
        verdict = wa.approval_breakdown(self.db, 'Rd')
        self.assertEqual(verdict['independent_controllers'], ['lin'])
        # same signature id with changed facts is a conflict, not an overwrite
        conflict = risk_sign.sign(self.db, 'dup', 'Rd', 'A', 22)
        self.assertEqual(conflict['decision'], 'signature_conflict')

    def test_signature_ledger_is_append_only(self):
        self.propose_R('Ri')
        risk_sign.sign(self.db, 'imm', 'Ri', 'A', 20)
        with self.assertRaises(sqlite3.Error):
            self.db.execute(
                "UPDATE risk_signatures SET qualified=1 WHERE id='imm'")
        with self.assertRaises(sqlite3.Error):
            self.db.execute("DELETE FROM risk_signatures WHERE id='imm'")
        with self.assertRaises(sqlite3.Error):
            self.db.execute(
                "UPDATE approval_ledger SET qualified=1 WHERE kind='external_signature'")
        # the original row is still there
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM risk_signatures WHERE id='imm'").fetchone()[0], 1)


# ---------------------------------------------------------------------------
# 3. competing legal revision + optimistic version compare
# ---------------------------------------------------------------------------

class CompetingRevision(NightCase):
    def test_minute19_revision_is_current_zero_head(self):
        head = wa.head_revision(self.db, 'z1', 'svcR')
        self.assertEqual(head['version'], 2)
        self.assertEqual(head['quota'], 0)

    def test_two_revisions_cannot_commit_on_same_base(self):
        race = wa.record_revision(
            self.db, 'race', service='svcR', zone='z1', quota=2, at=20,
            base_version=1, kind='formal')
        self.assertEqual(race['decision'], 'blocked')
        self.assertEqual(race['reason'], 'stale_base_version')
        self.assertEqual(race['current_quota'] if 'current_quota' in race
                         else race['head_quota'], 0)

    def test_stale_R_is_signature_plausible_but_version_blocked(self):
        self.propose_R()
        d, _, _ = self.sign_AB()
        c = risk_sign.sign(self.db, 'sC', 'R', 'C', 21,
                           signature=code('kC', d, 'C', 21), received_at=21)
        self.assertTrue(c['qualified'])
        verdict = wa.approval_breakdown(self.db, 'R')
        # A(Lin) + C are two distinct controllers covering both roles ...
        self.assertTrue(verdict['sufficient'])
        self.assertEqual(set(verdict['independent_controllers']),
                         {'lin', 'cheng'})
        # ... yet R cannot skip the minute-19 zero-budget revision.
        out = wa.activate(self.db, 'R', at=21)
        self.assertEqual(out['decision'], 'blocked')
        self.assertEqual(out['reason'], 'stale_base_version')
        self.assertEqual(out['current_version'], 2)
        self.assertEqual(out['current_quota'], 0)
        self.assertEqual(self.db.execute(
            "SELECT status FROM risk_requests WHERE id='R'").fetchone()[0], 'draft')

    def test_rebased_request_with_C_and_S_activates_quota_two(self):
        r2 = self.propose_R('R2', base_version=2, old=0, new=2, at=22)
        d = r2['digest']
        risk_sign.sign(self.db, 'c2', 'R2', 'C', 22,
                       signature=code('kC', d, 'C', 22))
        # Offline-caught-up signature: signed at 22, ingested at 25.
        risk_sign.sign(self.db, 's2', 'R2', 'S', 22,
                       signature=code('kS', d, 'S', 22), received_at=25)
        out = wa.activate(self.db, 'R2', at=25)
        self.assertEqual(out['decision'], 'activated', out)
        self.assertEqual(out['version'], 3)
        self.assertEqual(out['quota'], 2)
        self.assertEqual(set(out['independent_controllers']),
                         {'cheng', 'shen'})
        rev = wa.head_revision(self.db, 'z1', 'svcR')
        self.assertEqual((rev['version'], rev['quota'], rev['kind']),
                         (3, 2, 'formal'))
        # activation is idempotent, it must not fork another version
        again = wa.activate(self.db, 'R2', at=26)
        self.assertEqual(again['decision'], 'activated')
        self.assertTrue(again.get('replay'))
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM budget_revisions WHERE kind='formal'"
        ).fetchone()[0], 1)


# ---------------------------------------------------------------------------
# 4. wave connection: one baseline slot, approval unlocks the second
# ---------------------------------------------------------------------------

class WaveConnection(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db = fresh_db()
        seed_nodes(self.db, 'n1', 'n2')

    def tearDown(self):
        self.db.close(); self.tmp.cleanup()

    def test_declared_two_without_approval_keeps_only_baseline_one(self):
        wave.run(self.db, dict(op='plan', id='w', target='1.30',
                               max_unavailable=2, zone_budgets={'z1': 2}))
        first = wave.run(self.db, dict(
            op='release', id='w', transition='t1', node='n1', zone='z1'))
        self.assertEqual(first['decision'], 'released')
        second = wave.run(self.db, dict(
            op='release', id='w', transition='t2', node='n2', zone='z1'))
        self.assertEqual(second['decision'], 'blocked')
        self.assertEqual(second['reason'], 'risk_approval_required')
        self.assertEqual(second['budget_gate'], 'availability_budget')

    def test_formal_approval_unlocks_second_and_attributes_each_occupancy(self):
        wave.run(self.db, dict(op='plan', id='w', target='1.30',
                               max_unavailable=2, zone_budgets={'z1': 2}))
        self.assertEqual(wave.run(self.db, dict(
            op='release', id='w', transition='t1', node='n1', zone='z1'
        ))['decision'], 'released')
        blocked = wave.run(self.db, dict(
            op='release', id='w', transition='t2', node='n2', zone='z1'))
        self.assertEqual(blocked['reason'], 'risk_approval_required')

        # Build the real independent approval on the one-node baseline.
        wa.add_principal(self.db, 'cheng', controller_id='cheng')
        wa.add_principal(self.db, 'shen', controller_id='shen')
        wa.add_seat(self.db, 'C', holder_id='cheng', role='customer_rep',
                    valid_from=0, valid_to=100, cap=2, zones=['z1'], device_key='kC')
        wa.add_seat(self.db, 'S', holder_id='shen', role='security_lead',
                    valid_from=0, valid_to=100, cap=2, zones=['z1'], device_key='kS')
        wa.record_revision(self.db, 'base1', service='svc', zone='z1',
                           quota=1, at=0, kind='genesis')
        req = risk_request.propose(
            self.db, 'R', 'w', 'sup', 1, 2, 20, service='svc',
            base_version=1, zone='z1', customers=['Cust'])
        d = req['digest']
        risk_sign.sign(self.db, 'c', 'R', 'C', 21,
                       signature=code('kC', d, 'C', 21))
        risk_sign.sign(self.db, 's', 'R', 'S', 21,
                       signature=code('kS', d, 'S', 21))
        activated = wa.activate(self.db, 'R', at=21)
        self.assertEqual(activated['decision'], 'activated')
        wa.bind_wave(self.db, 'w', request_id='R')

        # The previously blocked transition id can now proceed.
        retry = wave.run(self.db, dict(
            op='release', id='w', transition='t2', node='n2', zone='z1'))
        self.assertEqual(retry['decision'], 'released', retry)

        report = wa.accountability(self.db, wave_id='w')
        kinds = {o['transition_id']: o['slot_kind'] for o in report['occupancy']}
        self.assertEqual(kinds, {'t1': 'baseline', 't2': 'formal'})
        formal_occ = next(o for o in report['occupancy']
                          if o['transition_id'] == 't2')
        self.assertEqual(
            sorted(b['controller_id'] for b in formal_occ['accountable']),
            ['cheng', 'shen'])
        self.assertGreaterEqual(report['independent_controller_count'], 2)

    def test_plan_can_carry_approval_reference_directly(self):
        wa.add_principal(self.db, 'cheng', controller_id='cheng')
        wa.add_principal(self.db, 'shen', controller_id='shen')
        wa.add_seat(self.db, 'C', holder_id='cheng', role='customer_rep',
                    valid_from=0, valid_to=100, cap=2, zones=['z1'], device_key='kC')
        wa.add_seat(self.db, 'S', holder_id='shen', role='security_lead',
                    valid_from=0, valid_to=100, cap=2, zones=['z1'], device_key='kS')
        wa.record_revision(self.db, 'base1', zone='z1', quota=1, at=0,
                           kind='genesis')
        req = risk_request.propose(self.db, 'R', 'w2', 'sup', 1, 2, 20,
                                   base_version=1, zone='z1')
        d = req['digest']
        risk_sign.sign(self.db, 'c', 'R', 'C', 21,
                       signature=code('kC', d, 'C', 21))
        risk_sign.sign(self.db, 's', 'R', 'S', 21,
                       signature=code('kS', d, 'S', 21))
        wa.activate(self.db, 'R', at=21)
        planned = wave.run(self.db, dict(
            op='plan', id='w2', target='1.30', max_unavailable=2,
            zone_budgets={'z1': 2}, approval_id='R'))
        self.assertEqual(planned['decision'], 'planned')
        self.assertEqual(wave.run(self.db, dict(
            op='release', id='w2', transition='a', node='n1', zone='z1'
        ))['decision'], 'released')
        self.assertEqual(wave.run(self.db, dict(
            op='release', id='w2', transition='b', node='n2', zone='z1'
        ))['decision'], 'released')


# ---------------------------------------------------------------------------
# 5. emergency permit route (incident, +1, until 22, review, accountability)
# ---------------------------------------------------------------------------

class EmergencyRoute(NightCase):
    def issue(self, **over):
        args = dict(permit_id='E1', incident_id='INC1', issuer_seat='Q',
                    at=20, valid_until=22, zone='z1', service='svcR')
        args.update(over)
        return wa.issue_emergency(self.db, **args)

    def test_issuance_guards_incident_role_quota_and_window(self):
        self.assertEqual(self.issue(incident_id='MISSING')['reason'],
                         'unknown_incident')
        wa.add_incident(self.db, 'OPEN', zone='z1', state='open')
        self.assertEqual(self.issue(incident_id='OPEN')['reason'],
                         'incident_not_verified')
        wa.add_incident(self.db, 'INC1', zone='z1', verified_at=20)
        self.assertEqual(self.issue(issuer_seat='A')['reason'],
                         'not_authorized_duty_lead')
        self.assertEqual(self.issue(add=2)['reason'],
                         'emergency_limit_exceeded')
        self.assertEqual(self.issue(valid_until=20)['reason'],
                         'invalid_validity_window')
        ok = self.issue()
        self.assertEqual(ok['decision'], 'issued')
        self.assertEqual(ok['extra_quota'], 1)
        self.assertEqual(ok['controller_id'], 'qin')
        self.assertEqual(ok['valid_until'], 22)

    def test_one_emergency_slot_until_22_then_expiry_stops_new_occupancy(self):
        wa.add_incident(self.db, 'INC1', zone='z1', verified_at=20)
        self.issue()
        wave.run(self.db, dict(op='plan', id='wE', target='1.30',
                               max_unavailable=2, zone_budgets={'z1': 2}))
        wa.bind_wave(self.db, 'wE', permit_id='E1')

        first = wave.run(self.db, dict(
            op='release', id='wE', transition='e1', node='n1',
            zone='z1', now=21))
        self.assertEqual(first['decision'], 'released', first)
        # the single extra slot is numerically exhausted
        second = wave.run(self.db, dict(
            op='release', id='wE', transition='e2', node='n2',
            zone='z1', now=21))
        self.assertEqual(second['decision'], 'blocked')
        self.assertEqual(second['reason'], 'availability_budget')

        # after minute 22 the permit has expired: new occupancy stops ...
        late = wave.run(self.db, dict(
            op='release', id='wE', transition='e2', node='n2',
            zone='z1', now=23))
        self.assertEqual(late['decision'], 'blocked')
        self.assertEqual(late['reason'], 'emergency_permit_expired')

        # ... but the minute-21 escalation remains implemented and attributed
        self.assertEqual(self.db.execute(
            "SELECT state FROM transitions WHERE id='e1'").fetchone()[0],
            'applying')
        report = wa.accountability(self.db, wave_id='wE')
        occ = next(o for o in report['occupancy']
                   if o['transition_id'] == 'e1')
        self.assertEqual(occ['slot_kind'], 'emergency')
        self.assertEqual(occ['accountable'][0]['controller_id'], 'qin')
        permit_inst = next(i for i in report['instruments']
                           if i['kind'] == 'emergency_extension_max_one')
        self.assertEqual(permit_inst['real_issuer']['principal_id'], 'qin')
        self.assertEqual(permit_inst['valid_until'], 22)
        self.assertIn('qin', report['statement'])

    def test_failed_review_exposes_remedy_and_keeps_incurred_risk(self):
        wa.add_incident(self.db, 'INC1', zone='z1', verified_at=20)
        self.issue()
        wave.run(self.db, dict(op='plan', id='wE', target='1.30',
                               max_unavailable=2, zone_budgets={'z1': 2}))
        wave.run(self.db, dict(
            op='release', id='wE', transition='e1', node='n1',
            zone='z1', now=21))

        review = wa.review_emergency(
            self.db, 'E1', at=21, outcome='failed', reviewer_seat='C',
            note='customer could not verify change window')
        self.assertEqual(review['decision'], 'review_failed')
        self.assertTrue(review['remedy'])
        self.assertIn('blocked', review['remedy'])

        # failed review immediately ends NEW emergency occupancy ...
        after = wave.run(self.db, dict(
            op='release', id='wE', transition='e2', node='n2',
            zone='z1', now=22))
        self.assertEqual(after['decision'], 'blocked')
        self.assertEqual(after['reason'], 'emergency_review_failed')

        # ... while the old external facts and the implemented release persist
        self.assertIsNotNone(self.db.execute(
            "SELECT * FROM emergency_permits WHERE id='E1' AND review_state='failed'"
        ).fetchone())
        occ = self.db.execute(
            "SELECT accountable FROM release_attributions WHERE transition_id='e1'"
        ).fetchone()[0]
        self.assertIn('qin', occ)
        report = wa.accountability(self.db, zone='z1')
        inst = next(i for i in report['instruments'] if i['id'] == 'E1')
        self.assertEqual(inst['review_state'], 'failed')
        self.assertTrue(inst['remedy'])
        self.assertEqual(inst['historical_risk_bearer'], 'qin')

        # reviews are not overwritten by a later conflicting call
        again = wa.review_emergency(
            self.db, 'E1', at=24, outcome='confirmed', reviewer_seat='C')
        self.assertEqual(again['decision'], 'replay')
        self.assertEqual(self.db.execute(
            "SELECT review_state FROM emergency_permits WHERE id='E1'"
        ).fetchone()[0], 'failed')

    def test_confirmed_review_records_customer_acceptance(self):
        wa.add_incident(self.db, 'INC1', zone='z1', verified_at=20)
        self.issue()
        review = wa.review_emergency(
            self.db, 'E1', at=23, outcome='confirmed', reviewer_seat='C')
        self.assertEqual(review['decision'], 'review_confirmed')
        self.assertEqual(self.db.execute(
            "SELECT review_state FROM emergency_permits WHERE id='E1'"
        ).fetchone()[0], 'confirmed')


# ---------------------------------------------------------------------------
# 6. offline catch-up signing is judged at the original signing minute
# ---------------------------------------------------------------------------

class OfflineCatchUp(NightCase):
    def test_ingested_later_still_uses_signing_time_and_replays(self):
        r2 = self.propose_R('Ro', base_version=2, old=0, new=2, at=22)
        d = r2['digest']
        # C device signs offline at 22, bundle arrives at 28.
        out = risk_sign.sign(
            self.db, 'offC', 'Ro', 'C', 22,
            signature=code('kC', d, 'C', 22), received_at=28)
        self.assertTrue(out['qualified'])
        row = self.db.execute(
            "SELECT at,received_at FROM risk_signatures WHERE id='offC'"
        ).fetchone()
        self.assertEqual((row['at'], row['received_at']), (22, 28))
        replay = risk_sign.sign(
            self.db, 'offC', 'Ro', 'C', 22,
            signature=code('kC', d, 'C', 22), received_at=28)
        self.assertEqual(replay['decision'], 'replay')
        risk_sign.sign(self.db, 'offS', 'Ro', 'S', 22,
                       signature=code('kS', d, 'S', 22), received_at=28)
        activated = wa.activate(self.db, 'Ro', at=28)
        self.assertEqual(activated['decision'], 'activated', activated)
        self.assertEqual(set(activated['independent_controllers']),
                         {'cheng', 'shen'})


# ---------------------------------------------------------------------------
# 7. authorization references on the release call + event replay
# ---------------------------------------------------------------------------

class ReleaseReferenceAndReplay(NightCase):
    def activate_R2(self):
        r2 = self.propose_R('R2', base_version=2, old=0, new=2, at=22)
        d = r2['digest']
        risk_sign.sign(self.db, 'c2', 'R2', 'C', 22,
                       signature=code('kC', d, 'C', 22))
        risk_sign.sign(self.db, 's2', 'R2', 'S', 22,
                       signature=code('kS', d, 'S', 22))
        return wa.activate(self.db, 'R2', at=22)

    def test_release_payload_can_name_approval_without_prior_binding(self):
        out = self.activate_R2()
        self.assertEqual(out['decision'], 'activated')
        wave.run(self.db, dict(op='plan', id='w', target='1.30',
                               max_unavailable=2, zone_budgets={'z1': 2}))
        first = wave.run(self.db, dict(
            op='release', id='w', transition='a', node='n1', zone='z1',
            approval_id='R2'))
        second = wave.run(self.db, dict(
            op='release', id='w', transition='b', node='n2', zone='z1',
            approval_id='R2'))
        self.assertEqual(first['decision'], 'released', first)
        self.assertEqual(second['decision'], 'released', second)
        # no wave-level binding row was required
        self.assertIsNone(self.db.execute(
            "SELECT 1 FROM wave_authorizations WHERE wave_id='w'").fetchone())

    def test_successful_release_with_attribution_replays_cleanly(self):
        from cloudlab.store import replay
        from cloudlab import migration
        tmp, db = fresh_db()
        fn = str(Path(tmp.name) / 'approval.sqlite')
        try:
            seed_nodes(db, 'n1')
            wave.run(db, dict(op='plan', id='legacy', target='1.30',
                              max_unavailable=1))
            self.assertEqual(wave.run(db, dict(
                op='release', id='legacy', transition='t', node='n1', zone='z1')
            )['decision'], 'released')
            db.close()
            result = replay(fn, {'inventory': inventory, 'wave': wave,
                                 'migration': migration})
            self.assertTrue(result['verified'], result['divergences'])
        finally:
            db.close(); tmp.cleanup()


# ---------------------------------------------------------------------------
# 8. capstone: the two lawful routes from the identical night-R facts
# ---------------------------------------------------------------------------

class TwoLawfulRoutesCapstone(unittest.TestCase):
    def identical_world(self):
        tmp, db = fresh_db()
        seed_night(db)
        seed_nodes(db, 'n1', 'n2')
        # Common original application + the two captured signatures + C at 21.
        req = risk_request.propose(
            db, 'R', 'w', 'lin', 1, 2, 20, service='svcR', base_version=1,
            zone='z1', window=(20, 26), customers=['BenefitingCustomer'])
        d = req['digest']
        risk_sign.sign(db, 'sA', 'R', 'A', 20,
                       signature=code('kA', d, 'A', 20))
        risk_sign.sign(db, 'sB', 'R', 'B', 20,
                       signature=code('kB', d, 'B', 20),
                       delegation_id='dAB', agent_id='lin')
        risk_sign.sign(db, 'sC', 'R', 'C', 21,
                       signature=code('kC', d, 'C', 21), received_at=21)
        return tmp, db

    def test_same_facts_support_emergency_or_rebaselined_formal_route(self):
        # ---- shared verdict: R itself can never take effect --------------
        tmp0, common = self.identical_world()
        try:
            verdict = wa.approval_breakdown(common, 'R')
            self.assertEqual(set(verdict['independent_controllers']),
                             {'lin', 'cheng'})
            self.assertIn('proxy_revoked',
                           next(r for r in verdict['rejected']
                                if r['seat'] == 'B')['reasons'])
            blocked = wa.activate(common, 'R', at=21)
            self.assertEqual(blocked['reason'], 'stale_base_version')
        finally:
            common.close(); tmp0.cleanup()

        # ---- route 1: independent duty lead issues emergency until 22 -----
        tmp_e, edb = self.identical_world()
        try:
            wa.add_incident(edb, 'INC-CAPACITY', kind='capacity',
                            service='svcR', zone='z1', opened_at=20,
                            verified_at=20, verifier_seat='Q')
            permit = wa.issue_emergency(
                edb, 'E-R', incident_id='INC-CAPACITY', issuer_seat='Q',
                at=20, valid_until=22, extra_quota=1, zone='z1',
                service='svcR', reason='verified capacity incident')
            self.assertEqual(permit['decision'], 'issued')
            self.assertEqual(permit['controller_id'], 'qin')

            wave.run(edb, dict(op='plan', id='wE', target='1.30',
                               max_unavailable=2, zone_budgets={'z1': 2}))
            wa.bind_wave(edb, 'wE', permit_id='E-R')
            self.assertEqual(wave.run(edb, dict(
                op='release', id='wE', transition='m1', node='n1',
                zone='z1', now=21))['decision'], 'released')
            self.assertEqual(wave.run(edb, dict(
                op='release', id='wE', transition='m2', node='n2',
                zone='z1', now=21))['reason'], 'availability_budget')
            self.assertEqual(wave.run(edb, dict(
                op='release', id='wE', transition='m2', node='n2',
                zone='z1', now=23))['reason'], 'emergency_permit_expired')

            review = wa.review_emergency(
                edb, 'E-R', at=24, outcome='failed', reviewer_seat='C',
                note='customer rep rejects post-window change')
            self.assertEqual(review['decision'], 'review_failed')

            report = wa.accountability(edb, wave_id='wE')
            self.assertEqual(len(report['occupancy']), 1)
            self.assertEqual(report['occupancy'][0]['slot_kind'], 'emergency')
            self.assertEqual(
                report['occupancy'][0]['accountable'][0]['controller_id'], 'qin')
            emergency = next(i for i in report['instruments']
                             if i['id'] == 'E-R')
            self.assertEqual(emergency['review_state'], 'failed')
            self.assertTrue(emergency['remedy'])
        finally:
            edb.close(); tmp_e.cleanup()

        # ---- route 2: re-baseline on v2(0), C + S independent -------------
        tmp_f, fdb = self.identical_world()
        try:
            new_req = risk_request.propose(
                fdb, 'R-NEW', 'wF', 'lin', 0, 2, 22, service='svcR',
                base_version=2, zone='z1', window=(22, 30),
                customers=['BenefitingCustomer'])
            d = new_req['digest']
            risk_sign.sign(fdb, 'nC', 'R-NEW', 'C', 22,
                           signature=code('kC', d, 'C', 22))
            risk_sign.sign(fdb, 'nS', 'R-NEW', 'S', 22,
                           signature=code('kS', d, 'S', 22),
                           received_at=26)  # offline catch-up
            activated = wa.activate(fdb, 'R-NEW', at=26)
            self.assertEqual(activated['decision'], 'activated')
            self.assertEqual(set(activated['independent_controllers']),
                             {'cheng', 'shen'})

            wave.run(fdb, dict(op='plan', id='wF', target='1.30',
                               max_unavailable=2, zone_budgets={'z1': 2},
                               approval_id='R-NEW'))
            self.assertEqual(wave.run(fdb, dict(
                op='release', id='wF', transition='f1', node='n1',
                zone='z1', now=26))['decision'], 'released')
            self.assertEqual(wave.run(fdb, dict(
                op='release', id='wF', transition='f2', node='n2',
                zone='z1', now=26))['decision'], 'released')

            report = wa.accountability(fdb, wave_id='wF')
            self.assertEqual(
                {o['transition_id']: o['slot_kind']
                 for o in report['occupancy']},
                {'f1': 'formal', 'f2': 'formal'})
            bearers = {b['controller_id']
                       for o in report['occupancy']
                       for b in o['accountable']}
            self.assertEqual(bearers, {'cheng', 'shen'})
            self.assertEqual(report['independent_controller_count'], 2)
        finally:
            fdb.close(); tmp_f.cleanup()


# ---------------------------------------------------------------------------
# 8b. late revocation after reliance preserves the implemented escalation
# ---------------------------------------------------------------------------

class LateRevocationAfterEscalation(unittest.TestCase):
    def test_history_stands_but_fresh_verdict_corrects(self):
        tmp, db = fresh_db()
        try:
            seed_nodes(db, 'n1', 'n2')
            wa.add_principal(db, 'pat', 'Customer Pat', controller_id='pat')
            wa.add_principal(db, 'shen', 'Security Shen', controller_id='shen')
            wa.add_seat(db, 'CUST', holder_id='pat', role='customer_rep',
                        valid_from=0, valid_to=100, cap=2, zones=['z1'],
                        device_key='kP')
            wa.add_seat(db, 'SEC', holder_id='shen', role='security_lead',
                        valid_from=0, valid_to=100, cap=2, zones=['z1'],
                        device_key='kS')
            wa.add_proxy(db, 'dP', grantor_seat='CUST', agent_id='agentX',
                         granted_at=10, scope={'zones': ['z1']})
            wa.record_revision(db, 'bv1', zone='z1', quota=1, at=0,
                               kind='genesis')
            req = risk_request.propose(
                db, 'R', 'w', 'owner', 1, 2, 20, base_version=1, zone='z1')
            d = req['digest']
            p = risk_sign.sign(db, 'p', 'R', 'CUST', 20,
                               signature=code('kP', d, 'CUST', 20),
                               delegation_id='dP', agent_id='agentX')
            s = risk_sign.sign(db, 's', 'R', 'SEC', 20,
                               signature=code('kS', d, 'SEC', 20))
            self.assertTrue(p['qualified'])
            self.assertTrue(s['qualified'])
            self.assertEqual(wa.activate(db, 'R', at=20)['decision'], 'activated')

            wave.run(db, dict(op='plan', id='w', target='1.30',
                              max_unavailable=2, zone_budgets={'z1': 2},
                              approval_id='R'))
            self.assertEqual(wave.run(db, dict(
                op='release', id='w', transition='f1', node='n1', zone='z1'
            ))['decision'], 'released')
            self.assertEqual(wave.run(db, dict(
                op='release', id='w', transition='f2', node='n2', zone='z1'
            ))['decision'], 'released')

            # Revocation receipt arrives at 25 but is effective at 18,
            # i.e. before the proxied signature at 20.
            wa.revoke_proxy(db, 'dP', revoked_at=18, received_at=25)

            # The external signature, formal version and both releases stand.
            self.assertIsNotNone(db.execute(
                "SELECT 1 FROM risk_signatures WHERE id='p'").fetchone())
            self.assertEqual(db.execute(
                "SELECT quota FROM budget_revisions WHERE ref_id='R'"
            ).fetchone()[0], 2)
            self.assertEqual(db.execute(
                "SELECT count(*) FROM transitions WHERE wave_id='w'"
            ).fetchone()[0], 2)
            self.assertEqual(db.execute(
                "SELECT count(*) FROM release_attributions WHERE wave_id='w'"
            ).fetchone()[0], 2)

            # Fresh truth, however, no longer treats the proxy seat as one of
            # the currently-qualified independent approvers.
            verdict = wa.approval_breakdown(db, 'R')
            self.assertFalse(verdict['sufficient'])
            self.assertEqual(verdict['independent_controllers'], ['shen'])

            # The historical accountability snapshot still names the root
            # grantor that bore the authorization at implementation time.
            report = wa.accountability(db, wave_id='w')
            controllers = {b['controller_id']
                           for o in report['occupancy']
                           for b in o['accountable']}
            self.assertEqual(controllers, {'pat', 'shen'})
        finally:
            db.close(); tmp.cleanup()


# ---------------------------------------------------------------------------
# 9. dispatcher / facade surface stays usable in codebase style
# ---------------------------------------------------------------------------

class DispatcherSurface(unittest.TestCase):
    def test_run_dispatcher_and_service_facade(self):
        tmp, db = fresh_db()
        try:
            self.assertEqual(wa.run(db, {'op': 'principal', 'principal_id': 'p',
                                         'name': 'P'})['decision'], 'registered')
            self.assertEqual(wa.run(db, {'op': 'seat', 'seat_id': 'X',
                                         'holder_id': 'p', 'role': 'customer_rep',
                                         'valid_from': 0})['decision'], 'registered')
            doc = wa.run(db, {'op': 'digest', 'request_id': 'q', 'zone': 'z1'})
            self.assertIn('digest', doc)
            svc = wa.ApprovalService(db)
            req = svc.request(request_id='q', wave_id='w', applicant='p',
                              old_budget=1, new_budget=2, at=1, zone='z1')
            self.assertEqual(req['decision'], 'draft')
            signed = svc.sign(signature_id='g', request_id='q', seat='X', at=2)
            self.assertEqual(signed['decision'], 'signed')
            report = svc.accountability(zone='z1')
            self.assertIn('instruments', report)
        finally:
            db.close(); tmp.cleanup()


if __name__ == '__main__':
    unittest.main()
