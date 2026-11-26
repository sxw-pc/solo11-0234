import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cloudlab.store import connect, replay
from cloudlab import inventory, migration, wave, legal_request, evidence_delivery


OLD = {'replicas': 3, 'minAvailable': 2, 'selector': {'app': 'S'}}
GOOD = {
    'desiredReplicas': 3,
    'availability': {'minimumReady': 2},
    'selector': {'app': 'S'},
}
BAD = {
    'desiredReplicas': 2,
    'availability': {'minimumReady': 2},
    'selector': {'app': 'S'},
}


class LegalDisclosureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = str(Path(self.tmp.name) / 'legal.sqlite')
        self.db = connect(self.db_path)
        self.addCleanup(self.db.close)
        self.out = str(Path(self.tmp.name) / 'delivered')
        self.keys = {'test-court': 'court-secret'}

    def order(self, oid='o1', start=10, end=16, fields=None, **overrides):
        payload = {
            'order_id': oid,
            'issuer': 'test-court',
            'case_ref': 'CASE-2026-0234',
            'target_customer': '甲',
            'service': 'S',
            'window_start': start,
            'window_end': end,
            'allowed_fields': fields or ['*'],
            'issued_at': 9,
            'valid_from': 9,
            'valid_until': 100,
            'recipient': 'closed-evidence-room-7',
        }
        payload.update(overrides)
        return legal_request.sign_order(payload, 'court-secret', key_id='test-court')

    def receive(self, *args, **kwargs):
        payload = dict(args[0]) if args else {}
        payload.update(kwargs)
        payload.update({'op': 'receive_order', 'trusted_signers': self.keys})
        return legal_request.run(self.db, payload)

    def seed_platform(self, map_a=True):
        customers = [
            ('b', '乙', 'mb', 'tb', 'wb', 12),
            ('a', '甲', 'ma', 'ta', 'wa', 15),
            ('c', '丙', 'mc', 'tc', 'wc', 18),
        ]
        for short, name, mid, tid, wid, minute in customers:
            node = f'n-{short}'
            inventory.run(self.db, {
                'op': 'node', 'id': node, 'architecture': 'amd64',
                'features': ['cgroup2'], 'generation': 1,
                'observed_at': minute - 2, 'version': '1.29',
                'zone': f'zone-{short}-dc7',
            })
            inventory.run(self.db, {
                'op': 'verify', 'id': node, 'now': minute - 1, 'max_age': 10,
                'architecture': 'amd64', 'features': ['cgroup2'],
                'deprecated_api': 'old/v1',
            })

        # B and C have ordinary successful migrations.  Each customer has its
        # own workload config, while service is the shared S named in the order.
        for short, name, mid, tid, wid, minute in customers:
            if short == 'a':
                continue
            workload = f'wl-{short}'
            migration.run(self.db, {'op': 'config', 'workload': workload, 'version': f'cfg-{short}'})
            self.assertEqual('verified', migration.run(self.db, {
                'op': 'verify', 'id': mid, 'workload': workload, 'service': 'S',
                'at': minute, 'customer_id': name, 'node': f'n-{short}',
                'transition': tid, 'old_api': 'old/v1', 'new_api': 'new/v2',
                'old_manifest': OLD, 'new_manifest': GOOD,
            })['decision'])
            self.assertEqual('ready', migration.run(self.db, {
                'op': 'anchor', 'id': f'a-{mid}', 'migration': mid,
                'node': f'n-{short}', 'node_version': '1.29',
                'config_version': f'cfg-{short}', 'at': minute,
            })['decision'])
            wave.run(self.db, {'op': 'plan', 'id': wid, 'target': '1.30', 'max_unavailable': 1})
            self.assertEqual('released', wave.run(self.db, {
                'op': 'release', 'id': wid, 'transition': tid,
                'node': f'n-{short}', 'zone': f'zone-{short}-dc7',
                'now': minute, 'migration': mid, 'service': 'S',
            })['decision'])
            legal_request.run(self.db, dict({'op': 'maintenance_receipt'}, **{
                'receipt_id': f'r-{short}', 'provider': 'DC Maintenance Co',
                'ticket_id': f'T-{short}', 'migration_id': mid,
                'transition_id': tid, 'node_id': f'n-{short}', 'wave_id': wid,
                'service': 'S', 'at': minute + 1, 'outcome': 'maintenance-observed',
                'location': f'secret-dc7-cage-{short}',
            }))

        # A has a failed verification, a causally blocked wave release, a
        # retried verification, release, health completion and later rollback.
        migration.run(self.db, {'op': 'config', 'workload': 'wl-a', 'version': 'cfg-a'})
        wave.run(self.db, {'op': 'plan', 'id': 'wa', 'target': '1.30',
                           'max_unavailable': 1, 'at': 14})
        self.assertEqual('rejected', migration.run(self.db, {
            'op': 'verify', 'id': 'ma', 'workload': 'wl-a', 'service': 'S', 'at': 15,
            'node': 'n-a', 'transition': 'ta',
            'old_api': 'old/v1', 'new_api': 'new/v2',
            'old_manifest': OLD, 'new_manifest': BAD,
        })['decision'])
        blocked = wave.run(self.db, {
            'op': 'release', 'id': 'wa', 'transition': 'ta', 'node': 'n-a',
            'zone': 'zone-a-dc7', 'now': 15, 'migration': 'ma', 'service': 'S',
        })
        self.assertEqual('migration_failed', blocked['reason'])
        self.assertEqual('verified', migration.run(self.db, {
            'op': 'verify', 'id': 'ma', 'workload': 'wl-a', 'service': 'S', 'at': 15,
            'node': 'n-a', 'transition': 'ta',
            'old_api': 'old/v1', 'new_api': 'new/v2',
            'old_manifest': OLD, 'new_manifest': GOOD,
        })['decision'])
        self.assertEqual('ready', migration.run(self.db, {
            'op': 'anchor', 'id': 'a-ma', 'migration': 'ma', 'node': 'n-a',
            'node_version': '1.29', 'config_version': 'cfg-a', 'at': 15,
        })['decision'])
        self.assertEqual('released', wave.run(self.db, {
            'op': 'release', 'id': 'wa', 'transition': 'ta', 'node': 'n-a',
            'zone': 'zone-a-dc7', 'now': 15, 'migration': 'ma', 'service': 'S',
        })['decision'])
        wave.run(self.db, {
            'op': 'probe', 'id': 'wa', 'transition': 'ta', 'probe': 'pa',
            'generation': 1, 'target': '1.30', 'at': 16, 'healthy': True,
        })
        self.assertEqual('complete', wave.run(self.db, {
            'op': 'finish', 'id': 'wa', 'transition': 'ta', 'at': 16,
        })['decision'])
        self.assertEqual('rolled_back', migration.run(self.db, {
            'op': 'rollback', 'id': 'a-ma', 'at': 16,
        })['decision'])
        legal_request.run(self.db, {
            'op': 'maintenance_receipt',
            'receipt_id': 'r-a', 'provider': 'DC Maintenance Co', 'ticket_id': 'T-A',
            'migration_id': 'ma', 'transition_id': 'ta', 'node_id': 'n-a',
            'wave_id': 'wa', 'service': 'S', 'at': 16,
            'outcome': 'external-maintenance-complete',
            'location': 'secret-dc7-cage-a',
        })
        if map_a:
            legal_request.run(self.db, {
                'op': 'attribute_customer',
                'mapping_id': 'map-a', 'command_id': 'map-a',
                'customer_id': '甲', 'service': 'S',
                'subject_type': 'migration', 'subject_id': 'ma',
                'source': 'court_customer_ledger', 'at': 20,
            })

    def deliver_court(self, **overrides):
        payload = {'order_id': 'o1', 'command_id': 'court-o1', 'now': 21}
        payload.update(overrides)
        result = evidence_delivery.deliver_court(self.db, payload)
        self.assertNotIn('blocked', result.get('decision'), result)
        return evidence_delivery.fetch_artifact(self.db, result['artifact_id'])

    def test_instrument_validates_identity_scope_fields_time_and_signature(self):
        valid = self.order()
        result = self.receive(valid)
        self.assertEqual('accepted', result['decision'])
        self.assertEqual('active', result['status'])

        tampered = dict(valid)
        tampered['target_customer'] = '丁'
        with self.assertRaises(legal_request.LegalRequestError) as ctx:
            legal_request.receive_order(self.db, tampered, trusted_signers=self.keys)
        self.assertEqual('invalid_signature', ctx.exception.reason)
        blocked = self.receive(dict(tampered, command_id='tampered-run'))
        self.assertEqual('blocked', blocked['decision'])
        self.assertEqual('invalid_signature', blocked['reason'])

        expired = self.order('expired', start=1, end=2, valid_until=10)
        signed_expired = legal_request.sign_order(expired, 'court-secret', key_id='test-court')
        with self.assertRaises(legal_request.LegalRequestError) as ctx:
            legal_request.verify_order(signed_expired, now=11, trusted_signers=self.keys)
        self.assertEqual('order_expired', ctx.exception.reason)

        with self.assertRaises(legal_request.LegalRequestError) as ctx:
            legal_request.verify_order(
                self.order('untrusted'), now=20,
                trusted_signers={'other-court': 'x'},
            )
        self.assertEqual('untrusted_issuer', ctx.exception.reason)

        unsigned = self.order('unsigned')
        unsigned.pop('signature')
        with self.assertRaises(legal_request.LegalRequestError):
            legal_request.verify_order(unsigned, now=20, trusted_signers=self.keys)

    def test_court_room_receives_exact_a_chain_without_b_or_c(self):
        self.seed_platform()
        self.receive(self.order())
        packet = self.deliver_court(output_dir=self.out)
        verification = evidence_delivery.verify_artifact(self.db, packet['artifact_id'])
        self.assertTrue(verification['valid'], verification)
        standalone = evidence_delivery.verify_received_document(packet['bytes'])
        self.assertTrue(standalone['valid'], standalone)

        document = packet['document']
        text = packet['text']
        self.assertEqual('closed-evidence-room-7', packet['recipient'])
        self.assertIn('target_customer_exact', packet['query_rights'])
        self.assertTrue(document['completeness']['hash_chain_valid'])
        self.assertTrue(document['completeness']['selected_event_count'] >= 8)

        # Exact A facts and blocking/reversal causality are present.
        timed = [(e.get('at'), e.get('event'), e.get('decision'), e.get('reason'))
                 for e in document['timeline']]
        self.assertTrue(any(at == 15 and event in ('verify',) for at, event, _, _ in timed))
        self.assertTrue(any(reason == 'migration_failed' for _, _, _, reason in timed))
        self.assertTrue(any(decision == 'rejected' for _, _, decision, _ in timed))
        self.assertTrue(any(decision == 'rolled_back' for _, _, decision, _ in timed))
        self.assertIn('external-maintenance-complete', text)

        # B and C originals, customer names and sensitive location stay out.
        self.assertNotIn('乙', text)
        self.assertNotIn('丙', text)
        self.assertNotIn('mb', text)
        self.assertNotIn('mc', text)
        self.assertNotIn('n-b', text)
        self.assertNotIn('n-c', text)
        self.assertNotIn('secret-dc7-cage-b', text)
        self.assertNotIn('secret-dc7-cage-c', text)
        self.assertIn('甲', text)
        self.assertIn('ma', text)

        # Bytes were actually written for the recipient and verify unchanged.
        path = Path(packet['path'])
        self.assertTrue(path.exists())
        self.assertEqual(path.read_bytes(), packet['bytes'])

    def test_allowed_fields_filter_configs_and_location(self):
        self.seed_platform()
        restricted = self.order(
            'restricted', fields=['event', 'at', 'decision', 'reason',
                                  'migration_id', 'node_id', 'subsystem']
        )
        self.receive(restricted)
        packet = self.deliver_court(order_id='restricted', command_id='court-restricted')
        text = packet['text']
        self.assertNotIn('old_manifest', text)
        self.assertNotIn('new_manifest', text)
        self.assertNotIn('secret-dc7-cage-a', text)
        self.assertNotIn('DC Maintenance Co', text)
        self.assertNotIn('T-A', text)
        self.assertIn('migration_failed', text)

    def test_late_customer_mapping_is_append_only_and_then_completes_package(self):
        self.seed_platform(map_a=False)
        self.receive(self.order())
        order_row = self.db.execute("SELECT * FROM legal_orders WHERE order_id='o1'").fetchone()
        before = evidence_delivery.build_court_document(self.db, order_row)
        self.assertEqual([], before['timeline'])

        legal_request.attribute_customer(self.db, {
            'mapping_id': 'late-map-a', 'customer_id': '甲', 'service': 'S',
            'migration_id': 'ma', 'at': 20,
        })
        packet = self.deliver_court(command_id='court-late')
        ids = ' '.join(str(e.get('migration_id') or e.get('object_id') or '')
                       for e in packet['document']['timeline'])
        self.assertIn('ma', ids)
        self.assertIn('late-map-a', packet['text'])
        self.assertIn('late-map-a', packet['document']['completeness']['late_mappings'])

        conflict = legal_request.attribute_customer(self.db, {
            'mapping_id': 'forged-relabel', 'customer_id': '丁',
            'migration_id': 'ma',
        })
        self.assertEqual('blocked', conflict['decision'])
        self.assertEqual('customer_attribution_conflict', conflict['reason'])

    def test_overlapping_orders_produce_one_merged_public_total(self):
        self.seed_platform()
        self.receive(self.order('o1', 10, 16))
        self.receive(self.order('o2', 14, 20))

        risk = evidence_delivery.assess_difference_risk(
            self.db, 'S', [(10, 16), (14, 20)], 2
        )
        self.assertTrue(risk['difference_risk'])
        self.assertTrue(any(seg['group_size'] < 2 for seg in risk['segments']))

        result = evidence_delivery.run(self.db, {
            'op': 'public_bulletin', 'order_ids': ['o1', 'o2'],
            'command_id': 'public-merged', 'now': 21,
        })
        self.assertEqual('created', result['decision'], result)
        self.assertEqual((10, 20), (result['window_start'], result['window_end']))
        self.assertEqual(3, result['count'])

        public = evidence_delivery.fetch_artifact(self.db, result['artifact_id'])
        court = self.deliver_court(command_id='court-for-overlap')
        self.assertNotEqual(public['artifact_hash'], court['artifact_hash'])
        self.assertEqual('public', public['recipient'])
        self.assertIn('aggregate_totals_only', public['query_rights'])
        self.assertIn('no_narrow_time_window_query', public['query_rights'])
        self.assertTrue(evidence_delivery.verify_artifact(self.db, public['artifact_id'])['valid'])
        self.assertTrue(evidence_delivery.verify_received_document(public['bytes'])['valid'])

        doc = public['document']
        self.assertFalse(doc['customer_identities_included'])
        self.assertFalse(doc['time_values_included'])
        self.assertFalse(doc['node_or_location_included'])
        self.assertEqual(3, doc['totals']['migration_operations'])
        self.assertNotIn('乙', public['text'])
        self.assertNotIn('丙', public['text'])
        self.assertNotIn('甲', public['text'])
        self.assertNotIn('secret-dc7', public['text'])
        self.assertNotIn('known_scope_sources', public['text'])

        # No per-operation time/value fields survive in the public document.
        def walk_times(value):
            found = []
            if isinstance(value, dict):
                for k, v in value.items():
                    if k in ('at', 'minute', 'occurred_at', 'released_at'):
                        found.append(v)
                    found.extend(walk_times(v))
            elif isinstance(value, list):
                for item in value:
                    found.extend(walk_times(item))
            return found
        self.assertEqual([], [v for v in walk_times(doc) if v in (12, 15, 18)])

    def test_previously_published_scope_is_irrevocable_and_binds_next_window(self):
        self.seed_platform()
        self.receive(self.order('o1', 10, 16))
        first = evidence_delivery.deliver_public(self.db, {
            'service': 'S', 'start': 10, 'end': 16,
            'command_id': 'public-first', 'now': 21,
        })
        self.assertEqual((10, 16), (first['window_start'], first['window_end']))
        self.assertEqual(2, first['count'])

        self.receive(self.order('o2', 14, 20))
        second = evidence_delivery.deliver_public(self.db, {'order_id': 'o2', 'command_id': 'public-second'})
        self.assertEqual((10, 20), (second['window_start'], second['window_end']))
        self.assertEqual(3, second['count'])
        self.assertIsNotNone(second['incident'])

        self.receive(self.order('o3', 19, 24))
        third = evidence_delivery.deliver_public(self.db, {'order_id': 'o3', 'command_id': 'public-third'})
        self.assertEqual((10, 24), (third['window_start'], third['window_end']))

        scopes = self.db.execute(
            'SELECT window_start,window_end FROM publication_scopes ORDER BY rowid'
        ).fetchall()
        self.assertEqual([(10, 16), (10, 20), (10, 24)], [tuple(r) for r in scopes])
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("DELETE FROM publication_scopes WHERE command_id='public-first'")

        retry = evidence_delivery.deliver_public(self.db, {'order_id': 'o2', 'command_id': 'public-second'})
        self.assertEqual('reused', retry['decision'])
        self.assertEqual(second['artifact_hash'], retry['artifact_hash'])
        self.assertEqual(1, self.db.execute(
            "SELECT COUNT(*) FROM evidence_artifacts WHERE command_id='public-second'"
        ).fetchone()[0])

    def test_wrong_narrow_send_and_deleted_file_still_have_incident_and_bytes(self):
        self.seed_platform()
        wrong = evidence_delivery.deliver_public(self.db, {
            'service': 'S', 'start': 14, 'end': 20,
            'command_id': 'wrong-narrow', 'force_narrow': True,
            'output_dir': self.out, 'now': 21,
        })
        self.assertEqual((14, 20), (wrong['window_start'], wrong['window_end']))
        self.assertIsNotNone(wrong['incident'])
        path = Path(wrong['path'])
        self.assertTrue(path.exists())

        # Deleting the attachment cannot delete the delivered bytes or history.
        path.unlink()
        refetched = evidence_delivery.fetch_artifact(self.db, wrong['artifact_id'])
        self.assertTrue(refetched['bytes'])
        incident = self.db.execute(
            "SELECT kind FROM privacy_incidents WHERE incident_id='incident:narrow:wrong-narrow'"
        ).fetchone()
        self.assertEqual('narrow_window_wrongly_sent', incident['kind'])
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("DELETE FROM privacy_incidents WHERE incident_id=?",
                            ('incident:narrow:wrong-narrow',))

    def test_court_rejection_correction_supplement_and_idempotent_retry(self):
        self.seed_platform()
        self.receive(self.order())
        original = self.deliver_court(output_dir=self.out)
        evidence_delivery.run(self.db, {
            'op': 'reject', 'artifact_id': original['artifact_id'],
            'command_id': 'receipt-reject', 'received_by': 'judge-clerk',
            'reason': 'missing sealed cover sheet', 'at': 22,
        })
        rejected = evidence_delivery.fetch_artifact(self.db, original['artifact_id'])
        self.assertEqual('rejected', rejected['status'])
        self.assertEqual('missing sealed cover sheet', rejected['latest_receipt']['detail']['reason'])
        original_bytes = rejected['bytes']

        corrected = evidence_delivery.correct(self.db, {
            'artifact_id': original['artifact_id'],
            'command_id': 'court-correction-1', 'now': 23,
            'note': 'Add cover sheet', 'output_dir': self.out,
        })
        self.assertEqual('correction', corrected['revision_kind'])
        self.assertEqual(2, corrected['revision'])
        evidence_delivery.run(self.db, {
            'op': 'accept', 'artifact_id': corrected['artifact_id'],
            'command_id': 'receipt-accept-correction', 'received_by': 'judge-clerk', 'at': 24,
        })

        legal_request.record_maintenance_receipt(self.db, {
            'receipt_id': 'r-late', 'migration_id': 'ma', 'transition_id': 'ta',
            'at': 25, 'outcome': 'late carrier confirmation',
        })
        supplemented = evidence_delivery.supplement(self.db, {
            'artifact_id': corrected['artifact_id'],
            'command_id': 'court-supplement-1', 'now': 26,
            'note': 'Late carrier receipt',
        })
        self.assertEqual('supplement', supplemented['revision_kind'])
        self.assertEqual(3, supplemented['revision'])
        sup_packet = evidence_delivery.fetch_artifact(self.db, supplemented['artifact_id'])
        self.assertIn('r-late', sup_packet['text'])

        # Original rejected dossier bytes and receipt remain exactly served.
        again_original = evidence_delivery.fetch_artifact(self.db, original['artifact_id'])
        self.assertEqual(original_bytes, again_original['bytes'])
        self.assertEqual('rejected', again_original['status'])
        self.assertEqual(1, len(again_original['receipts']))

        retry = evidence_delivery.correct(self.db, {
            'artifact_id': original['artifact_id'],
            'command_id': 'court-correction-1', 'now': 23,
        })
        self.assertEqual('reused', retry['decision'])
        self.assertEqual(corrected['artifact_hash'], retry['artifact_hash'])
        self.assertEqual(3, self.db.execute(
            "SELECT COUNT(*) FROM evidence_artifacts WHERE order_id='o1'"
        ).fetchone()[0])

    def test_revoked_instrument_retains_old_package_but_blocks_new_delivery(self):
        self.seed_platform()
        self.receive(self.order())
        served = self.deliver_court(command_id='court-before-revocation')
        evidence_delivery.run(self.db, {
            'op': 'accept', 'artifact_id': served['artifact_id'],
            'command_id': 'receipt-old', 'at': 21,
        })
        revoked = legal_request.revoke_order(self.db, {
            'order_id': 'o1', 'revocation_id': 'revoke-o1',
            'issuer': 'test-court', 'at': 22, 'reason': 'case withdrawn',
        })
        self.assertEqual('revoked', revoked['decision'])

        blocked = evidence_delivery.deliver_court(self.db, {
            'order_id': 'o1', 'command_id': 'court-after-revoke',
        })
        self.assertEqual('blocked', blocked['decision'])
        self.assertEqual('order_revoked', blocked['reason'])
        old = evidence_delivery.fetch_artifact(self.db, served['artifact_id'])
        self.assertTrue(old['bytes'])
        self.assertEqual('accepted', old['latest_receipt']['status'])
        revocation = self.db.execute(
            "SELECT revocation_bytes FROM order_revocations WHERE revocation_id='revoke-o1'"
        ).fetchone()
        self.assertTrue(revocation['revocation_bytes'])

    def test_replay_reconstructs_legal_tables(self):
        self.seed_platform()
        self.receive(self.order('o1', 10, 16))
        self.receive(self.order('o2', 14, 20))
        court = self.deliver_court(command_id='court-replay')
        evidence_delivery.run(self.db, {
            'op': 'public_bulletin', 'order_ids': ['o1', 'o2'],
            'command_id': 'public-replay',
        })
        # Direct helper calls outside run() also leave replayable decisions.
        evidence_delivery.record_delivery_receipt(self.db, {
            'artifact_id': court['artifact_id'], 'command_id': 'direct-receipt',
            'status': 'accepted', 'received_by': 'clerk', 'at': 22,
        })
        legal_request.revoke_order(self.db, {
            'order_id': 'o1', 'revocation_id': 'rev-direct',
            'command_id': 'rev-direct', 'issuer': 'test-court', 'at': 30,
        })
        self.db.close()
        result = replay(self.db_path, {
            'inventory': inventory,
            'wave': wave,
            'migration': migration,
            'legal_request': legal_request,
            'evidence_delivery': evidence_delivery,
        })
        self.assertTrue(result['verified'], json.dumps(result['divergences'], ensure_ascii=False, default=str))


if __name__ == '__main__':
    unittest.main()
