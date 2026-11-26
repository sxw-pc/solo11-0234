import sqlite3
import tempfile
import unittest
from pathlib import Path

from cloudlab.store import connect, replay
from cloudlab import inventory, wave, incident_scope, notice_delivery


class IncidentNoticeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / 'incident.sqlite')
        self.db = connect(self.path)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def seed_wave(self):
        inventory.run(self.db, {
            'op': 'node', 'id': 'n1', 'architecture': 'amd64', 'features': ['cgroup2'],
            'generation': 1, 'observed_at': 10, 'version': '1.29', 'zone': 'z',
        })
        inventory.run(self.db, {
            'op': 'verify', 'id': 'n1', 'now': 11, 'max_age': 10,
            'architecture': 'amd64', 'features': ['cgroup2'], 'deprecated_api': 'old/v1',
        })
        wave.run(self.db, {'op': 'plan', 'id': 'W', 'target': '1.30', 'max_unavailable': 1})
        wave.run(self.db, {'op': 'release', 'id': 'W', 'transition': 't1', 'node': 'n1', 'zone': 'z'})
        wave.run(self.db, {
            'op': 'probe', 'id': 'W', 'transition': 't1', 'probe': 'p1',
            'generation': 1, 'target': '1.30', 'at': 12, 'healthy': True,
        })
        finished = wave.run(self.db, {'op': 'finish', 'id': 'W', 'transition': 't1', 'at': 12})
        self.assertEqual(finished['decision'], 'complete', finished)
        return finished

    def open_fixed_incident(self, clients=('甲', '乙', '丙', '丁')):
        result = incident_scope.run(self.db, {
            'op': 'open', 'id': 'INC', 'fault_version': '1.30', 'wave_id': 'W',
            'node_id': 'n1', 'node_generation': 1,
            'evidence_at': 14, 'deadline_at': 19,
            'security_officer': 'officer-zhao', 'authorizer': 'legal-sun',
            'contract_owner': 'contract-qian',
            'approved_modes': ['escrow_precise', 'advisory_first'],
            'subscribers': list(clients),
        })
        self.assertEqual(result['decision'], 'opened', result)
        certificate = incident_scope.run(self.db, {
            'op': 'certificate', 'id': 'INC', 'artifact_id': 'gateway-cert-13',
            'name': 'trusted-gateway.pem', 'at': 13,
            'pem': b'-----BEGIN CERTIFICATE-----\nfixed-artifact\n-----END CERTIFICATE-----\n',
        })
        self.assertEqual(certificate['decision'], 'recorded', certificate)
        return result

    def record_leaking_response(self, token='token-real-yi', true_client='乙'):
        incident_scope.run(self.db, {
            'op': 'request', 'id': 'INC', 'request_id': 'req-13', 'at': 13,
            'client_hint': 'shared-proxy-session',
        })
        for attempt in (1, 2, 3):
            forwarded = incident_scope.run(self.db, {
                'op': 'forward', 'id': 'INC', 'request_id': 'req-13',
                'proxy_id': 'Q', 'nat_address': 'nat-Q-7', 'trace_id': 'trace-13',
                'attempt': attempt, 'at': 13, 'origin_region': 'cross-region-origin',
            })
            self.assertEqual(forwarded['decision'], 'recorded', forwarded)

        response_payload = {
            'op': 'response', 'id': 'INC', 'trace_id': 'trace-13',
            'request_id': 'req-13', 'proxy_id': 'Q', 'nat_address': 'nat-Q-7',
            'at': 13, 'candidate_clients': ['甲', '乙'], 'page_hint': '甲',
            'foreign_tenant_leak': True, 'egress_count': 1,
            'diagnostic_fields': ['other_tenant.diagnostic_id'],
            'raw': b'HTTP/1.1 200 OK\r\nX-Diagnostic: other-tenant\r\n\r\nleaked diagnostics',
        }
        first = incident_scope.run(self.db, response_payload)
        second = incident_scope.run(self.db, response_payload)
        self.assertEqual(first['decision'], 'recorded', first)
        self.assertEqual(second['decision'], 'reused', second)
        self.assertEqual(
            self.db.execute("SELECT COUNT(*) FROM incident_responses WHERE trace_id='trace-13'").fetchone()[0],
            1,
        )
        egress = incident_scope.run(self.db, {
            'op': 'egress_count', 'id': 'INC', 'observation_id': 'egress-1',
            'trace_id': 'trace-13', 'observer': 'independent-exit-meter', 'count': 1, 'at': 13,
        })
        self.assertEqual(egress['decision'], 'recorded', egress)
        receipt = incident_scope.run(self.db, {
            'op': 'receipt', 'id': 'INC', 'receipt_id': 'receipt-13',
            'trace_id': 'trace-13', 'token': token, 'terminal': True,
            'signer': 'client-app', 'signed_at': 13,
            'signature': b'terminal-client-receipt-signature',
        })
        self.assertEqual(receipt['decision'], 'recorded', receipt)
        self.assertFalse(receipt['subject_resolved'])
        return token

    def unseal(self, client='乙', token='token-real-yi', op='unseal', at=16):
        return incident_scope.run(self.db, {
            'op': op, 'id': 'INC', 'token': token, 'client_id': client,
            'custodian': 'confidential-custodian', 'authorizer': 'contract-qian', 'at': at,
        })

    def test_wave_completion_minute_and_first_generation_scan_are_bound(self):
        finished = self.seed_wave()
        self.assertEqual(finished['completed_at'], 12)
        wave_row = self.db.execute('SELECT state,completed_at FROM waves WHERE id=?', ('W',)).fetchone()
        self.assertEqual((wave_row['state'], wave_row['completed_at']), ('complete', 12))
        scan = self.db.execute('SELECT generation,observed_at,version FROM node_scans WHERE node_id=?', ('n1',)).fetchone()
        self.assertEqual((scan['generation'], scan['observed_at'], scan['version']), (1, 10, '1.29'))
        repeated = wave.run(self.db, {'op': 'finish', 'id': 'W', 'transition': 't1'})
        self.assertEqual(repeated['decision'], 'reused')
        self.assertEqual(repeated['completed_at'], 12)

    def test_scope_uses_terminal_token_not_proxy_page_and_dedupes_retries(self):
        self.seed_wave()
        self.open_fixed_incident()
        # Credible evidence arrives at minute 14; an older sample ingested later
        # may move earliest_fault_at but must not move the legal clock.
        late_sample = incident_scope.run(self.db, {
            'op': 'fault_sample', 'id': 'INC', 'sample_id': 'late-earlier-health',
            'kind': 'gateway_fault_sample', 'observed_at': 11, 'recorded_at': 15,
            'trusted': True, 'healthy': False, 'data_returned': True,
        })
        self.assertEqual(late_sample['legal_clock_started_at'], 14)
        self.assertEqual(late_sample['earliest_fault_at'], 11)
        self.assertFalse(late_sample['clock_moved'])

        token = self.record_leaking_response()

        # A failed health probe with zero returned data does not create a victim.
        health = incident_scope.run(self.db, {
            'op': 'health_failure', 'id': 'INC', 'sample_id': 'empty-health',
            'node_id': 'n2', 'observed_at': 12, 'healthy': False,
            'response_count': 0, 'data_returned': False,
        })
        self.assertEqual(health['decision'], 'recorded', health)
        empty_response = incident_scope.run(self.db, {
            'op': 'response', 'id': 'INC', 'trace_id': 'trace-empty',
            'at': 12, 'candidate_clients': ['丙'], 'returned_data': False,
            'foreign_tenant_leak': False, 'raw': b'',
        })
        self.assertEqual(empty_response['decision'], 'recorded', empty_response)

        before = incident_scope.build_scope(self.db, 'INC')
        self.assertEqual(before['confirmed_client_ids'], [])
        self.assertEqual(set(before['possible_client_ids']), {'甲', '乙'})
        self.assertNotIn('甲', before['confirmed_client_ids'])

        missing_custodian = incident_scope.run(self.db, {
            'op': 'unseal', 'id': 'INC', 'token': token, 'client_id': '乙',
        })
        self.assertEqual(missing_custodian['decision'], 'blocked')
        unsealed = self.unseal(token=token)
        self.assertEqual(unsealed['decision'], 'unsealed', unsealed)
        resolved = incident_scope.resolve_token(self.db, token=token)
        self.assertEqual(resolved['client_id'], '乙')

        scope = incident_scope.run(self.db, {'op': 'scope', 'id': 'INC', 'at': 16})
        self.assertEqual(scope['decision'], 'scoped', scope)
        self.assertEqual(scope['confirmed_client_ids'], ['乙'])
        self.assertEqual(scope['possible_client_ids'], [])
        self.assertEqual(set(scope['excluded_client_ids']), {'丙', '甲'})
        self.assertIn('丁', scope['unknown_client_ids'])
        self.assertEqual(scope['deduplicated_response_count'], 2)
        self.assertEqual(scope['leaking_response_count'], 1)
        self.assertEqual(
            [r['event_type'] for r in self.db.execute(
                "SELECT DISTINCT outcome AS event_type FROM incident_forward_attempts WHERE trace_id='trace-13'"
            )],
            ['forwarded'],
        )

    def test_receipt_token_reversal_recovers_true_principal(self):
        self.open_fixed_incident()
        incident_scope.run(self.db, {
            'op': 'response', 'id': 'INC', 'trace_id': 'trace-1', 'at': 13,
            'candidate_clients': ['甲', '乙'], 'page_hint': '甲',
            'foreign_tenant_leak': True, 'egress_count': 1,
        })
        incident_scope.run(self.db, {
            'op': 'receipt', 'id': 'INC', 'trace_id': 'trace-1',
            'token': 'reversible-token', 'terminal': True, 'signed_at': 13,
        })
        first = self.unseal('甲', 'reversible-token', at=15)
        self.assertEqual(first['decision'], 'unsealed', first)
        self.assertEqual(incident_scope.build_scope(self.db, 'INC')['confirmed_client_ids'], ['甲'])

        blocked = self.unseal('乙', 'reversible-token', op='unseal', at=16)
        self.assertEqual(blocked['decision'], 'blocked')
        self.assertEqual(blocked['reason'], 'token_binding_conflict')

        reversed_result = self.unseal('乙', 'reversible-token', op='reverse_token', at=16)
        self.assertEqual(reversed_result['decision'], 'unsealed', reversed_result)
        self.assertIsNotNone(reversed_result['reversed_binding_id'])
        scope = incident_scope.build_scope(self.db, 'INC')
        self.assertEqual(scope['confirmed_client_ids'], ['乙'])
        self.assertEqual(scope['excluded_client_ids'], ['甲'])
        bindings = self.db.execute(
            "SELECT client_id,state FROM incident_token_bindings WHERE token_hash=? ORDER BY rowid",
            (incident_scope.token_digest('reversible-token'),),
        ).fetchall()
        self.assertEqual([(r['client_id'], r['state']) for r in bindings],
                         [('甲', 'reversed'), ('乙', 'active')])

    def test_escrow_precise_route_is_single_signed_idempotent_copy(self):
        self.seed_wave()
        self.open_fixed_incident()
        token = self.record_leaking_response()
        self.unseal(client='乙', token=token)

        blocked = notice_delivery.run(self.db, {
            'op': 'send_private', 'id': 'letter-jia', 'incident_id': 'INC',
            'recipient_id': '甲', 'at': 17, 'authorizer': 'legal-sun',
        })
        self.assertEqual(blocked['decision'], 'blocked')
        self.assertEqual(blocked['reason'], 'recipient_not_confirmed')
        leak_body = notice_delivery.run(self.db, {
            'op': 'send_private', 'id': 'leak-body', 'incident_id': 'INC',
            'recipient_id': '乙', 'at': 17, 'authorizer': 'legal-sun',
            'raw': '您与客户甲共同涉及本次事故'.encode(),
        })
        self.assertEqual(leak_body['decision'], 'blocked', leak_body)
        self.assertEqual(leak_body['reason'], 'cross_customer_identity_in_notice_body')
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM notice_documents").fetchone()[0], 0)

        sent = notice_delivery.run(self.db, {
            'op': 'send_private', 'id': 'letter-yi', 'incident_id': 'INC',
            'recipient_id': '乙', 'address': 'secure://乙', 'at': 17,
            'authorizer': 'legal-sun', 'approval_id': 'approval-1',
            'execution_mode': 'escrow_precise', 'gateway_code': 200,
        })
        self.assertEqual(sent['decision'], 'issued', sent)
        self.assertTrue(sent['first_notice'])
        self.assertTrue(sent['deadline_met'])
        self.assertEqual(sent['external_recipient_count'], 1)
        self.assertEqual(sent['gateway_accepted_count'], 1)
        self.assertEqual(sent['signed_count'], 0)
        self.assertFalse(sent['terminal_delivery_proven'])

        raw = notice_delivery.get_notice_bytes(self.db, 'letter-yi')
        self.assertIn('乙'.encode(), raw)
        self.assertNotIn('甲'.encode(), raw)
        self.assertNotIn('丙'.encode(), raw)

        verified_before_sign = notice_delivery.run(self.db, {
            'op': 'verify', 'notice_id': 'letter-yi', 'recipient_id': '乙', 'body': raw,
        })
        self.assertTrue(verified_before_sign['authentic'])
        self.assertFalse(verified_before_sign['final_signed'])

        signed = notice_delivery.run(self.db, {
            'op': 'sign', 'notice_id': 'letter-yi', 'at': 18,
            'signer': '乙-device', 'signature': b'final-signature',
        })
        self.assertEqual(signed['decision'], 'recorded', signed)
        self.assertEqual(signed['state'], 'signed')
        self.assertEqual(signed['signed_count'], 1)
        self.assertTrue(signed['terminal_delivery_proven'])

        repeated = notice_delivery.run(self.db, {
            'op': 'send_private', 'id': 'letter-yi', 'incident_id': 'INC',
            'recipient_id': '乙', 'at': 25, 'body': b'contradictory new first version',
        })
        self.assertEqual(repeated['decision'], 'reused')
        self.assertTrue(repeated['idempotent'])
        self.assertEqual(repeated['first_sent_at'], 17)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM notice_documents").fetchone()[0], 1)
        self.assertEqual(notice_delivery.get_notice_bytes(self.db, 'letter-yi'), raw)

        history = notice_delivery.delivery_history(self.db, 'INC')
        self.assertEqual(history['first_notice_id'], 'letter-yi')
        self.assertEqual(history['first_kind'], 'customer_private')
        self.assertEqual(history['first_notice_recipient_count'], 1)
        self.assertEqual(history['execution_route'], 'escrow_precise')

    def test_advisory_first_preserves_general_notice_and_later_private_letter(self):
        self.seed_wave()
        self.open_fixed_incident(clients=('甲', '乙', '丙'))
        token = self.record_leaking_response()

        advisory = notice_delivery.run(self.db, {
            'op': 'send_advisory', 'id': 'advisory-1', 'incident_id': 'INC',
            'at': 15, 'authorizer': 'legal-sun',
            'execution_mode': 'advisory_first',
            'recipient_ids': ['甲', '乙', '丙'],
        })
        self.assertEqual(advisory['decision'], 'issued', advisory)
        self.assertTrue(advisory['first_notice'])
        self.assertTrue(advisory['deadline_met'])
        self.assertEqual(advisory['external_recipient_count'], 3)
        self.assertEqual(advisory['signed_count'], 0)
        advisory_bytes = notice_delivery.get_notice_bytes(self.db, 'advisory-1')
        for client in ('甲', '乙', '丙'):
            self.assertNotIn(client.encode(), advisory_bytes)
        self.assertIn('服务级预告'.encode(), advisory_bytes)

        # Gateway 200s are accepted handoff only, never terminal receipts.
        for client in ('甲', '乙'):
            ack = notice_delivery.run(self.db, {
                'op': 'gateway_success', 'notice_id': 'advisory-1',
                'recipient_id': client, 'at': 15, 'gateway_code': 200,
            })
            self.assertEqual(ack['decision'], 'recorded', ack)
        status = notice_delivery.notice_status(self.db, 'advisory-1')
        self.assertEqual(status['gateway_accepted_count'], 2)
        self.assertEqual(status['signed_count'], 0)
        self.assertFalse(status['terminal_delivery_proven'])

        self.unseal(client='乙', token=token, at=16)
        private = notice_delivery.run(self.db, {
            'op': 'send_private', 'id': 'private-yi', 'incident_id': 'INC',
            'recipient_id': '乙', 'at': 17, 'authorizer': 'legal-sun',
            'execution_mode': 'advisory_first', 'gateway_code': 200,
        })
        self.assertEqual(private['decision'], 'issued', private)
        self.assertFalse(private['first_notice'])
        self.assertEqual(private['first_notice_id'], 'advisory-1')
        private_bytes = notice_delivery.get_notice_bytes(self.db, 'private-yi')
        self.assertIn('乙'.encode(), private_bytes)
        self.assertNotIn('甲'.encode(), private_bytes)

        signed = notice_delivery.run(self.db, {
            'op': 'sign', 'notice_id': 'private-yi', 'at': 18,
            'signer': '乙', 'signature': b'yi-receipt',
        })
        self.assertEqual(signed['signed_count'], 1)

        history = notice_delivery.delivery_history(self.db, 'INC')
        self.assertEqual(history['first_notice_id'], 'advisory-1')
        self.assertEqual(history['first_body_hash'], advisory['body_hash'])
        self.assertEqual(history['first_notice_recipient_count'], 3)
        self.assertEqual(history['total_delivery_records'], 4)
        self.assertEqual(set(history['unique_recipient_ids']), {'甲', '乙', '丙'})

        yi_ledger = notice_delivery.recipient_ledger(self.db, '乙')
        self.assertEqual([n['notice_id'] for n in yi_ledger['notices']], ['advisory-1', 'private-yi'])
        for notice in yi_ledger['notices']:
            self.assertEqual([r['recipient_id'] for r in notice['recipients']], ['乙'])
        jia_ledger = notice_delivery.recipient_ledger(self.db, '甲')
        self.assertEqual([n['notice_id'] for n in jia_ledger['notices']], ['advisory-1'])

        repeated_advisory = notice_delivery.run(self.db, {
            'op': 'send_advisory', 'id': 'advisory-1', 'incident_id': 'INC', 'at': 22,
        })
        self.assertEqual(repeated_advisory['decision'], 'reused')
        self.assertEqual(notice_delivery.get_notice_bytes(self.db, 'advisory-1'), advisory_bytes)

    def test_bounce_redelivery_keeps_first_send_and_final_signature(self):
        self.open_fixed_incident()
        incident_scope.run(self.db, {
            'op': 'response', 'id': 'INC', 'trace_id': 'trace-bounce',
            'candidate_clients': ['乙'], 'foreign_tenant_leak': True, 'egress_count': 1,
        })
        incident_scope.run(self.db, {
            'op': 'receipt', 'id': 'INC', 'trace_id': 'trace-bounce',
            'token': 'tok-bounce', 'terminal': True, 'signed_at': 13,
        })
        self.unseal('乙', 'tok-bounce')
        sent = notice_delivery.run(self.db, {
            'op': 'send_private', 'id': 'letter-bounce', 'incident_id': 'INC',
            'recipient_id': '乙', 'at': 17, 'authorizer': 'legal-sun',
        })
        self.assertEqual(sent['decision'], 'issued', sent)

        bounced = notice_delivery.run(self.db, {
            'op': 'bounce', 'notice_id': 'letter-bounce', 'at': 17,
            'code': '550', 'bounce_reason': 'mailbox full / endpoint unreachable',
        })
        self.assertEqual(bounced['state'], 'bounced')
        self.assertEqual(bounced['bounced_count'], 1)

        retried = notice_delivery.run(self.db, {
            'op': 'redeliver', 'notice_id': 'letter-bounce', 'at': 18,
            'gateway_code': 250,
        })
        self.assertEqual(retried['decision'], 'recorded', retried)
        self.assertEqual(retried['recipients'][0]['attempts'], 2)
        self.assertEqual(retried['gateway_accepted_count'], 1)
        self.assertEqual(retried['bounced_count'], 0)

        delivered = notice_delivery.run(self.db, {
            'op': 'mark_delivered', 'notice_id': 'letter-bounce', 'at': 18,
            'delivery_receipt': 'carrier-handover',
        })
        self.assertEqual(delivered['delivered_count'], 1)
        self.assertTrue(delivered['terminal_delivery_proven'])

        signed = notice_delivery.run(self.db, {
            'op': 'sign', 'notice_id': 'letter-bounce', 'at': 19,
            'signer': '乙', 'signature': b'redelivered-final-receipt',
        })
        self.assertEqual(signed['state'], 'signed')
        self.assertEqual(signed['signed_count'], 1)
        self.assertEqual(signed['first_sent_at'], 17)
        event_types = [e['event_type'] for e in signed['events']]
        self.assertIn('bounced', event_types)
        self.assertEqual(event_types.count('send_attempt'), 2)
        self.assertIn('signed', event_types)

    def test_delivered_wrong_letter_is_corrected_not_deleted(self):
        self.open_fixed_incident()
        incident_scope.run(self.db, {
            'op': 'response', 'id': 'INC', 'trace_id': 'trace-wrong',
            'candidate_clients': ['甲', '乙'], 'page_hint': '甲',
            'foreign_tenant_leak': True, 'egress_count': 1,
        })
        incident_scope.run(self.db, {
            'op': 'receipt', 'id': 'INC', 'trace_id': 'trace-wrong',
            'token': 'tok-wrong', 'terminal': True, 'signed_at': 13,
        })
        self.unseal('甲', 'tok-wrong', at=15)
        wrong = notice_delivery.run(self.db, {
            'op': 'send_private', 'id': 'wrong-jia', 'incident_id': 'INC',
            'recipient_id': '甲', 'at': 16, 'authorizer': 'legal-sun', 'gateway_code': 200,
        })
        self.assertEqual(wrong['decision'], 'issued', wrong)
        notice_delivery.run(self.db, {
            'op': 'sign', 'notice_id': 'wrong-jia', 'at': 17,
            'signer': '甲', 'signature': b'jia-signed-wrong-letter',
        })
        wrong_bytes = notice_delivery.get_notice_bytes(self.db, 'wrong-jia')

        reversed_result = self.unseal('乙', 'tok-wrong', op='reverse_token', at=17)
        self.assertEqual(reversed_result['decision'], 'unsealed', reversed_result)
        blocked = notice_delivery.run(self.db, {
            'op': 'send_private', 'id': 'another-jia', 'incident_id': 'INC',
            'recipient_id': '甲', 'at': 18, 'authorizer': 'legal-sun',
        })
        self.assertEqual(blocked['reason'], 'recipient_not_confirmed')

        correction = notice_delivery.run(self.db, {
            'op': 'correct', 'id': 'correction-jia', 'incident_id': 'INC',
            'corrects_notice_id': 'wrong-jia', 'recipient_id': '甲',
            'at': 18, 'authorizer': 'legal-sun',
            'claimed_classification': 'confirmed',
            'correction_reason': 'signed token reversal identifies 乙 and unique egress excludes 甲',
            'gateway_code': 200,
        })
        self.assertEqual(correction['decision'], 'issued', correction)
        self.assertEqual(correction['kind'], 'correction')
        self.assertEqual(correction['corrects_notice_id'], 'wrong-jia')
        correction_bytes = notice_delivery.get_notice_bytes(self.db, 'correction-jia')
        self.assertIn('甲'.encode(), correction_bytes)
        self.assertNotIn('乙'.encode(), correction_bytes)
        notice_delivery.run(self.db, {
            'op': 'sign', 'notice_id': 'correction-jia', 'at': 19,
            'signer': '甲', 'signature': b'jia-correction-receipt',
        })

        right_letter = notice_delivery.run(self.db, {
            'op': 'send_private', 'id': 'right-yi', 'incident_id': 'INC',
            'recipient_id': '乙', 'at': 18, 'authorizer': 'legal-sun', 'gateway_code': 200,
        })
        self.assertEqual(right_letter['decision'], 'issued', right_letter)
        notice_delivery.run(self.db, {'op': 'sign', 'notice_id': 'right-yi', 'at': 19, 'signer': '乙'})

        # The delivered wrong original is retained byte-for-byte.
        self.assertEqual(notice_delivery.get_notice_bytes(self.db, 'wrong-jia'), wrong_bytes)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("DELETE FROM notice_documents WHERE notice_id='wrong-jia'")
        wrong_row = self.db.execute("SELECT state,body_hash FROM notice_documents WHERE notice_id='wrong-jia'").fetchone()
        self.assertEqual(wrong_row['state'], 'signed')
        self.assertGreaterEqual(self.db.execute("SELECT COUNT(*) FROM notice_documents").fetchone()[0], 3)
        corrected_link = self.db.execute(
            "SELECT json_extract(detail_json,'$.corrected_by') AS corrected_by FROM notice_documents WHERE notice_id='wrong-jia'"
        ).fetchone()
        self.assertEqual(corrected_link['corrected_by'], 'correction-jia')

    def test_regulator_supplement_has_original_authorization_bounce_and_signature(self):
        self.open_fixed_incident()
        incident_scope.run(self.db, {
            'op': 'response', 'id': 'INC', 'trace_id': 'trace-reg',
            'candidate_clients': ['甲', '乙'], 'foreign_tenant_leak': True, 'egress_count': 1,
        })
        incident_scope.run(self.db, {
            'op': 'receipt', 'id': 'INC', 'trace_id': 'trace-reg',
            'token': 'tok-reg', 'terminal': True, 'signed_at': 13,
        })
        self.unseal('乙', 'tok-reg')
        filing = notice_delivery.run(self.db, {
            'op': 'file_regulator', 'id': 'reg-1', 'incident_id': 'INC',
            'regulator_id': 'cyberspace-authority', 'at': 20,
            'authorizer': 'legal-sun', 'approval_id': 'reg-approval',
        })
        self.assertEqual(filing['decision'], 'issued', filing)
        self.assertEqual(filing['kind'], 'regulator_supplement')
        raw = notice_delivery.get_notice_bytes(self.db, 'reg-1')
        self.assertIn('乙'.encode(), raw)
        self.assertIn('甲'.encode(), raw)
        row = self.db.execute('SELECT authorizer,approval_id,body_raw FROM notice_documents WHERE notice_id=?', ('reg-1',)).fetchone()
        self.assertEqual(row['authorizer'], 'legal-sun')
        self.assertEqual(row['approval_id'], 'reg-approval')
        self.assertTrue(row['body_raw'])

        bounced = notice_delivery.run(self.db, {
            'op': 'bounce', 'notice_id': 'reg-1', 'at': 20, 'code': '451',
            'bounce_reason': 'temporary regulator gateway failure',
        })
        self.assertEqual(bounced['bounced_count'], 1)
        notice_delivery.run(self.db, {'op': 'redeliver', 'notice_id': 'reg-1', 'at': 21, 'gateway_code': 202})
        signed = notice_delivery.run(self.db, {
            'op': 'sign', 'notice_id': 'reg-1', 'at': 22,
            'signer': 'regulator-mailroom', 'signature': b'regulator-receipt',
        })
        self.assertEqual(signed['state'], 'signed')
        self.assertEqual(signed['signed_count'], 1)
        verification = notice_delivery.run(self.db, {
            'op': 'verify', 'notice_id': 'reg-1',
            'recipient_id': 'cyberspace-authority', 'body_hash': filing['body_hash'],
        })
        self.assertTrue(verification['authentic'])
        self.assertTrue(verification['final_signed'])

    def test_late_first_notice_is_blocked_unless_breach_is_authorized(self):
        self.open_fixed_incident()
        late_sample = incident_scope.run(self.db, {
            'op': 'fault_sample', 'id': 'INC', 'sample_id': 'very-old',
            'observed_at': 9, 'recorded_at': 18, 'healthy': False,
        })
        self.assertEqual(late_sample['legal_clock_started_at'], 14)
        self.assertEqual(late_sample['first_notice_deadline_at'], 19)

        blocked = notice_delivery.run(self.db, {
            'op': 'send_advisory', 'id': 'late-1', 'incident_id': 'INC',
            'recipient_ids': ['甲'], 'at': 20, 'authorizer': 'legal-sun',
        })
        self.assertEqual(blocked['decision'], 'blocked')
        self.assertEqual(blocked['reason'], 'first_notice_deadline_exceeded')
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM notice_documents").fetchone()[0], 0)

        allowed = notice_delivery.run(self.db, {
            'op': 'send_advisory', 'id': 'late-breach', 'incident_id': 'INC',
            'recipient_ids': ['甲'], 'at': 20, 'authorizer': 'legal-sun',
            'accept_breach': True, 'breach_authorized_by': 'general-counsel',
        })
        self.assertEqual(allowed['decision'], 'issued_late_breach_recorded')
        self.assertTrue(allowed['late'])
        self.assertFalse(allowed['deadline_met'])

    def test_execution_route_must_be_contract_owner_preapproved(self):
        incident_scope.run(self.db, {
            'op': 'open', 'id': 'I-approval', 'evidence_at': 14, 'deadline_at': 19,
            'contract_owner': 'contract-qian',
            'approved_modes': ['escrow_precise'], 'subscribers': ['甲'],
        })
        blocked = notice_delivery.run(self.db, {
            'op': 'send_advisory', 'id': 'adv', 'incident_id': 'I-approval',
            'at': 15, 'authorizer': 'legal-sun',
        })
        self.assertEqual(blocked['decision'], 'blocked', blocked)
        self.assertEqual(blocked['reason'], 'execution_route_not_preapproved')
        approval = incident_scope.run(self.db, {
            'op': 'approve_route', 'id': 'I-approval',
            'mode': 'advisory_first', 'approved_by': 'contract-qian',
            'approval_id': 'route-approval-2', 'at': 14,
        })
        self.assertEqual(approval['decision'], 'approved', approval)
        sent = notice_delivery.run(self.db, {
            'op': 'send_advisory', 'id': 'adv', 'incident_id': 'I-approval',
            'at': 15, 'authorizer': 'legal-sun',
        })
        self.assertEqual(sent['decision'], 'issued', sent)

    def test_full_incident_and_delivery_replay_matches(self):
        self.seed_wave()
        self.open_fixed_incident()
        token = self.record_leaking_response()
        self.unseal(client='乙', token=token)
        notice_delivery.run(self.db, {
            'op': 'send_private', 'id': 'letter', 'incident_id': 'INC',
            'recipient_id': '乙', 'at': 17, 'authorizer': 'legal-sun',
            'execution_mode': 'escrow_precise', 'gateway_code': 200,
            'raw': b'From: legal@example\r\nTo: yi@example\r\n\r\nExact original \xe5\x87\xbd\xe4\xbb\xb6 bytes',
        })
        notice_delivery.run(self.db, {
            'op': 'sign', 'notice_id': 'letter', 'at': 18,
            'signer': '乙', 'signature': b'receipt-bytes',
        })
        self.db.close()
        result = replay(self.path, {
            'inventory': inventory,
            'wave': wave,
            'incident_scope': incident_scope,
            'notice_delivery': notice_delivery,
        })
        self.assertTrue(result['verified'], result['divergences'])


if __name__ == '__main__':
    unittest.main()
