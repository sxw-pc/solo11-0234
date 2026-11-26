import json
import tempfile
import unittest
from pathlib import Path

from cloudlab.store import connect, replay
from cloudlab import inventory, wave, warranty, warranty_resolution as resolution


class WarrantyResolutionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / 'warranty.sqlite')
        self.db = connect(self.path)
        inventory.run(self.db, {
            'op': 'node', 'id': 'n1', 'architecture': 'amd64',
            'features': ['cgroup2'], 'generation': 1,
            'observed_at': 10, 'version': '1.29', 'zone': 'z1',
        })
        inventory.run(self.db, {
            'op': 'verify', 'id': 'n1', 'now': 12, 'max_age': 10,
            'architecture': 'amd64', 'features': ['cgroup2'],
            'deprecated_api': 'old/v1',
        })
        wave.run(self.db, {'op': 'plan', 'id': 'w', 'target': '1.30', 'max_unavailable': 1})
        wave.run(self.db, {'op': 'release', 'id': 'w', 'transition': 't',
                           'node': 'n1', 'now': 13})
        wave.run(self.db, {'op': 'probe', 'id': 'w', 'transition': 't',
                           'probe': 'bad', 'generation': 1, 'target': '1.30',
                           'at': 14, 'healthy': False,
                           'fault_category': 'mainboard'})
        self.assertEqual(warranty.open_claim(self.db, 'C', 't', 'V')['decision'], 'draft')
        resolution.run(self.db, {
            'op': 'register_contract', 'id': 'K', 'vendor': 'V',
            'entitlement_id': 'E-n1', 'device_id': 'n1', 'buyer': 'acme-procurement',
            'bank_account_id': 'acme-001', 'account_owner': 'Acme Manufacturing',
            'active_from': 1, 'active_to': 100,
            'fault_categories': ['mainboard'],
            'replacement_model': 'MB-X2', 'replacement_capacity': '1TB',
            'warranty_days': 365, 'cash_amount': 1000,
        })
        self.assertEqual(resolution.run(self.db, {
            'op': 'bind_claim', 'claim_id': 'C', 'contract_id': 'K',
            'fault_category': 'mainboard', 'entitlement_id': 'E-n1',
        })['decision'], 'bound')
        self.assertEqual(resolution.run(self.db, {
            'op': 'acknowledge_vendor', 'id': 'Q1', 'claim_id': 'C',
            'at': 20, 'covered': True, 'fault_category': 'mainboard',
            'scope': ['mainboard'], 'cash_amount': 1000,
        })['decision'], 'acknowledged')

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_contract_period_and_failed_probe_are_enforced(self):
        with tempfile.TemporaryDirectory() as d:
            db = connect(str(Path(d) / 'small.sqlite'))
            inventory.run(db, {'op': 'node', 'id': 'n', 'architecture': 'amd64',
                               'features': [], 'generation': 1, 'observed_at': 1,
                               'version': '1'})
            inventory.run(db, {'op': 'verify', 'id': 'n', 'now': 2, 'max_age': 10,
                               'architecture': 'amd64', 'features': [],
                               'deprecated_api': 'old/v1'})
            wave.run(db, {'op': 'plan', 'id': 'w', 'target': '2', 'max_unavailable': 1})
            wave.run(db, {'op': 'release', 'id': 'w', 'transition': 't',
                          'node': 'n', 'now': 2})
            wave.run(db, {'op': 'probe', 'id': 'w', 'transition': 't', 'probe': 'p',
                          'generation': 1, 'target': '2', 'at': 3, 'healthy': False})
            warranty.open_claim(db, 'C', 't', 'V')
            resolution.run(db, {'op': 'contract', 'id': 'old', 'vendor': 'V',
                                'entitlement_id': 'E', 'active_from': 50,
                                'active_to': 60, 'categories': ['x']})
            result = resolution.run(db, {'op': 'bind', 'claim_id': 'C',
                                         'contract_id': 'old', 'category': 'x'})
            self.assertEqual(result['reason'], 'contract_not_effective_at_fault')
            db.close()

    def test_changed_claim_number_cannot_create_second_relief(self):
        conflict = warranty.open_claim(self.db, 'C2', 't', 'V')
        self.assertEqual(conflict['decision'], 'claim_conflict')
        self.assertEqual(conflict['reason'], 'duplicate_fault')
        self.assertEqual(self.db.execute(
            'SELECT COUNT(*) FROM warranty_claims WHERE transition_id=?', ('t',)
        ).fetchone()[0], 1)

        again = warranty.open_claim(self.db, 'C', 't', 'V')
        self.assertEqual(again['decision'], 'replay')

    def test_portal_and_carrier_events_do_not_create_stock(self):
        resolution.run(self.db, {'op': 'select_remedy', 'claim_id': 'C',
                                 'remedy': 'replacement', 'at': 21})
        resolution.run(self.db, {'op': 'portal_status', 'id': 'portal-10',
                                 'claim_id': 'C', 'at': 30,
                                 'status': 'free_item_replenished'})
        resolution.run(self.db, {'op': 'ship_replacement', 'id': 'SHIP1',
                                 'claim_id': 'C', 'at': 30, 'carrier': 'Fast',
                                 'tracking_ref': 'TRK1', 'status': 'packed',
                                 'model': 'MB-X2', 'capacity': '1TB',
                                 'warranty_days': 365})
        resolution.run(self.db, {'op': 'carrier_pickup', 'id': 'PICK1',
                                 'claim_id': 'C', 'at': 31,
                                 'shipment_id': 'SHIP1', 'status': 'picked_up'})
        self.assertEqual(resolution.stock_available(self.db), 0)

        signed = resolution.run(self.db, {'op': 'sign_receipt', 'id': 'R1',
                                          'claim_id': 'C', 'shipment_id': 'SHIP1',
                                          'at': 34})
        self.assertEqual(signed['decision'], 'signed')
        self.assertEqual(resolution.stock_available(self.db), 0)

    def test_conforming_warehouse_acceptance_creates_only_vendor_stock_and_tracks_core(self):
        resolution.run(self.db, {'op': 'choose_remedy', 'claim_id': 'C',
                                 'remedy': 'replacement'})
        result = resolution.run(self.db, {
            'op': 'accept_replacement', 'id': 'R1', 'claim_id': 'C',
            'shipment_id': 'SHIP1', 'at': 34, 'model': 'MB-X2',
            'capacity': '1024GB', 'warranty_days': 365, 'quantity': 1,
        })
        # No shipment was required before receipt; acceptance itself records arrival.
        self.assertEqual(result['decision'], 'accepted')
        self.assertTrue(result['inventory_changed'])
        self.assertEqual(resolution.stock_available(self.db), 1)

        stock = self.db.execute(
            "SELECT source_type,supplier,payer FROM warehouse_stock WHERE claim_id='C'"
        ).fetchone()
        self.assertEqual(stock['source_type'], 'vendor_replacement')
        self.assertEqual(stock['supplier'], 'V')
        self.assertEqual(stock['payer'], 'acme-procurement')

        state = resolution.status(self.db, 'C')
        self.assertEqual(state['completion_boundary'], 'warehouse_acceptance')
        self.assertEqual(state['selected_remedy'], 'replacement')
        self.assertTrue(any(o['type'] == 'return_faulty_core' for o in state['obligations']))

        shipped = resolution.run(self.db, {'op': 'return_core', 'id': 'RET-CORE',
                                           'claim_id': 'C', 'carrier': 'Fast',
                                           'at': 40})
        self.assertEqual(shipped['decision'], 'core_disposition_recorded')
        owned = resolution.run(self.db, {'op': 'confirm_core_return', 'id': 'CORE-OK',
                                         'claim_id': 'C', 'at': 44})
        self.assertEqual(owned['core_state'], 'vendor_owned')
        self.assertEqual(resolution.status(self.db, 'C')['core_owner'], 'vendor')

    def test_wrong_part_is_rejected_and_vendor_still_owes(self):
        resolution.run(self.db, {'op': 'select_remedy', 'claim_id': 'C',
                                 'remedy': 'replacement'})
        bad = resolution.run(self.db, {
            'op': 'receive_replacement', 'id': 'R-BAD', 'claim_id': 'C',
            'at': 35, 'model': 'MB-999', 'capacity': '512GB',
            'warranty_days': 90,
        })
        self.assertEqual(bad['decision'], 'rejected')
        self.assertIn('model_mismatch', bad['spec_mismatches'])
        self.assertEqual(resolution.stock_available(self.db), 0)

        ret = resolution.run(self.db, {'op': 'shipment', 'id': 'RET1',
                                       'claim_id': 'C', 'kind': 'return',
                                       'direction': 'return_to_vendor',
                                       'link_id': 'R-BAD', 'at': 36})
        self.assertEqual(ret['decision'], 'shipment_recorded')
        state = resolution.status(self.db, 'C')
        self.assertTrue(any(o['party'] == 'V' and o['type'] == 'conforming_replacement'
                            for o in state['obligations']))

        good = resolution.run(self.db, {
            'op': 'receive_replacement', 'id': 'R-GOOD', 'claim_id': 'C',
            'at': 38, 'model': 'MB-X2', 'capacity': '1TB',
            'warranty_days': 365,
        })
        self.assertEqual(good['decision'], 'accepted')
        self.assertEqual(resolution.stock_available(self.db), 1)

    def test_credit_memo_and_portal_paid_are_not_cash(self):
        resolution.run(self.db, {'op': 'elect_remedy', 'claim_id': 'C', 'remedy': 'cash'})
        for op, payload in [
            ('record_bank_receipt', {'id': 'CM1', 'instrument': 'credit_memo', 'amount': 1000}),
            ('settle_cash', {'id': 'P1', 'channel': 'portal_paid', 'amount': 1000}),
        ]:
            payload.update({'op': op, 'claim_id': 'C'})
            result = resolution.run(self.db, payload)
            self.assertEqual(result['reason'], 'not_bank_settlement')
        self.assertEqual(resolution.status(self.db, 'C')['cash']['net'], 0)

    def test_partial_bank_payments_leave_remaining_vendor_obligation(self):
        resolution.run(self.db, {'op': 'select_remedy', 'claim_id': 'C', 'remedy': 'cash'})
        first = resolution.run(self.db, {'op': 'bank_receipt', 'id': 'B1',
                                         'claim_id': 'C', 'amount': 400,
                                         'at': 21, 'account_owner': 'Acme Manufacturing'})
        self.assertEqual(first['decision'], 'settled')
        self.assertFalse(first['cash_complete'])
        state = resolution.status(self.db, 'C')
        self.assertEqual(state['cash']['remaining_from_vendor'], 600)
        self.assertTrue(any(o['type'] == 'cash_payment' and o['remaining_amount'] == 600
                            for o in state['obligations']))

        replay_first = resolution.run(self.db, {'op': 'bank_receipt', 'id': 'B1',
                                                'claim_id': 'C', 'amount': 400,
                                                'at': 21,
                                                'account_owner': 'Acme Manufacturing'})
        self.assertEqual(replay_first['decision'], 'replay')
        second = resolution.run(self.db, {'op': 'record_bank_receipt', 'id': 'B2',
                                          'claim_id': 'C', 'amount': 600,
                                          'at': 25,
                                          'account_owner': 'Acme Manufacturing'})
        self.assertTrue(second['cash_complete'])
        self.assertEqual(resolution.status(self.db, 'C')['completion_boundary'],
                         'bank_settlement')

    def test_wrong_owner_and_pending_receipt_do_not_settle_until_late_confirmation(self):
        wrong = resolution.run(self.db, {'op': 'bank_receipt', 'id': 'BW',
                                         'claim_id': 'C', 'amount': 1000,
                                         'account_owner': 'Some Other Corp',
                                         'at': 22})
        self.assertEqual(wrong['decision'], 'blocked')
        self.assertEqual(wrong['reason'], 'bank_receipt_not_available_as_cash')
        self.assertEqual(resolution.status(self.db, 'C')['cash']['net'], 0)

        pending = resolution.run(self.db, {'op': 'bank_receipt', 'id': 'BP',
                                           'claim_id': 'C', 'amount': 1000,
                                           'status': 'pending',
                                           'account_owner': 'Acme Manufacturing',
                                           'at': 23})
        self.assertEqual(pending['status'], 'pending')
        self.assertEqual(resolution.status(self.db, 'C')['cash']['net'], 0)

        settled = resolution.run(self.db, {'op': 'attribute_bank_receipt',
                                           'receipt_id': 'BP',
                                           'account_owner': 'Acme Manufacturing',
                                           'at': 28})
        self.assertEqual(settled['decision'], 'settled')
        self.assertTrue(settled['cash_net'] == 1000)

    def test_cash_path_requires_independent_purchase_and_actual_purchase_arrival(self):
        resolution.run(self.db, {'op': 'select_remedy', 'claim_id': 'C', 'remedy': 'cash'})
        blocked = resolution.run(self.db, {'op': 'create_purchase_order', 'id': 'PO1',
                                           'claim_id': 'C', 'supplier': 'S2'})
        self.assertEqual(blocked['reason'], 'cash_not_settled_before_procurement')

        resolution.run(self.db, {'op': 'bank_receipt', 'id': 'B1', 'claim_id': 'C',
                                 'amount': 1000,
                                 'account_owner': 'Acme Manufacturing'})
        same_vendor = resolution.run(self.db, {'op': 'purchase_order', 'id': 'POV',
                                               'claim_id': 'C', 'supplier': 'V'})
        self.assertEqual(same_vendor['reason'], 'procurement_supplier_must_be_independent')

        po = resolution.run(self.db, {'op': 'purchase_order', 'id': 'PO1',
                                      'claim_id': 'C', 'supplier': 'S2',
                                      'amount': 920})
        self.assertEqual(po['decision'], 'purchase_order_created')
        self.assertEqual(resolution.stock_available(self.db), 0)

        arrival = resolution.run(self.db, {'op': 'receive_purchase', 'id': 'PR1',
                                           'claim_id': 'C', 'purchase_order_id': 'PO1',
                                           'at': 40, 'model': 'MB-X2',
                                           'capacity': '1TB', 'warranty_days': 365})
        self.assertEqual(arrival['decision'], 'accepted')
        stock = self.db.execute(
            "SELECT source_type,source_id,supplier,payer FROM warehouse_stock WHERE claim_id='C'"
        ).fetchone()
        self.assertEqual(stock['source_type'], 'third_party_purchase')
        self.assertEqual(stock['source_id'], 'PO1')
        self.assertEqual(stock['supplier'], 'S2')
        self.assertEqual(stock['payer'], 'acme-procurement')
        self.assertEqual(resolution.stock_available(self.db), 1)

    def test_late_wrong_part_after_cash_is_not_stock_and_cannot_create_double_relief(self):
        resolution.run(self.db, {'op': 'select_remedy', 'claim_id': 'C', 'remedy': 'cash'})
        resolution.run(self.db, {'op': 'bank_receipt', 'id': 'B1', 'claim_id': 'C',
                                 'amount': 1000,
                                 'account_owner': 'Acme Manufacturing'})
        late = resolution.run(self.db, {'op': 'receive_replacement', 'id': 'LATE',
                                        'claim_id': 'C', 'at': 35,
                                        'model': 'MB-999', 'capacity': '512GB',
                                        'warranty_days': 30})
        self.assertEqual(late['decision'], 'rejected')
        self.assertEqual(late['reason'], 'spec_mismatch')
        self.assertEqual(resolution.stock_available(self.db), 0)

        # A later conforming unit must also be excluded once cash boundary is complete.
        conforming = resolution.run(self.db, {'op': 'receive_replacement', 'id': 'LATE2',
                                             'claim_id': 'C', 'at': 36,
                                             'model': 'MB-X2', 'capacity': '1TB',
                                             'warranty_days': 365})
        self.assertEqual(conforming['decision'], 'rejected')
        self.assertEqual(conforming['reason'], 'cash_remedy_completed')
        self.assertEqual(resolution.stock_available(self.db), 0)
        self.assertTrue(resolution.status(self.db, 'C')['exclusive_relief_intact'])

    def test_replacement_then_late_cash_must_be_reversed(self):
        resolution.run(self.db, {'op': 'select_remedy', 'claim_id': 'C',
                                 'remedy': 'replacement'})
        resolution.run(self.db, {'op': 'receive_replacement', 'id': 'R1',
                                 'claim_id': 'C', 'model': 'MB-X2',
                                 'capacity': '1TB', 'warranty_days': 365})
        late_cash = resolution.run(self.db, {'op': 'bank_receipt', 'id': 'LATE-BANK',
                                             'claim_id': 'C', 'amount': 1000,
                                             'account_owner': 'Acme Manufacturing'})
        self.assertEqual(late_cash['decision'], 'settled')
        self.assertTrue(late_cash['exclusive_remedy_conflict'])
        state = resolution.status(self.db, 'C')
        self.assertTrue(any(o['type'] == 'return_duplicate_cash' for o in state['obligations']))

        reversal = resolution.run(self.db, {'op': 'reverse_bank_receipt',
                                            'id': 'REV1', 'reversal_id': 'REV1',
                                            'receipt_id': 'LATE-BANK',
                                            'claim_id': 'C', 'at': 50,
                                            'reason': 'exclusive_remedy'})
        self.assertEqual(reversal['decision'], 'reversed')
        self.assertEqual(reversal['cash_net'], 0)
        self.assertTrue(resolution.status(self.db, 'C')['exclusive_relief_intact'])

    def test_partial_shipment_only_adds_accepted_quantity_and_keeps_vendor_obligation(self):
        resolution.run(self.db, {'op': 'select_remedy', 'claim_id': 'C',
                                 'remedy': 'replacement', 'quantity': 2})
        self.assertEqual(self.db.execute(
            "SELECT required_quantity FROM warranty_claims WHERE id='C'"
        ).fetchone()[0], 2)
        partial = resolution.run(self.db, {'op': 'receive_replacement', 'id': 'RP1',
                                           'claim_id': 'C', 'quantity': 2,
                                           'accepted_quantity': 1,
                                           'model': 'MB-X2', 'capacity': '1TB',
                                           'warranty_days': 365})
        self.assertEqual(partial['decision'], 'partially_accepted')
        self.assertEqual(resolution.stock_available(self.db), 1)
        state = resolution.status(self.db, 'C')
        self.assertFalse(state['cash']['complete'])
        self.assertTrue(any(o['type'] == 'conforming_replacement'
                            and o['remaining_quantity'] == 1 for o in state['obligations']))

    def test_fixed_minute_timeline_requires_physical_or_bank_boundary(self):
        # Minute 10: portal claims replenishment; logistics is only packed.
        resolution.run(self.db, {'op': 'select_remedy', 'claim_id': 'C',
                                 'remedy': 'replacement', 'at': 9})
        resolution.run(self.db, {'op': 'portal_status', 'id': 'portal-10',
                                 'claim_id': 'C', 'at': 10,
                                 'status': 'free_item_replenished'})
        resolution.run(self.db, {'op': 'record_shipment', 'id': 'SHIP',
                                 'claim_id': 'C', 'at': 10, 'status': 'packed'})
        # Minute 11: vendor offers equal cash; switching before a boundary is allowed.
        offer = resolution.run(self.db, {'op': 'quote', 'id': 'CASH-OFFER',
                                         'claim_id': 'C', 'at': 11,
                                         'cash_amount': 1000})
        self.assertEqual(offer['decision'], 'quoted')
        switched = resolution.run(self.db, {'op': 'elect_remedy', 'claim_id': 'C',
                                            'remedy': 'cash', 'at': 11})
        self.assertEqual(switched['selected_remedy'], 'cash')
        # Minute 14: no warehouse signature yet.
        self.assertEqual(resolution.stock_available(self.db), 0)
        # Minute 15: wrong unit arrives and bank value is actually credited.
        wrong = resolution.run(self.db, {'op': 'receive_replacement', 'id': 'WRONG-15',
                                         'claim_id': 'C', 'at': 15,
                                         'model': 'UNKNOWN', 'capacity': '128GB',
                                         'warranty_days': 30})
        self.assertEqual(wrong['decision'], 'rejected')
        bank = resolution.run(self.db, {'op': 'bank_receipt', 'id': 'BANK-15',
                                        'claim_id': 'C', 'at': 15,
                                        'amount': 1000,
                                        'account_owner': 'Acme Manufacturing'})
        self.assertTrue(bank['cash_complete'])
        self.assertEqual(resolution.stock_available(self.db), 0)
        self.assertTrue(resolution.status(self.db, 'C')['exclusive_relief_intact'])

    def test_cross_buyer_refile_and_split_quotes_do_not_add_relief(self):
        other = resolution.run(self.db, {'op': 'bind_claim', 'claim_id': 'C',
                                         'contract_id': 'K',
                                         'fault_category': 'mainboard',
                                         'entitlement_id': 'E-n1',
                                         'buyer': 'buyer-2'})
        self.assertEqual(other['decision'], 'blocked')
        self.assertEqual(other['reason'], 'claim_binding_conflict')
        resolution.run(self.db, {'op': 'record_quote', 'id': 'Q2', 'claim_id': 'C',
                                 'cash_amount': 600})
        resolution.run(self.db, {'op': 'record_quote', 'id': 'Q3', 'claim_id': 'C',
                                 'cash_amount': 600})
        state = resolution.status(self.db, 'C')
        self.assertEqual(state['cash']['required'], 1000)
        self.assertEqual(self.db.execute(
            'SELECT COUNT(*) FROM warranty_quotes WHERE claim_id=?', ('C',)
        ).fetchone()[0], 3)

    def test_cash_path_leaves_old_unit_with_buyer(self):
        resolution.run(self.db, {'op': 'select_remedy', 'claim_id': 'C', 'remedy': 'cash'})
        result = resolution.run(self.db, {'op': 'retain_core', 'id': 'KEEP-CORE',
                                          'claim_id': 'C', 'at': 40})
        self.assertEqual(result['owner'], 'buyer')
        self.assertEqual(resolution.status(self.db, 'C')['core_owner'], 'buyer')

    def test_procurement_retry_is_idempotent_after_interruption(self):
        resolution.run(self.db, {'op': 'select_remedy', 'claim_id': 'C', 'remedy': 'cash'})
        resolution.run(self.db, {'op': 'bank_receipt', 'id': 'B', 'claim_id': 'C',
                                 'amount': 1000,
                                 'account_owner': 'Acme Manufacturing'})
        payload = {'op': 'create_purchase_order', 'id': 'PO-RETRY',
                   'claim_id': 'C', 'supplier': 'S2'}
        first = resolution.run(self.db, payload)
        second = resolution.run(self.db, payload)
        self.assertEqual(first['decision'], 'purchase_order_created')
        self.assertEqual(second['decision'], 'replay')
        arrival = {'op': 'receive_purchase', 'id': 'PR-RETRY', 'claim_id': 'C',
                   'purchase_order_id': 'PO-RETRY', 'model': 'MB-X2',
                   'capacity': '1TB', 'warranty_days': 365}
        resolution.run(self.db, arrival)
        retry = resolution.run(self.db, arrival)
        self.assertEqual(retry['decision'], 'replay')
        self.assertEqual(resolution.stock_available(self.db), 1)

    def test_source_label_cannot_bypass_purchase_or_exclusive_boundary(self):
        resolution.run(self.db, {'op': 'select_remedy', 'claim_id': 'C', 'remedy': 'cash'})
        resolution.run(self.db, {'op': 'bank_receipt', 'id': 'B', 'claim_id': 'C',
                                 'amount': 1000,
                                 'account_owner': 'Acme Manufacturing'})
        no_po = resolution.run(self.db, {'op': 'receive_purchase', 'id': 'FAKE-PO-RECEIPT',
                                         'claim_id': 'C', 'model': 'MB-X2',
                                         'capacity': '1TB', 'warranty_days': 365})
        self.assertEqual(no_po['reason'], 'unknown_purchase_order')
        spoofed = resolution.run(self.db, {'op': 'receive_replacement', 'id': 'SPOOF',
                                          'claim_id': 'C',
                                          'source_type': 'third_party_purchase',
                                          'source_id': 'PO-DOES-NOT-EXIST',
                                          'model': 'MB-X2', 'capacity': '1TB',
                                          'warranty_days': 365})
        self.assertIn(spoofed['decision'], ('blocked', 'rejected'))
        self.assertIn(spoofed['reason'], ('unknown_purchase_order', 'cash_remedy_completed'))
        self.assertEqual(resolution.stock_available(self.db), 0)

    def test_sign_then_accept_same_receipt_id_completes_inspection(self):
        resolution.run(self.db, {'op': 'elect_replacement', 'claim_id': 'C'})
        signed = resolution.sign_receipt(self.db, 'C', 'R-SIGN', 40)
        self.assertEqual(signed['decision'], 'signed')
        accepted = resolution.accept_replacement(
            self.db, 'C', 'R-SIGN', 41, 'MB-X2', '1TB', 365,
        )
        self.assertEqual(accepted['decision'], 'accepted')
        self.assertEqual(resolution.stock_available(self.db), 1)

    def test_forged_fault_time_cannot_select_inactive_contract(self):
        resolution.run(self.db, {'op': 'contract', 'id': 'LATE-K', 'vendor': 'V',
                                 'entitlement_id': 'E2', 'active_from': 50,
                                 'active_to': 60, 'categories': ['mainboard']})
        self.db.execute("""UPDATE warranty_claims
                          SET contract_id=NULL, entitlement_id=NULL, buyer=NULL,
                              fault_category=NULL, fault_at=NULL
                          WHERE id='C'""")
        result = resolution.run(self.db, {'op': 'bind', 'claim_id': 'C',
                                          'contract_id': 'LATE-K',
                                          'fault_category': 'mainboard',
                                          'entitlement_id': 'E2',
                                          'fault_at': 55})
        self.assertEqual(result['reason'], 'fault_time_conflict')

    def test_negative_or_pending_reversal_cannot_increase_cash(self):
        resolution.run(self.db, {'op': 'select_remedy', 'claim_id': 'C', 'remedy': 'cash'})
        pending = resolution.run(self.db, {'op': 'bank_receipt', 'id': 'P',
                                           'claim_id': 'C', 'amount': 100,
                                           'status': 'pending',
                                           'account_owner': 'Acme Manufacturing'})
        self.assertEqual(pending['status'], 'pending')
        blocked = resolution.run(self.db, {'op': 'reverse_bank_receipt',
                                           'reversal_id': 'REV-NEG',
                                           'receipt_id': 'P', 'amount': -50})
        self.assertEqual(blocked['reason'], 'only_settled_bank_receipt_can_be_reversed')

        resolution.run(self.db, {'op': 'bank_receipt', 'id': 'B', 'claim_id': 'C',
                                 'amount': 1000,
                                 'account_owner': 'Acme Manufacturing'})
        too_much = resolution.run(self.db, {'op': 'reverse_bank_receipt',
                                            'reversal_id': 'REV-BIG',
                                            'receipt_id': 'B', 'amount': 1001})
        self.assertEqual(too_much['reason'], 'reversal_exceeds_receipt')
        self.assertEqual(resolution.status(self.db, 'C')['cash']['net'], 1000)

    def test_power_loss_reopen_retry_appends_no_duplicate_settlement(self):
        payload = {'op': 'bank_receipt', 'id': 'B-POWER', 'claim_id': 'C',
                   'amount': 1000, 'at': 21,
                   'account_owner': 'Acme Manufacturing'}
        resolution.run(self.db, {'op': 'select_remedy', 'claim_id': 'C', 'remedy': 'cash'})
        self.assertEqual(resolution.run(self.db, payload)['decision'], 'settled')
        self.db.close()

        reopened = connect(self.path)
        retried = resolution.run(reopened, payload)
        self.assertEqual(retried['decision'], 'replay')
        self.assertEqual(resolution.status(reopened, 'C')['cash']['gross'], 1000)
        reopened.close()
        self.db = connect(self.path)

    def test_claim_letter_versions_are_append_only(self):
        first = resolution.run(self.db, {'op': 'send_claim_letter', 'id': 'LET',
                                         'claim_id': 'C', 'at': 18,
                                         'text': 'first'})
        second_version = resolution.run(self.db, {'op': 'send_claim_letter',
                                                  'id': 'LET', 'claim_id': 'C',
                                                  'version': 2, 'at': 19,
                                                  'text': 'corrected'})
        retry = resolution.run(self.db, {'op': 'send_claim_letter', 'id': 'LET',
                                         'claim_id': 'C', 'at': 18,
                                         'text': 'first'})
        self.assertEqual(first['decision'], 'sent')
        self.assertEqual(second_version['version'], 2)
        self.assertEqual(retry['decision'], 'replay')
        texts = [json.loads(r['payload_json'])['text']
                 for r in self.db.execute(
                     "SELECT payload_json FROM warranty_documents WHERE logical_id='LET' ORDER BY version"
                 )]
        self.assertEqual(texts, ['first', 'corrected'])

    def test_full_workflow_replays_without_divergence(self):
        resolution.run(self.db, {'op': 'select_remedy', 'claim_id': 'C', 'remedy': 'cash'})
        resolution.run(self.db, {'op': 'bank_receipt', 'id': 'B1', 'claim_id': 'C',
                                 'amount': 400, 'at': 21,
                                 'account_owner': 'Acme Manufacturing'})
        resolution.run(self.db, {'op': 'bank_receipt', 'id': 'B2', 'claim_id': 'C',
                                 'amount': 600, 'at': 22,
                                 'account_owner': 'Acme Manufacturing'})
        resolution.run(self.db, {'op': 'purchase_order', 'id': 'PO1', 'claim_id': 'C',
                                 'supplier': 'S2'})
        resolution.run(self.db, {'op': 'receive_purchase', 'id': 'PR1', 'claim_id': 'C',
                                 'purchase_order_id': 'PO1', 'model': 'MB-X2',
                                 'capacity': '1TB', 'warranty_days': 365})
        result = replay(self.path, {
            'inventory': inventory, 'wave': wave, 'warranty': warranty,
            'warranty_resolution': resolution,
        })
        self.assertTrue(result['verified'], result['divergences'])


if __name__ == '__main__':
    unittest.main()
