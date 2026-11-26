import json
import tempfile
import unittest
from pathlib import Path

from cloudlab.store import connect, replay
from cloudlab import inventory, wave, migration, object_custody
from cloudlab.object_custody import CustodyLedger
from cloudlab import compat

OLD = {'replicas': 3, 'minAvailable': 2, 'selector': {'app': 'web'}}
GOOD = {'desiredReplicas': 3, 'availability': {'minimumReady': 2}, 'selector': {'app': 'web'}}


class CustomerStateRollbackTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / 'custody.sqlite')
        self.db = connect(self.path)
        inventory.run(self.db, {
            'op': 'node', 'id': 'n', 'architecture': 'amd64', 'features': ['cgroup2'],
            'generation': 1, 'observed_at': 10, 'version': '1', 'zone': 'z',
        })
        inventory.run(self.db, {
            'op': 'usage', 'id': 'u', 'workload': 'web', 'api': 'old/v1', 'generation': 1,
        })
        migration.run(self.db, {'op': 'config', 'workload': 'web', 'version': 'cfg1'})
        result = migration.run(self.db, {
            'op': 'verify', 'id': 'm', 'workload': 'web',
            'old_api': 'old/v1', 'new_api': 'new/v2',
            'old_manifest': OLD, 'new_manifest': GOOD,
        })
        self.assertEqual(result['decision'], 'verified')
        result = migration.run(self.db, {
            'op': 'anchor', 'id': 'a', 'migration': 'm', 'node': 'n',
            'node_version': '1', 'config_version': 'cfg1',
        })
        self.assertEqual(result['decision'], 'ready')

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def upgrade_node(self, version='2'):
        # Drive the version change through recorded workflows so evidence
        # replay reconstructs the same actual controller version.
        inventory.run(self.db, {
            'op': 'verify', 'id': 'n', 'now': 12, 'max_age': 100,
            'architecture': 'amd64', 'features': ['cgroup2'], 'deprecated_api': 'old/v1',
        })
        wave.run(self.db, {'op': 'plan', 'id': 'w', 'target': version, 'max_unavailable': 1})
        released = wave.run(self.db, {
            'op': 'release', 'id': 'w', 'transition': 't', 'node': 'n', 'zone': 'z',
        })
        self.assertEqual(released['decision'], 'released', released)
        wave.run(self.db, {
            'op': 'probe', 'id': 'w', 'transition': 't', 'probe': 'p',
            'generation': 1, 'target': version, 'at': 13, 'healthy': True,
        })
        finished = wave.run(self.db, {'op': 'finish', 'id': 'w', 'transition': 't'})
        self.assertEqual(finished['decision'], 'complete', finished)

    def write_blue(self, command_id='c18', **extra):
        payload = {
            'op': 'customer_write', 'workload': 'web', 'command_id': command_id,
            'operation': 'create', 'at': 19,
            'object': {'name': 'blue', 'replicas': 3, 'region_retention_days': 365},
            'notification_id': 'notif-blue',
        }
        payload.update(extra)
        return migration.run(self.db, payload)

    def test_field_contract_distinguishes_expressible_and_irreversible(self):
        scope = compat.object_contract()
        self.assertEqual(scope['expressible_fields'], ['name', 'replicas'])
        reversible = compat.classify_object({'name': 'green', 'replicas': 2}, scope)
        self.assertTrue(reversible['expressible'])
        nested = compat.classify_object({
            'metadata': {'name': 'blue', 'uid': 'uid-blue'},
            'spec': {'replicas': 3, 'regionRetention': {'days': 365}},
        }, scope)
        self.assertFalse(nested['expressible'])
        self.assertIn('spec.regionRetention.days', nested['violations'][0]['path'])
        with self.assertRaises(compat.IrreversibleField):
            compat.to_old_object({'name': 'blue', 'retention_days': 365}, scope)

    def test_anchor_binds_raw_bytes_generation_object_version_and_rules(self):
        migration.run(self.db, {'op': 'config', 'workload': 'rawweb', 'version': 'cfgraw'})
        migration.run(self.db, {
            'op': 'verify', 'id': 'mraw', 'workload': 'rawweb',
            'old_api': 'old/v1', 'new_api': 'new/v2',
            'old_manifest': OLD, 'new_manifest': GOOD,
            'old_config_raw': '{"fixed": "original bytes é"}',
        })
        ready = migration.run(self.db, {
            'op': 'anchor', 'id': 'araw', 'migration': 'mraw', 'node': 'n',
            'node_version': '1', 'config_version': 'cfgraw',
        })
        self.assertEqual(ready['decision'], 'ready')
        row = self.db.execute('SELECT * FROM custody_anchors WHERE anchor_id=?', ('araw',)).fetchone()
        contract = self.db.execute('SELECT * FROM custody_contracts WHERE migration_id=?', ('mraw',)).fetchone()
        self.assertEqual(row['old_config_bytes'], '{"fixed": "original bytes é"}'.encode('utf-8'))
        self.assertEqual(row['old_config_hash'], contract['old_config_hash'])
        self.assertEqual(row['node_generation'], 1)
        self.assertEqual(row['object_version'], 0)
        rules = json.loads(row['rules_json'])
        self.assertEqual(rules['version'], compat.CONVERSION_RULES_VERSION)

        bad_generation = migration.run(self.db, {
            'op': 'anchor', 'id': 'badgen', 'migration': 'm', 'node': 'n',
            'node_version': '1', 'config_version': 'cfg1', 'node_generation': 99,
        })
        self.assertEqual(bad_generation['reason'], 'anchor_version_mismatch')

        self.write_blue('c18')
        bad_version = migration.run(self.db, {
            'op': 'anchor', 'id': 'badobj', 'migration': 'm', 'node': 'n',
            'node_version': '1', 'config_version': 'cfg1', 'object_version': 0,
        })
        self.assertEqual(bad_version['decision'], 'blocked')
        self.assertEqual(bad_version['reason'], 'object_version_mismatch')

    def test_irreversible_confirmed_object_forbids_false_rolled_back(self):
        self.upgrade_node()
        confirmed = self.write_blue()
        self.assertEqual(confirmed['decision'], 'confirmed')
        self.assertIn('region_retention_days', confirmed['untranslatable_fields'])

        first = migration.run(self.db, {'op': 'rollback', 'id': 'a', 'at': 20})
        self.assertEqual(first['decision'], 'forward_fix_required')
        self.assertFalse(first['rolled_back'])
        self.assertTrue(first['not_rolled_back'])
        self.assertTrue(first['apply_request']['recovery_path'] == 'forward_compat')
        # Safe assessment freezes the new write entrance.
        blocked = self.write_blue('c19-retry-after-freeze')
        self.assertEqual(blocked['decision'], 'blocked')
        self.assertEqual(blocked['reason'], 'writes_frozen')
        # Infrastructure rows were not physically reverted by the unsafe path.
        self.assertEqual(self.db.execute('SELECT version FROM nodes WHERE id=?', ('n',)).fetchone()[0], '2')
        self.assertEqual(self.db.execute("SELECT state FROM migrations WHERE id='m'").fetchone()[0],
                         'forward_fix_required')

        approved = dict(first['apply_request'])
        approved.update({
            'approval_id': 'ops-approval-42',
            'correction_notification_id': 'corr-blue-1',
            'corrects_notification_id': 'notif-blue',
        })
        repaired = migration.run(self.db, approved)
        self.assertEqual(repaired['decision'], 'forward_fix_applied')
        self.assertFalse(repaired['rolled_back'])
        self.assertEqual(repaired['storage_format'], 'new/v2')
        self.assertEqual(repaired['actual_controller_version'], '2')
        self.assertEqual(self.db.execute('SELECT version FROM nodes WHERE id=?', ('n',)).fetchone()[0], '2')
        config = self.db.execute('SELECT version,state FROM workload_configs WHERE workload=?', ('web',)).fetchone()
        self.assertEqual(config['state'], 'compat_active')
        self.assertNotEqual(config['version'], 'cfg1')
        self.assertEqual(self.db.execute("SELECT state FROM api_usage WHERE id='u'").fetchone()[0],
                         'compat_served')

        old_view = migration.run(self.db, {'op': 'old_read', 'workload': 'web', 'name': 'blue'})
        self.assertEqual(old_view['object'], {'name': 'blue', 'replicas': 3})
        self.assertNotIn('region_retention_days', old_view['object'])
        new_view = CustodyLedger(self.db).read_new('web', name='blue')
        self.assertEqual(new_view['object']['region_retention_days'], 365)
        self.assertEqual(new_view['version'], 1)

        # Old-client contract write succeeds through the facade and must not
        # erase the extension that old clients cannot see.
        old_write = migration.run(self.db, {
            'op': 'old_write', 'workload': 'web', 'command_id': 'old-update-1',
            'operation': 'update', 'name': 'blue',
            'object': {'name': 'blue', 'replicas': 5},
            'fence_token': repaired['write_fence']['token'],
        })
        self.assertEqual(old_write['decision'], 'confirmed')
        self.assertEqual(migration.run(self.db, {'op': 'old_read', 'workload': 'web', 'name': 'blue'})['object'],
                         {'name': 'blue', 'replicas': 5})
        new_view = CustodyLedger(self.db).read_new('web', name='blue')
        self.assertEqual(new_view['object']['replicas'], 5)
        self.assertEqual(new_view['object']['region_retention_days'], 365)

        corrections = self.db.execute('SELECT COUNT(*) FROM custody_corrections').fetchone()[0]
        self.assertGreaterEqual(corrections, 1)
        notes = self.db.execute('SELECT notification_id,state,corrects_notification_id FROM custody_notifications ORDER BY notification_id').fetchall()
        note_ids = {r[0]: r for r in notes}
        self.assertEqual(note_ids['notif-blue']['state'], 'sent')
        self.assertEqual(note_ids['corr-blue-1']['corrects_notification_id'], 'notif-blue')

        # Repeating the forward receipt must not publish a second repair/fence.
        repeated = migration.run(self.db, {'op': 'rollback', 'id': 'a', 'recovery_path': 'forward_compat'})
        self.assertEqual(repeated['decision'], 'forward_fix_applied')
        self.assertTrue(repeated['reused'])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM custody_compat_repairs').fetchone()[0], 1)

        result = replay(self.path, {'inventory': inventory, 'wave': wave, 'migration': migration})
        self.assertTrue(result['verified'], result['divergences'])

    def test_reversible_write_physical_rollback_retry_and_notification_are_exact_once(self):
        self.upgrade_node()
        payload = {
            'op': 'customer_write', 'workload': 'web', 'command_id': 'c-green',
            'operation': 'create', 'at': 18,
            'object': {'name': 'green', 'replicas': 2},
            'notification_id': 'notif-green',
        }
        first = migration.run(self.db, payload)
        second = migration.run(self.db, dict(payload, at=19))
        self.assertFalse(first['reused'])
        self.assertTrue(second['reused'])
        self.assertEqual(first['ack_id'], second['ack_id'])
        self.assertEqual(first['seq'], second['seq'])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM custody_commands').fetchone()[0], 1)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM custody_acks').fetchone()[0], 1)

        result = migration.run(self.db, {'op': 'rollback', 'id': 'a', 'approval_id': 'cust-ok'})
        self.assertEqual(result['decision'], 'rolled_back')
        self.assertTrue(result['physical_rollback'])
        self.assertEqual(result['actual_controller_version'], '1')
        self.assertEqual(result['object_set'], [{'name': 'green', 'replicas': 2}])
        self.assertEqual(self.db.execute('SELECT version FROM nodes WHERE id=?', ('n',)).fetchone()[0], '1')
        cfg = self.db.execute('SELECT version,state FROM workload_configs WHERE workload=?', ('web',)).fetchone()
        self.assertEqual((cfg[0], cfg[1]), ('cfg1', 'restored'))
        self.assertEqual(self.db.execute("SELECT state FROM api_usage WHERE id='u'").fetchone()[0], 'observed')
        self.assertEqual(CustodyLedger(self.db).read_old('web', 'green'),
                         {'name': 'green', 'replicas': 2})
        self.assertEqual(self.db.execute("SELECT object_uid FROM custody_objects WHERE name='green'").fetchone()[0],
                         'uid:green')
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM custody_object_versions WHERE object_uid='uid:green'").fetchone()[0],
                         1)
        self.assertEqual(self.db.execute("SELECT state FROM custody_notifications WHERE notification_id='notif-green'").fetchone()[0],
                         'sent')

        repeated = migration.run(self.db, {'op': 'rollback', 'id': 'a'})
        self.assertEqual(repeated['decision'], 'rolled_back')
        self.assertTrue(repeated['reused'])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM custody_commands').fetchone()[0], 1)
        self.assertEqual(len(CustodyLedger(self.db).list_old('web')), 1)

        result = replay(self.path, {'inventory': inventory, 'wave': wave, 'migration': migration})
        self.assertTrue(result['verified'], result['divergences'])

    def test_causal_create_update_delete_preserves_order_and_absence(self):
        self.upgrade_node()
        commands = [
            ('c1', 'create', {'name': 'orange', 'replicas': 1}),
            ('c2', 'update', {'name': 'orange', 'replicas': 4}),
            ('c3', 'delete', {'name': 'orange'}),
        ]
        for cid, operation, obj in commands:
            result = migration.run(self.db, {
                'op': 'customer_write', 'workload': 'web', 'command_id': cid,
                'operation': operation, 'object': obj,
            })
            self.assertEqual(result['decision'], 'confirmed', result)
        # Duplicate delivery of the update does not apply it twice.
        duplicate = migration.run(self.db, {
            'op': 'customer_write', 'workload': 'web', 'command_id': 'c2',
            'operation': 'update', 'object': {'name': 'orange', 'replicas': 4},
        })
        self.assertTrue(duplicate['reused'])
        self.assertEqual([r[0] for r in self.db.execute('SELECT command_id FROM custody_commands ORDER BY seq')],
                         ['c1', 'c2', 'c3'])
        self.assertEqual(self.db.execute('SELECT current_version FROM custody_objects WHERE name=?', ('orange',)).fetchone()[0], 3)

        assessment = migration.run(self.db, {'op': 'assess_rollback', 'id': 'a'})
        self.assertTrue(assessment['lossless'])
        self.assertEqual([s['op'] for s in assessment['steps']], ['create', 'update', 'delete'])

        rolled = migration.run(self.db, {'op': 'rollback', 'id': 'a'})
        self.assertEqual(rolled['decision'], 'rolled_back')
        self.assertEqual(rolled['object_set'], [])
        self.assertIsNone(CustodyLedger(self.db).read_old('web', 'orange'))
        self.assertEqual(self.db.execute("SELECT state FROM custody_objects WHERE name='orange'").fetchone()[0],
                         'deleted')
        result = replay(self.path, {'inventory': inventory, 'wave': wave, 'migration': migration})
        self.assertTrue(result['verified'], result['divergences'])

    def test_write_fences_reject_stale_new_replica_and_allow_one_committer(self):
        fence = migration.run(self.db, {'op': 'write_fence', 'workload': 'dual'})
        token_new = fence['fence']['token']
        ok = migration.run(self.db, {
            'op': 'customer_write', 'workload': 'dual', 'command_id': 'd1',
            'operation': 'create', 'fence_token': token_new,
            'object': {'name': 'd1', 'replicas': 1},
        })
        self.assertEqual(ok['decision'], 'confirmed')
        bad = migration.run(self.db, {
            'op': 'customer_write', 'workload': 'dual', 'command_id': 'd2',
            'operation': 'create', 'fence_token': 'wrong-token',
            'object': {'name': 'd2', 'replicas': 1},
        })
        self.assertEqual(bad['reason'], 'write_fence_violation')

        handoff = migration.run(self.db, {
            'op': 'handoff_write_fence', 'workload': 'dual', 'to_role': 'old',
        })
        self.assertEqual(handoff['decision'], 'write_fence_handed_off')
        old_token = handoff['token']
        stale_new = migration.run(self.db, {
            'op': 'customer_write', 'workload': 'dual', 'command_id': 'd3-stale',
            'operation': 'create', 'fence_token': token_new,
            'object': {'name': 'd3', 'replicas': 1},
        })
        self.assertEqual(stale_new['decision'], 'blocked')
        self.assertIn(stale_new['reason'], {'write_fence_violation', 'stale_fence_epoch'})
        old_ok = migration.run(self.db, {
            'op': 'old_write', 'workload': 'dual', 'command_id': 'd3-old',
            'name': 'd3', 'fence_token': old_token,
            'object': {'name': 'd3', 'replicas': 2},
        })
        self.assertEqual(old_ok['decision'], 'confirmed')
        self.assertEqual(CustodyLedger(self.db).read_old('dual', 'd3'), {'name': 'd3', 'replicas': 2})

    def test_power_loss_after_handoff_resumes_to_same_object_set(self):
        migration.run(self.db, {
            'op': 'customer_write', 'workload': 'web', 'command_id': 'power-1',
            'operation': 'create', 'object': {'name': 'steady', 'replicas': 3},
            'client_request_id': 'offline-retry-1',
        })
        staged = migration.run(self.db, {'op': 'rollback_handoff', 'id': 'a'})
        self.assertEqual(staged['decision'], 'handoff_ready')
        self.assertEqual(self.db.execute("SELECT state FROM rollbacks WHERE id='a'").fetchone()[0], 'handoff')
        self.db.close()

        # Simulate process/power loss and reopen the same durable file.
        self.db = connect(self.path)
        resumed = migration.run(self.db, {'op': 'rollback', 'id': 'a'})
        self.assertEqual(resumed['decision'], 'rolled_back')
        self.assertEqual(resumed['object_set'], [{'name': 'steady', 'replicas': 3}])
        self.assertEqual(self.db.execute('SELECT version FROM nodes WHERE id=?', ('n',)).fetchone()[0], '1')
        self.db.close()

        self.db = connect(self.path)
        retried = migration.run(self.db, {'op': 'rollback', 'id': 'a'})
        self.assertEqual(retried['decision'], 'rolled_back')
        self.assertTrue(retried['reused'])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM custody_commands').fetchone()[0], 1)
        self.assertEqual(CustodyLedger(self.db).list_old('web'), [{'name': 'steady', 'replicas': 3}])

        result = replay(self.path, {'inventory': inventory, 'wave': wave, 'migration': migration})
        self.assertTrue(result['verified'], result['divergences'])

    def test_anchor_baseline_and_confirmed_new_write_restore_together(self):
        migration.run(self.db, {'op': 'config', 'workload': 'baseweb', 'version': 'cfg-base'})
        migration.run(self.db, {
            'op': 'verify', 'id': 'mbase', 'workload': 'baseweb',
            'old_api': 'old/v1', 'new_api': 'new/v2', 'old_manifest': OLD, 'new_manifest': GOOD,
        })
        anchored = migration.run(self.db, {
            'op': 'anchor', 'id': 'abase', 'migration': 'mbase', 'node': 'n',
            'node_version': '1', 'config_version': 'cfg-base',
            'baseline_objects': [{'name': 'preexisting', 'replicas': 1}],
        })
        self.assertEqual(anchored['decision'], 'ready')
        migration.run(self.db, {
            'op': 'customer_write', 'workload': 'baseweb', 'command_id': 'base-new',
            'operation': 'create', 'object': {'name': 'later', 'replicas': 2},
        })
        rolled = migration.run(self.db, {'op': 'rollback', 'id': 'abase'})
        self.assertEqual(rolled['decision'], 'rolled_back')
        self.assertEqual(
            sorted(rolled['object_set'], key=lambda o: o['name']),
            [{'name': 'later', 'replicas': 2}, {'name': 'preexisting', 'replicas': 1}],
        )
        self.assertEqual(CustodyLedger(self.db).read_old('baseweb', 'preexisting'),
                         {'name': 'preexisting', 'replicas': 1})

    def test_anchor_auto_snapshots_existing_old_store_without_payload_objects(self):
        # Seed the live old store first, then anchor without repeating objects.
        seeded = CustodyLedger(self.db).seed_object({
            'workload': 'autosnap', 'object': {'name': 'already-there', 'replicas': 1},
        })
        self.assertEqual(seeded['decision'], 'observed')
        migration.run(self.db, {'op': 'config', 'workload': 'autosnap', 'version': 'cfg-auto'})
        migration.run(self.db, {
            'op': 'verify', 'id': 'mauto', 'workload': 'autosnap',
            'old_api': 'old/v1', 'new_api': 'new/v2', 'old_manifest': OLD, 'new_manifest': GOOD,
        })
        ready = migration.run(self.db, {
            'op': 'anchor', 'id': 'aauto', 'migration': 'mauto', 'node': 'n',
            'node_version': '1', 'config_version': 'cfg-auto',
        })
        self.assertEqual(ready['decision'], 'ready')
        count = self.db.execute(
            'SELECT COUNT(*) FROM custody_baseline_objects WHERE anchor_id=?', ('aauto',)
        ).fetchone()[0]
        self.assertEqual(count, 1)
        rolled = migration.run(self.db, {'op': 'rollback', 'id': 'aauto'})
        self.assertEqual(rolled['decision'], 'rolled_back')
        self.assertEqual(rolled['object_set'], [{'name': 'already-there', 'replicas': 1}])

    def test_repeated_handoff_keeps_same_fence_token(self):
        first = migration.run(self.db, {'op': 'rollback_handoff', 'id': 'a'})
        self.assertEqual(first['decision'], 'handoff_ready')
        second = migration.run(self.db, {'op': 'rollback_handoff', 'id': 'a'})
        self.assertEqual(second['decision'], 'handoff_ready')
        self.assertTrue(second['reused'])
        self.assertEqual(first['write_fence']['epoch'], second['write_fence']['epoch'])
        self.assertEqual(first['write_fence']['token'], second['write_fence']['token'])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM custody_handoffs').fetchone()[0], 1)
        # The original token remains the sole committer credential.
        write = migration.run(self.db, {
            'op': 'old_write', 'workload': 'web', 'command_id': 'after-handoff-retry',
            'name': 'hz', 'fence_token': first['write_fence']['token'],
            'object': {'name': 'hz', 'replicas': 1},
        })
        self.assertEqual(write['decision'], 'confirmed')
        replayed = replay(self.path, {'inventory': inventory, 'migration': migration})
        self.assertTrue(replayed['verified'], replayed['divergences'])

    def test_ack_lost_after_commit_is_recovered_by_reopen_and_retry(self):
        payload = {
            'op': 'customer_write', 'workload': 'web', 'command_id': 'lost-response',
            'operation': 'create', 'object': {'name': 'durable', 'replicas': 3},
        }
        first = migration.run(self.db, payload)
        self.assertEqual(first['decision'], 'confirmed')
        ack_id = first['ack_id']
        self.db.close()

        self.db = connect(self.path)
        retry = migration.run(self.db, payload)
        self.assertTrue(retry['reused'])
        self.assertEqual(retry['ack_id'], ack_id)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM custody_objects').fetchone()[0], 1)
        rolled = migration.run(self.db, {'op': 'rollback', 'id': 'a'})
        self.assertEqual(rolled['decision'], 'rolled_back')
        self.assertEqual(rolled['object_set'], [{'name': 'durable', 'replicas': 3}])

    def test_offline_retry_with_client_request_id_is_one_effect(self):
        payload = {
            'op': 'customer_write', 'workload': 'web', 'command_id': 'network-call-1',
            'client_request_id': 'client-uuid-1', 'operation': 'create',
            'object': {'name': 'retry-me', 'replicas': 1},
        }
        self.assertEqual(migration.run(self.db, payload)['decision'], 'confirmed')
        retry = migration.run(self.db, payload)
        self.assertTrue(retry['reused'])
        conflict = migration.run(self.db, dict(payload, command_id='different-command',
                                               object={'name': 'changed', 'replicas': 9}))
        self.assertEqual(conflict['decision'], 'blocked')
        self.assertEqual(conflict['reason'], 'idempotency_key_conflict')


if __name__ == '__main__':
    unittest.main()
