import tempfile
import unittest
from pathlib import Path
import cloudlab
from cloudlab.store import connect,report,replay
from cloudlab import inventory,wave,migration

class Workflows(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.db=connect(str(Path(self.tmp.name)/'x.sqlite'))
    def tearDown(self):self.db.close();self.tmp.cleanup()
    def base(self):
        inventory.run(self.db,dict(op='node',id='n',architecture='amd64',features=['cgroup2'],generation=1,observed_at=10,version='1.29'))
        inventory.run(self.db,dict(op='verify',id='n',now=12,max_age=10,architecture='amd64',features=['cgroup2'],deprecated_api='old/v1'))
    def test_inventory_staleness_and_usage(self):
        self.base()
        self.assertEqual(inventory.run(self.db,dict(op='verify',id='n',now=100,max_age=10,architecture='amd64',features=['cgroup2'],deprecated_api='old/v1'))['reason'],'stale_observation')
        inventory.run(self.db,dict(op='usage',id='u',workload='web',api='old/v1',generation=1))
        self.assertEqual(inventory.run(self.db,dict(op='verify',id='n',now=12,max_age=10,architecture='amd64',features=['cgroup2'],deprecated_api='old/v1'))['reason'],'deprecated_api')
    def test_wave_budget_and_dependency(self):
        self.base();wave.run(self.db,dict(op='plan',id='w',target='1.30',max_unavailable=1))
        self.assertEqual(wave.run(self.db,dict(op='release',id='w',transition='t',node='n',zone='z',zone_budget=1))['decision'],'released')
        self.assertEqual(wave.run(self.db,dict(op='release',id='w',transition='t2',node='n',zone='z',zone_budget=1))['reason'],'availability_budget')
        wave.run(self.db,dict(op='plan',id='next',target='1.31',parent='w',max_unavailable=1))
        self.assertEqual(wave.run(self.db,dict(op='release',id='next',transition='t3',node='n',zone='z',zone_budget=1))['reason'],'parent_incomplete')
        self.assertEqual(wave.run(self.db,dict(op='finish',id='w',transition='t'))['decision'],'complete')
        self.assertEqual(self.db.execute("SELECT version FROM nodes WHERE id='n'").fetchone()[0],'1.30')
    def test_migration_freeze_and_rollback(self):
        self.base();wave.run(self.db,dict(op='plan',id='w',target='1.30',max_unavailable=1))
        self.assertEqual(migration.run(self.db,dict(op='verify',id='m',workload='web',old_api='old/v1',new_api='new/v2',expected='healthy',observed='broken'))['decision'],'rejected')
        self.assertEqual(wave.run(self.db,dict(op='release',id='w',transition='t',node='n',zone='z',zone_budget=1))['reason'],'migration_failed')
        self.assertEqual(migration.run(self.db,dict(op='anchor',id='a',migration='m',node_version='1.29',config_version='cfg1'))['decision'],'ready')
        self.assertEqual(migration.run(self.db,dict(op='rollback',id='a'))['decision'],'rolled_back')
        self.assertTrue(any(x['event']=='rollback' for x in report(self.db)))

    def test_evidence_replays_migration_and_wave(self):
        self.base();wave.run(self.db,dict(op='plan',id='w',target='1.30',max_unavailable=1))
        migration.run(self.db,dict(op='verify',id='m',workload='web',old_api='old/v1',new_api='new/v2',expected='healthy',observed='broken'))
        wave.run(self.db,dict(op='release',id='w',transition='t',node='n',zone='z',zone_budget=1))
        result=replay(str(Path(self.tmp.name)/'x.sqlite'),{'inventory':inventory,'wave':wave,'migration':migration})
        self.assertTrue(result['verified'],result['divergences'])
    def test_architecture_and_generation_conflicts(self):
        self.base()
        self.assertEqual(inventory.run(self.db,dict(op='node',id='n',architecture='arm64',features=[],generation=1,observed_at=11,version='1.29'))['reason'],'stale_generation')
        self.assertEqual(inventory.run(self.db,dict(op='verify',id='n',now=13,max_age=10,architecture='amd64',features=['cgroup2','gpu'],deprecated_api='old/v1'))['reason'],'missing_capability')
    def test_wave_requires_verified_node(self):
        inventory.run(self.db,dict(op='node',id='n',architecture='amd64',features=['cgroup2'],generation=1,observed_at=10,version='1.29'))
        wave.run(self.db,dict(op='plan',id='w',target='1.30',max_unavailable=1))
        self.assertEqual(wave.run(self.db,dict(op='release',id='w',transition='t',node='n',zone='z',zone_budget=1))['reason'],'unverified_node')
    def test_wave_retry_resumes_without_consuming_budget_twice(self):
        self.base();wave.run(self.db,dict(op='plan',id='w',target='1.30',max_unavailable=1))
        payload=dict(op='release',id='w',transition='t',node='n',zone='z',zone_budget=1)
        self.assertEqual(wave.run(self.db,payload)['decision'],'released')
        self.assertEqual(wave.run(self.db,payload)['decision'],'reused')
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM transitions WHERE id='t'").fetchone()[0],1)
    def test_unmigrated_api_blocks_wave_after_new_scan(self):
        self.base();wave.run(self.db,dict(op='plan',id='w',target='1.30',max_unavailable=1))
        inventory.run(self.db,dict(op='usage',id='u',workload='web',api='old/v1',generation=1))
        self.assertEqual(wave.run(self.db,dict(op='release',id='w',transition='t',node='n',zone='z',zone_budget=1))['reason'],'deprecated_api_pending')
    def test_migration_clears_deprecated_api_and_unfreezes_wave(self):
        self.base();inventory.run(self.db,dict(op='usage',id='u',workload='web',api='old/v1',generation=1))
        wave.run(self.db,dict(op='plan',id='w',target='1.30',max_unavailable=1))
        self.assertEqual(inventory.run(self.db,dict(op='verify',id='n',now=13,max_age=10,architecture='amd64',features=['cgroup2'],deprecated_api='old/v1'))['reason'],'deprecated_api')
        migration.run(self.db,dict(op='verify',id='m',workload='web',old_api='old/v1',new_api='new/v2',expected='healthy',observed='healthy'))
        self.assertEqual(wave.run(self.db,dict(op='release',id='w',transition='t',node='n',zone='z',zone_budget=1))['decision'],'released')
    def test_incomplete_rollback_anchor_is_rejected(self):
        self.base();migration.run(self.db,dict(op='verify',id='m',workload='web',old_api='old/v1',new_api='new/v2',expected='healthy',observed='broken'))
        self.assertEqual(migration.run(self.db,dict(op='anchor',id='a',migration='m',node_version='1.29',config_version=''))['reason'],'incomplete_anchor')
        self.assertEqual(migration.run(self.db,dict(op='rollback',id='a'))['reason'],'missing_anchor')

print('imported_module_file=',cloudlab.__file__)
if __name__=='__main__':unittest.main()
