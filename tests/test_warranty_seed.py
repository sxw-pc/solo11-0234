import tempfile,unittest
from pathlib import Path
from cloudlab.store import connect
from cloudlab import inventory,wave,warranty
class WarrantySeedTest(unittest.TestCase):
    def test_failed_probe_opens_one_draft_claim(self):
        with tempfile.TemporaryDirectory() as d:
            db=connect(str(Path(d)/'seed.sqlite'))
            inventory.run(db,{'op':'node','id':'n1','architecture':'amd64','features':['cgroup2'],'generation':1,'observed_at':10,'version':'1.29','zone':'z1'})
            inventory.run(db,{'op':'verify','id':'n1','now':12,'max_age':10,'architecture':'amd64','features':['cgroup2'],'deprecated_api':'old/v1'})
            wave.run(db,{'op':'plan','id':'w','target':'1.30','max_unavailable':1})
            wave.run(db,{'op':'release','id':'w','transition':'t','node':'n1','now':13})
            self.assertEqual(warranty.open_claim(db,'c','t','vendor')['reason'],'no_failed_probe')
            wave.run(db,{'op':'probe','id':'w','transition':'t','probe':'p','generation':1,'target':'1.30','at':14,'healthy':False})
            self.assertEqual(warranty.open_claim(db,'c','t','vendor')['decision'],'draft')
            self.assertEqual(warranty.open_claim(db,'c','t','vendor')['decision'],'replay')
            self.assertEqual(db.execute('SELECT state FROM warranty_claims').fetchone()[0],'draft')
            db.close()
