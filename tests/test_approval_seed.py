import tempfile,unittest
from pathlib import Path
from cloudlab.store import connect
from cloudlab import risk_request,risk_sign
class ApprovalSeedTest(unittest.TestCase):
    def test_proposal_and_signatures_are_real_rows(self):
        with tempfile.TemporaryDirectory() as d:
            db=connect(str(Path(d)/'seed.sqlite'))
            self.assertEqual(risk_sign.sign(db,'s','r','A',12)['decision'],'missing_request')
            self.assertEqual(risk_request.propose(db,'r','w','Lin',1,2,10)['decision'],'draft')
            self.assertEqual(risk_sign.sign(db,'s','r','A',12)['decision'],'signed')
            self.assertEqual(risk_sign.sign(db,'s','r','A',12)['decision'],'replay')
            self.assertEqual(db.execute('SELECT count(*) FROM risk_signatures').fetchone()[0],1)
            db.close()
