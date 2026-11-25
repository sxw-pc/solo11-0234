import tempfile,unittest
from pathlib import Path
from cloudlab.store import connect
from cloudlab import meter_capture,vendor_payable,tenant_charge
class FinanceSeedTest(unittest.TestCase):
    def test_page_real_payable_and_charge(self):
        with tempfile.TemporaryDirectory() as d:
            db=connect(str(Path(d)/'seed.sqlite'))
            lines=[{'host':'h1','tenant':'t1','minute':10,'unit_seconds':60},{'host':'h2','tenant':'t2','minute':10,'unit_seconds':30}]
            self.assertEqual(meter_capture.import_page(db,'p','vendor','digest',lines)['decision'],'imported')
            self.assertEqual(meter_capture.import_page(db,'p','vendor','digest',lines)['decision'],'replay')
            self.assertEqual(vendor_payable.close(db,'c','p')['unit_seconds'],90)
            self.assertEqual(tenant_charge.issue(db,'i','p','t1')['unit_seconds'],60)
            self.assertEqual(db.execute('select unit_seconds from vendor_payables').fetchone()[0],90)
            self.assertEqual(db.execute('select unit_seconds from tenant_charges').fetchone()[0],60)
            db.close()
