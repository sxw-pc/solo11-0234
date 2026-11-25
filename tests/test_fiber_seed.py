import tempfile,unittest
from pathlib import Path
from cloudlab.store import connect
from cloudlab import fiber_map,fiber_trace,fiber_splice
class FiberSeedTest(unittest.TestCase):
    def test_equal_distance_branches_remain_distinct(self):
        with tempfile.TemporaryDirectory() as d:
            db=connect(str(Path(d)/'seed.sqlite'))
            fiber_map.register(db,'north','p',12,'shaft-n')
            self.assertEqual(fiber_trace.observe(db,'t1','p',12,8)['candidates'],['north'])
            fiber_map.register(db,'south','p',12,'shaft-s')
            self.assertEqual(fiber_trace.observe(db,'t2','p',12,8)['candidates'],['north','south'])
            self.assertEqual(fiber_splice.submit(db,'s1','north','worker')['decision'],'received')
            self.assertEqual(db.execute('SELECT count(*) FROM fiber_splices').fetchone()[0],1)
            db.close()
