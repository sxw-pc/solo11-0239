import tempfile,unittest
from cloudquota import water_meter,valve_log,site_hazard
from cloudquota.store import open_db

class WaterControlSeed(unittest.TestCase):
    def test_meter_valve_and_hazard_are_independent(self):
        with tempfile.TemporaryDirectory() as d:
            db=open_db(d+'/state.sqlite')
            try:
                self.assertEqual(water_meter.sample(db,'w1','loop-1',20,12,8,1),'captured')
                self.assertEqual(valve_log.receipt(db,'v1','loop-1','drain','close',20,'closed'),'captured')
                self.assertEqual(site_hazard.sample(db,'h1','drain-1','chem-1',20,'coolant',7),'captured')
                self.assertEqual(db.execute('SELECT intake-returned-drained FROM water_samples').fetchone()[0],3)
            finally:db.close()
