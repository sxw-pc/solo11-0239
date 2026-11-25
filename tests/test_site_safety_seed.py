import tempfile,unittest
from cloudquota import site_access,site_permit,site_hazard
from cloudquota.store import open_db

class SiteSafetySeed(unittest.TestCase):
    def test_permit_presence_and_hazard_are_separate(self):
        with tempfile.TemporaryDirectory() as d:
            db=open_db(d+'/state.sqlite')
            try:
                self.assertEqual(site_permit.issue(db,'p','worker','room','inspection',10,30,'chief'),'issued')
                self.assertEqual(site_access.swipe(db,'s','worker','room','east',12,'in','reader-a'),'captured')
                self.assertEqual(site_hazard.sample(db,'h','room','gas-a',20,'gas',8),'captured')
                self.assertEqual(db.execute('SELECT COUNT(*) FROM door_swipes').fetchone()[0],1)
            finally:db.close()
