import hashlib,tempfile,unittest
from cloudquota import volume_copy,volume_manifest,volume_client
from cloudquota.store import open_db

class VolumeSeed(unittest.TestCase):
    def test_controller_replica_and_client_can_disagree(self):
        with tempfile.TemporaryDirectory() as d:
            db=open_db(d+'/state.sqlite')
            try:
                a=hashlib.sha256(b'a').hexdigest();b=hashlib.sha256(b'b').hexdigest()
                self.assertEqual(volume_copy.record(db,'c1','vol','blk','replica-1',2,7,b'a',20),'captured')
                self.assertEqual(volume_manifest.record(db,'m1','vol','blk',2,7,a,'controller',20),'captured')
                self.assertEqual(volume_client.receipt(db,'r1','tenant','vol','blk',7,b,21),'captured')
                self.assertNotEqual(db.execute('SELECT digest FROM volume_copies').fetchone()[0],db.execute('SELECT digest FROM volume_client_receipts').fetchone()[0])
            finally:db.close()
