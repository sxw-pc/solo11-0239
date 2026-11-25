import tempfile,unittest
from cloudquota import drive_asset,drive_sanitize,key_envelope
from cloudquota.store import open_db

class DriveRetireSeed(unittest.TestCase):
    def test_success_receipt_does_not_cover_shared_key(self):
        with tempfile.TemporaryDirectory() as d:
            db=open_db(d+'/state.sqlite')
            try:
                self.assertEqual(drive_asset.attach(db,'a','drive-1','serial-1','replica-1','ctl',10),'captured')
                self.assertEqual(key_envelope.record(db,'k','key-1','drive-1','vol-1',2,'hsm'),'captured')
                self.assertEqual(drive_sanitize.receipt(db,'r','drive-1','crypto',20,'tool-1','success'),'captured')
                self.assertEqual(db.execute('SELECT COUNT(*) FROM key_envelopes').fetchone()[0],1)
            finally:db.close()
