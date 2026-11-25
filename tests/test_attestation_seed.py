import tempfile,unittest
from cloudquota import attest,agent_command
from cloudquota.store import open_db

class AttestationSeed(unittest.TestCase):
    def test_quote_does_not_prove_command_origin(self):
        with tempfile.TemporaryDirectory() as d:
            db=open_db(d+'/state.sqlite')
            try:
                self.assertEqual(attest.quote(db,'q1','node-1','chip-a','nonce-1',8,'known',20,'issuer-x'),'captured')
                self.assertEqual(agent_command.receipt(db,'r1','node-1','chip-a','capacity-report',2,'ok',21),'captured')
                self.assertEqual(db.execute('SELECT COUNT(*) FROM device_quotes').fetchone()[0],1)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM agent_receipts').fetchone()[0],1)
            finally:db.close()
