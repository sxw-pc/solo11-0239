"""Observed local-agent actions; not a proof of device origin."""
from .store import one,transaction

def receipt(db,receipt_id,node,device,command,generation,result,at):
    db.execute('CREATE TABLE IF NOT EXISTS agent_receipts(id TEXT PRIMARY KEY,node TEXT,device TEXT,command TEXT,generation INTEGER,result TEXT,at INTEGER)')
    if generation<0 or at<0:return 'invalid_receipt'
    with transaction(db):
        old=one(db,'SELECT * FROM agent_receipts WHERE id=?',(receipt_id,))
        expected=(node,device,command,generation,result,at)
        if old:return 'replayed' if tuple(old[k] for k in ('node','device','command','generation','result','at'))==expected else 'receipt_conflict'
        db.execute('INSERT INTO agent_receipts VALUES(?,?,?,?,?,?,?)',(receipt_id,*expected))
        return 'captured'
