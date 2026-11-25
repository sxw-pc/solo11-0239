"""Client receipt contains a digest but no replacement bytes."""
from .store import one,transaction

def receipt(db,receipt_id,customer,volume,block,version,digest,at):
    db.execute('CREATE TABLE IF NOT EXISTS volume_client_receipts(id TEXT PRIMARY KEY,customer TEXT,volume TEXT,block_id TEXT,version INTEGER,digest TEXT,at INTEGER)')
    if min(version,at)<0:return 'invalid_receipt'
    with transaction(db):
        old=one(db,'SELECT * FROM volume_client_receipts WHERE id=?',(receipt_id,))
        expected=(customer,volume,block,version,digest,at)
        if old:return 'replayed' if tuple(old[k] for k in ('customer','volume','block_id','version','digest','at'))==expected else 'receipt_conflict'
        db.execute('INSERT INTO volume_client_receipts VALUES (?,?,?,?,?,?,?)',(receipt_id,*expected))
        return 'captured'
