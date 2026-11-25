"""Replica observations do not establish customer-visible commit."""
import hashlib
from .store import one,transaction

def record(db,receipt_id,volume,block,replica,epoch,version,data,at):
    db.execute('CREATE TABLE IF NOT EXISTS volume_copies(id TEXT PRIMARY KEY,volume TEXT,block_id TEXT,replica TEXT,epoch INTEGER,version INTEGER,digest TEXT,data BLOB,at INTEGER)')
    if min(epoch,version,at)<0:return 'invalid_copy'
    digest=hashlib.sha256(data).hexdigest()
    with transaction(db):
        old=one(db,'SELECT * FROM volume_copies WHERE id=?',(receipt_id,))
        expected=(volume,block,replica,epoch,version,digest,data,at)
        if old:return 'replayed' if tuple(old[k] for k in ('volume','block_id','replica','epoch','version','digest','data','at'))==expected else 'copy_conflict'
        db.execute('INSERT INTO volume_copies VALUES (?,?,?,?,?,?,?,?,?)',(receipt_id,*expected))
        return 'captured'
