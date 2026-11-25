"""Controller manifest is separate from replica bytes."""
from .store import one,transaction

def record(db,manifest_id,volume,block,epoch,version,digest,controller,at):
    db.execute('CREATE TABLE IF NOT EXISTS volume_manifests(id TEXT PRIMARY KEY,volume TEXT,block_id TEXT,epoch INTEGER,version INTEGER,digest TEXT,controller TEXT,at INTEGER)')
    if min(epoch,version,at)<0:return 'invalid_manifest'
    with transaction(db):
        old=one(db,'SELECT * FROM volume_manifests WHERE id=?',(manifest_id,))
        expected=(volume,block,epoch,version,digest,controller,at)
        if old:return 'replayed' if tuple(old[k] for k in ('volume','block_id','epoch','version','digest','controller','at'))==expected else 'manifest_conflict'
        db.execute('INSERT INTO volume_manifests VALUES (?,?,?,?,?,?,?,?)',(manifest_id,*expected))
        return 'captured'
