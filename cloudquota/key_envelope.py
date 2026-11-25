"""Key envelopes may be shared by more than one drive generation."""
from .store import one,transaction

def record(db,record_id,key_id,drive,volume,epoch,wrap_site):
    db.execute('CREATE TABLE IF NOT EXISTS key_envelopes(id TEXT PRIMARY KEY,key_id TEXT,drive TEXT,volume TEXT,epoch INTEGER,wrap_site TEXT)')
    if epoch<0:return 'invalid_envelope'
    with transaction(db):
        old=one(db,'SELECT * FROM key_envelopes WHERE id=?',(record_id,))
        expected=(key_id,drive,volume,epoch,wrap_site)
        if old:return 'replayed' if tuple(old[k] for k in ('key_id','drive','volume','epoch','wrap_site'))==expected else 'envelope_conflict'
        db.execute('INSERT INTO key_envelopes VALUES (?,?,?,?,?,?)',(record_id,*expected))
        return 'captured'
