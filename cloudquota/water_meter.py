"""Independent intake, return and drain meter samples."""
from .store import one,transaction

def sample(db,sample_id,circuit,at,intake,returned,drained):
    db.execute('CREATE TABLE IF NOT EXISTS water_samples(id TEXT PRIMARY KEY,circuit TEXT,at INTEGER,intake INTEGER,returned INTEGER,drained INTEGER)')
    if min(at,intake,returned,drained)<0:return 'invalid_sample'
    with transaction(db):
        old=one(db,'SELECT * FROM water_samples WHERE id=?',(sample_id,))
        expected=(circuit,at,intake,returned,drained)
        if old:return 'replayed' if tuple(old[k] for k in ('circuit','at','intake','returned','drained'))==expected else 'sample_conflict'
        db.execute('INSERT INTO water_samples VALUES(?,?,?,?,?,?)',(sample_id,*expected))
        return 'captured'
