"""Hazard samples are independent of badges and permits."""
from .store import one,transaction

def sample(db,sample_id,zone,sensor,at,kind,level):
    db.execute('CREATE TABLE IF NOT EXISTS hazard_samples(id TEXT PRIMARY KEY,zone TEXT,sensor TEXT,at INTEGER,kind TEXT,level INTEGER)')
    if at<0 or level<0:return 'invalid_sample'
    with transaction(db):
        old=one(db,'SELECT * FROM hazard_samples WHERE id=?',(sample_id,))
        expected=(zone,sensor,at,kind,level)
        if old:return 'replayed' if tuple(old[k] for k in ('zone','sensor','at','kind','level'))==expected else 'sample_conflict'
        db.execute('INSERT INTO hazard_samples VALUES (?,?,?,?,?,?)',(sample_id,*expected))
        return 'captured'
