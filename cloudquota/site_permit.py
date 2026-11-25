"""Work permit grants intent, not observed presence."""
from .store import one,transaction

def issue(db,permit_id,person,zone,work,valid_from,valid_until,issuer):
    db.execute('CREATE TABLE IF NOT EXISTS work_permits(id TEXT PRIMARY KEY,person TEXT,zone TEXT,work TEXT,valid_from INTEGER,valid_until INTEGER,issuer TEXT)')
    if valid_from<0 or valid_until<=valid_from:return 'invalid_permit'
    with transaction(db):
        old=one(db,'SELECT * FROM work_permits WHERE id=?',(permit_id,))
        expected=(person,zone,work,valid_from,valid_until,issuer)
        if old:return 'replayed' if tuple(old[k] for k in ('person','zone','work','valid_from','valid_until','issuer'))==expected else 'permit_conflict'
        db.execute('INSERT INTO work_permits VALUES (?,?,?,?,?,?,?)',(permit_id,*expected))
        return 'issued'
