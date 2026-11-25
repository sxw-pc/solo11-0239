"""Door observations do not assert physical evacuation."""
from .store import one,transaction

def swipe(db,receipt_id,person,zone,door,at,direction,reader):
    db.execute('CREATE TABLE IF NOT EXISTS door_swipes(id TEXT PRIMARY KEY,person TEXT,zone TEXT,door TEXT,at INTEGER,direction TEXT,reader TEXT)')
    if at<0 or direction not in ('in','out'):return 'invalid_swipe'
    with transaction(db):
        old=one(db,'SELECT * FROM door_swipes WHERE id=?',(receipt_id,))
        expected=(person,zone,door,at,direction,reader)
        if old:return 'replayed' if tuple(old[k] for k in ('person','zone','door','at','direction','reader'))==expected else 'swipe_conflict'
        db.execute('INSERT INTO door_swipes VALUES (?,?,?,?,?,?,?)',(receipt_id,*expected))
        return 'captured'
