"""Actuator receipts are not water-flow measurements."""
from .store import one,transaction

def receipt(db,receipt_id,circuit,valve,command,at,position):
    db.execute('CREATE TABLE IF NOT EXISTS valve_receipts(id TEXT PRIMARY KEY,circuit TEXT,valve TEXT,command TEXT,at INTEGER,position TEXT)')
    if at<0 or position not in ('open','closed','unknown'):return 'invalid_receipt'
    with transaction(db):
        old=one(db,'SELECT * FROM valve_receipts WHERE id=?',(receipt_id,))
        expected=(circuit,valve,command,at,position)
        if old:return 'replayed' if tuple(old[k] for k in ('circuit','valve','command','at','position'))==expected else 'receipt_conflict'
        db.execute('INSERT INTO valve_receipts VALUES(?,?,?,?,?,?)',(receipt_id,*expected))
        return 'captured'
