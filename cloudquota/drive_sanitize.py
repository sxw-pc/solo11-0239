"""A tool receipt is separate from physical or cryptographic proof."""
from .store import one,transaction

def receipt(db,receipt_id,drive,method,at,tool,status):
    db.execute('CREATE TABLE IF NOT EXISTS sanitize_receipts(id TEXT PRIMARY KEY,drive TEXT,method TEXT,at INTEGER,tool TEXT,status TEXT)')
    if at<0:return 'invalid_receipt'
    with transaction(db):
        old=one(db,'SELECT * FROM sanitize_receipts WHERE id=?',(receipt_id,))
        expected=(drive,method,at,tool,status)
        if old:return 'replayed' if tuple(old[k] for k in ('drive','method','at','tool','status'))==expected else 'receipt_conflict'
        db.execute('INSERT INTO sanitize_receipts VALUES (?,?,?,?,?,?)',(receipt_id,*expected))
        return 'captured'
