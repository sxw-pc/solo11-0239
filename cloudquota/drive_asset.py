"""Physical drive identity can outlive logical replicas."""
from .store import one,transaction

def attach(db,record_id,drive,serial,replica,controller,at):
    db.execute('CREATE TABLE IF NOT EXISTS drive_attachments(id TEXT PRIMARY KEY,drive TEXT,serial TEXT,replica TEXT,controller TEXT,at INTEGER)')
    if at<0:return 'invalid_attachment'
    with transaction(db):
        old=one(db,'SELECT * FROM drive_attachments WHERE id=?',(record_id,))
        expected=(drive,serial,replica,controller,at)
        if old:return 'replayed' if tuple(old[k] for k in ('drive','serial','replica','controller','at'))==expected else 'attachment_conflict'
        db.execute('INSERT INTO drive_attachments VALUES (?,?,?,?,?,?)',(record_id,*expected))
        return 'captured'
