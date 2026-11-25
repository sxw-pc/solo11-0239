"""Received hardware quotes, separate from resource decisions."""
import hashlib,json
from .store import one,transaction

def quote(db,quote_id,node,device,nonce,boot_counter,measurement,at,issuer):
    db.execute('CREATE TABLE IF NOT EXISTS device_quotes(id TEXT PRIMARY KEY,node TEXT,device TEXT,nonce TEXT,boot_counter INTEGER,measurement TEXT,at INTEGER,issuer TEXT,digest TEXT)')
    if boot_counter<0 or at<0 or not all((node,device,nonce,measurement,issuer)):return 'invalid_quote'
    raw=json.dumps([node,device,nonce,boot_counter,measurement,at,issuer],separators=(',',':'))
    digest=hashlib.sha256(raw.encode()).hexdigest()
    with transaction(db):
        old=one(db,'SELECT digest FROM device_quotes WHERE id=?',(quote_id,))
        if old:return 'replayed' if old['digest']==digest else 'quote_conflict'
        db.execute('INSERT INTO device_quotes VALUES(?,?,?,?,?,?,?,?,?)',(quote_id,node,device,nonce,boot_counter,measurement,at,issuer,digest))
        return 'captured'
