from .store import transaction,record

def sign(db,signature_id,request_id,seat,at):
    db.execute('CREATE TABLE IF NOT EXISTS risk_requests(id TEXT PRIMARY KEY,wave_id TEXT,applicant TEXT,old_budget INTEGER,new_budget INTEGER,at INTEGER,status TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS risk_signatures(id TEXT PRIMARY KEY,request_id TEXT,seat TEXT,at INTEGER)')
    with transaction(db):
        old=db.execute('SELECT request_id,seat,at FROM risk_signatures WHERE id=?',(signature_id,)).fetchone()
        if old:return {'decision':'replay' if tuple(old)==(request_id,seat,at) else 'signature_conflict'}
        if not db.execute('SELECT 1 FROM risk_requests WHERE id=?',(request_id,)).fetchone():return {'decision':'missing_request'}
        db.execute('INSERT INTO risk_signatures VALUES(?,?,?,?)',(signature_id,request_id,seat,at))
        record(db,'approval',signature_id,'sign',1,{'request':request_id,'seat':seat,'at':at})
        return {'decision':'signed'}
