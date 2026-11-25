from .store import transaction,record

def propose(db,request_id,wave_id,applicant,old_budget,new_budget,at):
    db.execute('CREATE TABLE IF NOT EXISTS risk_requests(id TEXT PRIMARY KEY,wave_id TEXT,applicant TEXT,old_budget INTEGER,new_budget INTEGER,at INTEGER,status TEXT)')
    with transaction(db):
        old=db.execute('SELECT wave_id,applicant,old_budget,new_budget,at FROM risk_requests WHERE id=?',(request_id,)).fetchone()
        if old:return {'decision':'replay' if tuple(old)==(wave_id,applicant,old_budget,new_budget,at) else 'request_conflict'}
        db.execute('INSERT INTO risk_requests VALUES(?,?,?,?,?,?,?)',(request_id,wave_id,applicant,old_budget,new_budget,at,'draft'))
        record(db,'approval',request_id,'propose',1,{'wave':wave_id,'applicant':applicant,'old_budget':old_budget,'new_budget':new_budget,'at':at})
        return {'decision':'draft'}
