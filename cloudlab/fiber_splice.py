from .store import transaction,record

def submit(db,receipt_id,branch,worker):
    db.execute('CREATE TABLE IF NOT EXISTS fiber_splices(id TEXT PRIMARY KEY,branch TEXT,worker TEXT)')
    with transaction(db):
        old=db.execute('SELECT branch,worker FROM fiber_splices WHERE id=?',(receipt_id,)).fetchone()
        if old:return {'decision':'replay' if (old['branch'],old['worker'])==(branch,worker) else 'splice_conflict'}
        if not db.execute('SELECT 1 FROM fiber_branches WHERE id=?',(branch,)).fetchone():return {'decision':'unknown_branch'}
        db.execute('INSERT INTO fiber_splices VALUES(?,?,?)',(receipt_id,branch,worker))
        record(db,'fiber',receipt_id,'splice',1,{'branch':branch,'worker':worker})
        return {'decision':'received'}
