from .store import transaction,record

def register(db,branch,port,length_km,shaft):
    db.execute('CREATE TABLE IF NOT EXISTS fiber_branches(id TEXT PRIMARY KEY,port TEXT,length_km INTEGER,shaft TEXT)')
    with transaction(db):
        old=db.execute('SELECT * FROM fiber_branches WHERE id=?',(branch,)).fetchone()
        if old:return {'decision':'replay' if old['port']==port and old['length_km']==length_km and old['shaft']==shaft else 'branch_conflict'}
        db.execute('INSERT INTO fiber_branches VALUES(?,?,?,?)',(branch,port,length_km,shaft))
        record(db,'fiber',branch,'register',1,{'port':port,'length_km':length_km,'shaft':shaft})
        return {'decision':'registered'}
