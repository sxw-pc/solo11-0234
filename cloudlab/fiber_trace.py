from .store import transaction,record

def observe(db,trace_id,port,distance_km,loss):
    db.execute('CREATE TABLE IF NOT EXISTS fiber_traces(id TEXT PRIMARY KEY,port TEXT,distance_km INTEGER,loss INTEGER)')
    with transaction(db):
        old=db.execute('SELECT port,distance_km,loss FROM fiber_traces WHERE id=?',(trace_id,)).fetchone()
        if old:return {'decision':'replay' if (old['port'],old['distance_km'],old['loss'])==(port,distance_km,loss) else 'trace_conflict'}
        db.execute('INSERT INTO fiber_traces VALUES(?,?,?,?)',(trace_id,port,distance_km,loss))
        record(db,'fiber',trace_id,'observe',1,{'port':port,'distance_km':distance_km,'loss':loss})
        candidates=[r['id'] for r in db.execute('SELECT id FROM fiber_branches WHERE port=? AND length_km=? ORDER BY id',(port,distance_km))]
        return {'decision':'observed','candidates':candidates}
