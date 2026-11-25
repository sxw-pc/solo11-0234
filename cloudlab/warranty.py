from .store import transaction,record

def open_claim(db,claim_id,transition,vendor):
    db.execute('CREATE TABLE IF NOT EXISTS warranty_claims(id TEXT PRIMARY KEY,transition_id TEXT,vendor TEXT,state TEXT)')
    with transaction(db):
        old=db.execute('SELECT transition_id,vendor FROM warranty_claims WHERE id=?',(claim_id,)).fetchone()
        if old:return {'decision':'replay' if old['transition_id']==transition and old['vendor']==vendor else 'claim_conflict'}
        failed=db.execute('SELECT 1 FROM transition_probes WHERE transition_id=? AND healthy=0 LIMIT 1',(transition,)).fetchone()
        if not failed:return {'decision':'blocked','reason':'no_failed_probe'}
        db.execute('INSERT INTO warranty_claims VALUES(?,?,?,?)',(claim_id,transition,vendor,'draft'))
        record(db,'warranty',claim_id,'open',1,{'transition':transition,'vendor':vendor})
        return {'decision':'draft'}
