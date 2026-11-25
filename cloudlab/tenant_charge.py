from .store import transaction,record

def issue(db,invoice_id,page_id,tenant):
    db.execute('CREATE TABLE IF NOT EXISTS tenant_charges(id TEXT PRIMARY KEY,page TEXT,tenant TEXT,unit_seconds INTEGER)')
    with transaction(db):
        old=db.execute('SELECT unit_seconds FROM tenant_charges WHERE id=?',(invoice_id,)).fetchone()
        if old:return {'decision':'replay','unit_seconds':old['unit_seconds']}
        total=db.execute('SELECT SUM(unit_seconds) FROM meter_lines WHERE page=? AND tenant=?',(page_id,tenant)).fetchone()[0]
        if total is None:return {'decision':'missing_tenant'}
        db.execute('INSERT INTO tenant_charges VALUES(?,?,?,?)',(invoice_id,page_id,tenant,total))
        record(db,'charge',invoice_id,'issue',1,{'page':page_id,'tenant':tenant,'unit_seconds':total})
        return {'decision':'issued','unit_seconds':total}
