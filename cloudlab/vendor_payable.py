from .store import transaction,record

def close(db,close_id,page_id):
    db.execute('CREATE TABLE IF NOT EXISTS vendor_payables(id TEXT PRIMARY KEY,page TEXT,unit_seconds INTEGER)')
    with transaction(db):
        old=db.execute('SELECT unit_seconds FROM vendor_payables WHERE id=?',(close_id,)).fetchone()
        if old:return {'decision':'replay','unit_seconds':old['unit_seconds']}
        total=db.execute('SELECT SUM(unit_seconds) FROM meter_lines WHERE page=?',(page_id,)).fetchone()[0]
        if total is None:return {'decision':'missing_page'}
        db.execute('INSERT INTO vendor_payables VALUES(?,?,?)',(close_id,page_id,total))
        record(db,'payable',close_id,'close',1,{'page':page_id,'unit_seconds':total})
        return {'decision':'closed','unit_seconds':total}
