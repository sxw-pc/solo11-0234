from .store import transaction,record

def init(db):
    db.execute('CREATE TABLE IF NOT EXISTS physical_payables(id TEXT PRIMARY KEY,batch TEXT,vendor TEXT,serial TEXT,minute INTEGER,unit_seconds INTEGER,state TEXT,bank_batch TEXT,digest TEXT,UNIQUE(serial,minute))')
    db.execute('CREATE TABLE IF NOT EXISTS vendor_adjustments(id TEXT PRIMARY KEY,batch TEXT,payable TEXT,kind TEXT,unit_seconds INTEGER,reason TEXT,digest TEXT)')

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

def physical_close(db,payable_id,batch_id,vendor,serial,minute,unit_seconds,digest):
    """One physical host's real core-seconds for one minute become one payable.

    Re-scans from different vendor portals and chassis relabels resolve to the
    same (serial, minute) via physical_meter, so no duplicate compute is paid.
    """
    init(db)
    old=db.execute('SELECT * FROM physical_payables WHERE id=?',(payable_id,)).fetchone()
    if old:
        if old['digest']!=digest:return {'decision':'blocked','reason':'payable_conflict'}
        return {'decision':'replay','unit_seconds':old['unit_seconds'],'state':old['state']}
    dup=db.execute('SELECT id FROM physical_payables WHERE serial=? AND minute=?',(serial,minute)).fetchone()
    if dup:return {'decision':'blocked','reason':'host_minute_already_payable','payable':dup['id']}
    db.execute('INSERT INTO physical_payables VALUES(?,?,?,?,?,?,?,?,?)',
               (payable_id,batch_id,vendor,serial,minute,unit_seconds,'open',None,digest))
    record(db,'payable',payable_id,'physical_close',1,
           {'batch':batch_id,'vendor':vendor,'serial':serial,'minute':minute,'unit_seconds':unit_seconds,'digest':digest})
    return {'decision':'closed','unit_seconds':unit_seconds,'state':'open'}

def mark_paid(db,payable_id,bank_batch):
    init(db)
    row=db.execute('SELECT state,bank_batch FROM physical_payables WHERE id=?',(payable_id,)).fetchone()
    if not row:return {'decision':'blocked','reason':'unknown_payable'}
    if row['state']=='paid':
        return {'decision':'replay','state':'paid'} if row['bank_batch']==bank_batch else {'decision':'blocked','reason':'bank_batch_conflict'}
    db.execute("UPDATE physical_payables SET state='paid',bank_batch=? WHERE id=?",(bank_batch,payable_id))
    record(db,'payable',payable_id,'mark_paid',1,{'bank_batch':bank_batch})
    return {'decision':'paid','bank_batch':bank_batch}

def assert_open(db,payable_id):
    row=db.execute('SELECT state FROM physical_payables WHERE id=?',(payable_id,)).fetchone()
    return row is not None and row['state']=='open'

def add_recourse(db,adjustment_id,batch_id,payable_id,unit_seconds,reason,digest):
    """Late evidence after a bank batch can only create a recourse entry;
    the paid payable row itself is never overwritten."""
    init(db)
    old=db.execute('SELECT digest FROM vendor_adjustments WHERE id=?',(adjustment_id,)).fetchone()
    if old:
        if old['digest']!=digest:return {'decision':'blocked','reason':'adjustment_conflict'}
        return {'decision':'replay'}
    row=db.execute('SELECT state FROM physical_payables WHERE id=?',(payable_id,)).fetchone()
    if not row:return {'decision':'blocked','reason':'unknown_payable'}
    if row['state']!='paid':return {'decision':'blocked','reason':'payable_not_banked'}
    db.execute('INSERT INTO vendor_adjustments(id,batch,payable,kind,unit_seconds,reason,digest) VALUES(?,?,?,?,?,?,?)',
               (adjustment_id,batch_id,payable_id,'recourse',unit_seconds,reason,digest))
    record(db,'payable',adjustment_id,'recourse',1,
           {'batch':batch_id,'payable':payable_id,'unit_seconds':unit_seconds,'reason':reason,'digest':digest})
    return {'decision':'recorded','kind':'recourse','unit_seconds':unit_seconds}
