from .store import transaction,record

def init(db):
    db.execute('CREATE TABLE IF NOT EXISTS tenant_invoices(id TEXT PRIMARY KEY,batch TEXT,tenant TEXT,serial TEXT,minute INTEGER,unit_seconds INTEGER,state TEXT,bank_batch TEXT,digest TEXT,UNIQUE(serial,minute,tenant))')
    db.execute('CREATE TABLE IF NOT EXISTS tenant_invoice_adjustments(id TEXT PRIMARY KEY,batch TEXT,invoice TEXT,kind TEXT,unit_seconds INTEGER,reason TEXT,digest TEXT)')

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

def confirmed_issue(db,invoice_id,batch_id,tenant,serial,minute,unit_seconds,digest):
    """Issue only core-seconds whose tenant is the same across every migration
    history still compatible with the original bytes. Vendor portal labels are
    never accepted as proof here."""
    init(db)
    old=db.execute('SELECT * FROM tenant_invoices WHERE id=?',(invoice_id,)).fetchone()
    if old:
        if old['digest']!=digest:return {'decision':'blocked','reason':'invoice_conflict'}
        return {'decision':'replay','unit_seconds':old['unit_seconds'],'state':old['state']}
    dup=db.execute('SELECT id FROM tenant_invoices WHERE serial=? AND minute=? AND tenant=?',(serial,minute,tenant)).fetchone()
    if dup:return {'decision':'blocked','reason':'host_minute_tenant_already_invoiced','invoice':dup['id']}
    db.execute('INSERT INTO tenant_invoices VALUES(?,?,?,?,?,?,?,?,?)',
               (invoice_id,batch_id,tenant,serial,minute,unit_seconds,'open',None,digest))
    record(db,'charge',invoice_id,'confirmed_issue',1,
           {'batch':batch_id,'tenant':tenant,'serial':serial,'minute':minute,'unit_seconds':unit_seconds,'digest':digest})
    return {'decision':'issued','unit_seconds':unit_seconds,'state':'open'}

def mark_invoiced(db,invoice_id,bank_batch):
    init(db)
    row=db.execute('SELECT state,bank_batch FROM tenant_invoices WHERE id=?',(invoice_id,)).fetchone()
    if not row:return {'decision':'blocked','reason':'unknown_invoice'}
    if row['state']=='issued':
        return {'decision':'replay','state':'issued'} if row['bank_batch']==bank_batch else {'decision':'blocked','reason':'bank_batch_conflict'}
    db.execute("UPDATE tenant_invoices SET state='issued',bank_batch=? WHERE id=?",(bank_batch,invoice_id))
    record(db,'charge',invoice_id,'mark_invoiced',1,{'bank_batch':bank_batch})
    return {'decision':'issued','bank_batch':bank_batch}

def assert_open(db,invoice_id):
    row=db.execute('SELECT state FROM tenant_invoices WHERE id=?',(invoice_id,)).fetchone()
    return row is not None and row['state']=='open'

def add_adjustment(db,adjustment_id,batch_id,invoice_id,kind,unit_seconds,reason,digest):
    """A banked invoice is immutable: late migration slips produce a separate
    supplement or reversal voucher that traces back to the original."""
    init(db)
    if kind not in ('supplement','reversal'):return {'decision':'blocked','reason':'unknown_adjustment_kind'}
    old=db.execute('SELECT digest FROM tenant_invoice_adjustments WHERE id=?',(adjustment_id,)).fetchone()
    if old:
        if old['digest']!=digest:return {'decision':'blocked','reason':'adjustment_conflict'}
        return {'decision':'replay'}
    row=db.execute('SELECT state FROM tenant_invoices WHERE id=?',(invoice_id,)).fetchone()
    if not row:return {'decision':'blocked','reason':'unknown_invoice'}
    if row['state']!='issued':return {'decision':'blocked','reason':'invoice_not_banked'}
    db.execute('INSERT INTO tenant_invoice_adjustments(id,batch,invoice,kind,unit_seconds,reason,digest) VALUES(?,?,?,?,?,?,?)',
               (adjustment_id,batch_id,invoice_id,kind,unit_seconds,reason,digest))
    record(db,'charge',adjustment_id,kind,1,
           {'batch':batch_id,'invoice':invoice_id,'unit_seconds':unit_seconds,'reason':reason,'digest':digest})
    return {'decision':'recorded','kind':kind,'unit_seconds':unit_seconds}

def net_billed(db,tenant=None):
    init(db)
    if tenant:
        base=db.execute('SELECT COALESCE(SUM(unit_seconds),0) FROM tenant_invoices WHERE tenant=?',(tenant,)).fetchone()[0]
        reversed_se=db.execute('''SELECT COALESCE(SUM(a.unit_seconds),0) FROM tenant_invoice_adjustments a
                                  JOIN tenant_invoices i ON i.id=a.invoice
                                  WHERE a.kind='reversal' AND i.tenant=?''',(tenant,)).fetchone()[0]
    else:
        base=db.execute('SELECT COALESCE(SUM(unit_seconds),0) FROM tenant_invoices').fetchone()[0]
        reversed_se=db.execute("SELECT COALESCE(SUM(unit_seconds),0) FROM tenant_invoice_adjustments WHERE kind='reversal'").fetchone()[0]
    return base-reversed_se
