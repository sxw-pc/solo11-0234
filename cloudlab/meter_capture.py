from .store import transaction,record,fingerprint,digest_bytes

def verify_page_chain(evidence):
    """Verify a meter page is connected to the original bytes.

    evidence may carry:
      raw_digest  - SHA-256 of the captured raw page bytes
      page_digest - digest claimed over the page summary itself
      clock       - {'digest':..., 'parent':...} calibration chain anchor
      serial_chain- ordered [{'serial':...,'digest':...}] host serial chain,
                    each entry's digest must chain from its predecessor
    A page without evidence is accepted by the legacy seed path but the
    physical settlement pipeline never treats it as raw-linked proof.
    """
    if not evidence:return {'ok':True,'linked':False}
    page_digest=evidence.get('page_digest')
    if not page_digest:return {'ok':False,'linked':False,'reason':'missing_page_digest'}
    raw_digest=evidence.get('raw_digest')
    if raw_digest is not None and digest_bytes(evidence.get('raw',b''))!=raw_digest:
        return {'ok':False,'linked':True,'reason':'raw_digest_mismatch'}
    clock=evidence.get('clock')
    if clock:
        if not clock.get('digest'):return {'ok':False,'linked':True,'reason':'missing_clock_digest'}
        if clock.get('parent') is not None and fingerprint(clock['parent'])!=clock['digest']:
            return {'ok':False,'linked':True,'reason':'clock_chain_broken'}
    chain=evidence.get('serial_chain')
    if chain:
        previous=page_digest
        for entry in chain:
            if not entry.get('serial') or not entry.get('digest'):
                return {'ok':False,'linked':True,'reason':'serial_chain_incomplete'}
            if fingerprint({'previous':previous,'serial':entry['serial']})!=entry['digest']:
                return {'ok':False,'linked':True,'reason':'serial_chain_broken'}
            previous=entry['digest']
    return {'ok':True,'linked':True,'page_digest':page_digest}

def init(db):
    db.execute('CREATE TABLE IF NOT EXISTS meter_pages(id TEXT,vendor TEXT,digest TEXT,PRIMARY KEY(id,vendor))')
    db.execute('CREATE TABLE IF NOT EXISTS meter_lines(page TEXT,line INTEGER,host TEXT,tenant TEXT,minute INTEGER,unit_seconds INTEGER,PRIMARY KEY(page,line))')
    db.execute('CREATE TABLE IF NOT EXISTS meter_raw_pages(page TEXT PRIMARY KEY,vendor TEXT,page_digest TEXT,raw_digest TEXT,clock_digest TEXT,chain_tail TEXT)')

def import_page(db,page_id,vendor,digest,lines,evidence=None):
    init(db)
    with transaction(db):
        chain=verify_page_chain(evidence)
        if not chain['ok']:return {'decision':'blocked','reason':chain['reason']}
        old=db.execute('SELECT vendor,digest FROM meter_pages WHERE id=?',(page_id,)).fetchone()
        if old:
            if old['vendor']!=vendor:return {'decision':'blocked','reason':'page_id_vendor_conflict'}
            return {'decision':'replay' if old['digest']==digest else 'page_conflict'}
        db.execute('INSERT INTO meter_pages VALUES(?,?,?)',(page_id,vendor,digest))
        for i,line in enumerate(lines):
            db.execute('INSERT INTO meter_lines VALUES(?,?,?,?,?,?)',(page_id,i,line['host'],line['tenant'],line['minute'],line['unit_seconds']))
        if evidence and chain['linked']:
            serial_chain=evidence.get('serial_chain') or []
            db.execute('INSERT INTO meter_raw_pages VALUES(?,?,?,?,?,?)',
                       (page_id,vendor,chain['page_digest'],evidence.get('raw_digest'),
                        (evidence.get('clock') or {}).get('digest'),
                        serial_chain[-1]['digest'] if serial_chain else None))
        record(db,'meter',page_id,'import',1,{'vendor':vendor,'digest':digest,'lines':lines,'evidence':evidence,'chain':chain})
        return {'decision':'imported','lines':len(lines),'chain':chain}
