import json
from .store import transaction,record

def import_page(db,page_id,vendor,digest,lines):
    db.execute('CREATE TABLE IF NOT EXISTS meter_pages(id TEXT PRIMARY KEY,vendor TEXT,digest TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS meter_lines(page TEXT,line INTEGER,host TEXT,tenant TEXT,minute INTEGER,unit_seconds INTEGER,PRIMARY KEY(page,line))')
    with transaction(db):
        old=db.execute('SELECT digest FROM meter_pages WHERE id=?',(page_id,)).fetchone()
        if old:return {'decision':'replay' if old['digest']==digest else 'page_conflict'}
        db.execute('INSERT INTO meter_pages VALUES(?,?,?)',(page_id,vendor,digest))
        for i,line in enumerate(lines):
            db.execute('INSERT INTO meter_lines VALUES(?,?,?,?,?,?)',(page_id,i,line['host'],line['tenant'],line['minute'],line['unit_seconds']))
        record(db,'meter',page_id,'import',1,{'vendor':vendor,'digest':digest,'lines':lines})
        return {'decision':'imported','lines':len(lines)}
