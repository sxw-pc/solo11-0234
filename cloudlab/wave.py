from .store import transaction,record,audit_run

@audit_run('wave')
def run(db,x):
    with transaction(db):
        if x['op']=='plan':
            db.execute('INSERT INTO waves VALUES(?,?,?,?,?)',(x['id'],x['target'],x.get('parent'),x['max_unavailable'],'planned'))
            record(db,'wave',x['id'],'plan',1,x)
            return {'decision':'planned'}
        wave=db.execute('SELECT * FROM waves WHERE id=?',(x['id'],)).fetchone()
        if not wave:return {'decision':'blocked','reason':'unknown_wave'}
        if x['op']=='release':
            old=db.execute('SELECT state,node_id,wave_id FROM transitions WHERE id=?',(x['transition'],)).fetchone()
            if old:return {'decision':'reused' if old['node_id']==x['node'] and old['wave_id']==x['id'] else 'blocked','state':old['state'],'reason':'transition_conflict' if old['node_id']!=x['node'] or old['wave_id']!=x['id'] else None}
            if wave['parent']:
                parent=db.execute('SELECT state FROM waves WHERE id=?',(wave['parent'],)).fetchone()
                if not parent or parent['state']!='complete':return {'decision':'blocked','reason':'parent_incomplete'}
            if db.execute("SELECT 1 FROM migrations WHERE state='rejected'").fetchone():return {'decision':'blocked','reason':'migration_failed'}
            if db.execute("SELECT 1 FROM api_usage WHERE state='observed'").fetchone():return {'decision':'blocked','reason':'deprecated_api_pending'}
            existing=db.execute("SELECT COUNT(*) FROM transitions WHERE wave_id=? AND state='applying'",(x['id'],)).fetchone()[0]
            zone=db.execute("SELECT COUNT(*) FROM transitions WHERE zone=? AND state='applying'",(x['zone'],)).fetchone()[0]
            if existing>=wave['max_unavailable'] or zone>=x['zone_budget']:return {'decision':'blocked','reason':'availability_budget'}
            if not db.execute('SELECT 1 FROM nodes WHERE id=? AND verified_at IS NOT NULL',(x['node'],)).fetchone():return {'decision':'blocked','reason':'unverified_node'}
            db.execute('INSERT INTO transitions VALUES(?,?,?,?,?)',(x['transition'],x['id'],x['node'],x['zone'],'applying'))
            db.execute("UPDATE waves SET state='applying' WHERE id=?",(x['id'],))
            record(db,'wave',x['transition'],'release',1,x)
            return {'decision':'released'}
        if x['op']=='finish':
            row=db.execute('SELECT * FROM transitions WHERE id=?',(x['transition'],)).fetchone()
            if not row:return {'decision':'blocked','reason':'unknown_transition'}
            if row['wave_id']!=x['id']:return {'decision':'blocked','reason':'wrong_wave'}
            if row['state']=='complete':return {'decision':'reused','state':'complete'}
            db.execute("UPDATE transitions SET state='complete' WHERE id=?",(x['transition'],))
            db.execute('UPDATE nodes SET version=?,verified_at=NULL WHERE id=?',(wave['target'],row['node_id']))
            left=db.execute("SELECT COUNT(*) FROM transitions WHERE wave_id=? AND state='applying'",(x['id'],)).fetchone()[0]
            if left==0:db.execute("UPDATE waves SET state='complete' WHERE id=?",(x['id'],))
            record(db,'wave',x['transition'],'finish',2,x)
            return {'decision':'complete'}
        raise ValueError(x['op'])
