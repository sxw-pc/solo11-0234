import json
from .store import transaction,record,audit_run,fingerprint

def init(db):
    db.execute('CREATE TABLE IF NOT EXISTS physical_windows(id TEXT PRIMARY KEY,wave_id TEXT,serial TEXT,from_minute INTEGER,to_minute INTEGER,digest TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS vm_motions(id TEXT PRIMARY KEY,window_id TEXT,serial TEXT,container TEXT,from_minute INTEGER,to_minute INTEGER,barcode TEXT,digest TEXT)')

@audit_run('wave')
def run(db,x):
    with transaction(db):
        init(db)
        if x['op']=='physical_window':
            old=db.execute('SELECT digest FROM physical_windows WHERE id=?',(x['id'],)).fetchone()
            payload={'wave_id':x['wave_id'],'serial':x['serial'],'from_minute':x['from_minute'],'to_minute':x['to_minute']}
            digest=fingerprint(payload)
            if old:
                if old['digest']!=digest:return {'decision':'blocked','reason':'window_conflict'}
                return {'decision':'replay','digest':digest}
            db.execute('INSERT INTO physical_windows VALUES(?,?,?,?,?,?)',
                       (x['id'],x['wave_id'],x['serial'],x['from_minute'],x['to_minute'],digest))
            record(db,'wave',x['id'],'physical_window',1,payload)
            return {'decision':'registered','digest':digest}
        if x['op']=='vm_motion':
            old=db.execute('SELECT digest FROM vm_motions WHERE id=?',(x['id'],)).fetchone()
            window=db.execute('SELECT * FROM physical_windows WHERE id=?',(x['window_id'],)).fetchone()
            if not window:return {'decision':'blocked','reason':'unknown_physical_window'}
            payload={'window_id':x['window_id'],'serial':x['serial'],'container':x['container'],
                     'from_minute':x['from_minute'],'to_minute':x['to_minute'],'barcode':x['barcode']}
            digest=fingerprint(payload)
            if old:
                if old['digest']!=digest:return {'decision':'blocked','reason':'motion_conflict'}
                return {'decision':'replay','digest':digest}
            if x['serial']!=window['serial']:return {'decision':'blocked','reason':'motion_host_conflict'}
            if not (window['from_minute']<=x['from_minute']<=window['to_minute'] and x['to_minute']>x['from_minute']):
                return {'decision':'blocked','reason':'motion_outside_window'}
            db.execute('INSERT INTO vm_motions VALUES(?,?,?,?,?,?,?,?)',
                       (x['id'],x['window_id'],x['serial'],x['container'],x['from_minute'],x['to_minute'],x['barcode'],digest))
            record(db,'wave',x['id'],'vm_motion',1,payload)
            return {'decision':'registered','digest':digest}
        if x['op']=='plan':
            budgets=x.get('zone_budgets',{})
            if x['max_unavailable']<1 or any(not isinstance(v,int) or v<1 for v in budgets.values()):
                return {'decision':'blocked','reason':'invalid_availability_budget'}
            db.execute('INSERT INTO waves VALUES(?,?,?,?,?,?)',(x['id'],x['target'],x.get('parent'),x['max_unavailable'],json.dumps(budgets,sort_keys=True),'planned'))
            record(db,'wave',x['id'],'plan',1,x)
            return {'decision':'planned'}
        wave=db.execute('SELECT * FROM waves WHERE id=?',(x['id'],)).fetchone()
        if not wave:return {'decision':'blocked','reason':'unknown_wave'}
        if x['op']=='probe':
            transition=db.execute('SELECT * FROM transitions WHERE id=? AND wave_id=?',(x['transition'],x['id'])).fetchone()
            node=db.execute('SELECT * FROM nodes WHERE id=?',(transition['node_id'],)).fetchone() if transition else None
            if not transition or transition['state']!='applying' or not node or node['generation']!=transition['node_generation']:
                return {'decision':'blocked','reason':'stale_transition'}
            if x['generation']!=node['generation'] or x['target']!=wave['target'] or x['at']<transition['released_at']:
                return {'decision':'blocked','reason':'probe_identity_or_time'}
            db.execute('INSERT INTO transition_probes VALUES(?,?,?,?,?,?)',
                       (x['probe'],x['transition'],x['generation'],x['target'],x['at'],int(x['healthy'])))
            record(db,'wave',x['probe'],'probe',x['generation'],x)
            return {'decision':'healthy' if x['healthy'] else 'unhealthy'}
        if x['op']=='release':
            old=db.execute('SELECT state,node_id,wave_id FROM transitions WHERE id=?',(x['transition'],)).fetchone()
            if old:return {'decision':'reused' if old['node_id']==x['node'] and old['wave_id']==x['id'] else 'blocked','state':old['state'],'reason':'transition_conflict' if old['node_id']!=x['node'] or old['wave_id']!=x['id'] else None}
            if wave['parent']:
                parent=db.execute('SELECT state FROM waves WHERE id=?',(wave['parent'],)).fetchone()
                if not parent or parent['state']!='complete':return {'decision':'blocked','reason':'parent_incomplete'}
            if db.execute("SELECT 1 FROM migrations WHERE state='rejected'").fetchone():return {'decision':'blocked','reason':'migration_failed'}
            if db.execute("SELECT 1 FROM api_usage WHERE state='observed'").fetchone():return {'decision':'blocked','reason':'deprecated_api_pending'}
            node=db.execute('SELECT * FROM nodes WHERE id=? AND verified_at IS NOT NULL',(x['node'],)).fetchone()
            if not node:return {'decision':'blocked','reason':'unverified_node'}
            if x.get('zone',node['zone'])!=node['zone']:
                return {'decision':'blocked','reason':'zone_identity_conflict'}
            budgets=json.loads(wave['zone_budgets'])
            limit=budgets.get(node['zone'],wave['max_unavailable'])
            existing=db.execute("SELECT COUNT(*) FROM transitions WHERE wave_id=? AND state='applying'",(x['id'],)).fetchone()[0]
            zone=db.execute("SELECT COUNT(*) FROM transitions WHERE zone=? AND state='applying'",(node['zone'],)).fetchone()[0]
            if existing>=wave['max_unavailable'] or zone>=limit:return {'decision':'blocked','reason':'availability_budget'}
            released_at=x.get('now',node['verified_at'])
            if released_at<node['verified_at']:return {'decision':'blocked','reason':'release_before_verification'}
            db.execute('INSERT INTO transitions VALUES(?,?,?,?,?,?,?)',(x['transition'],x['id'],x['node'],node['zone'],node['generation'],released_at,'applying'))
            db.execute("UPDATE waves SET state='applying' WHERE id=?",(x['id'],))
            record(db,'wave',x['transition'],'release',1,x)
            return {'decision':'released'}
        if x['op']=='finish':
            row=db.execute('SELECT * FROM transitions WHERE id=?',(x['transition'],)).fetchone()
            if not row:return {'decision':'blocked','reason':'unknown_transition'}
            if row['wave_id']!=x['id']:return {'decision':'blocked','reason':'wrong_wave'}
            if row['state']=='complete':return {'decision':'reused','state':'complete'}
            node=db.execute('SELECT * FROM nodes WHERE id=?',(row['node_id'],)).fetchone()
            if not node or node['generation']!=row['node_generation']:
                return {'decision':'blocked','reason':'stale_node_generation'}
            probe=db.execute('SELECT * FROM transition_probes WHERE transition_id=? ORDER BY at DESC,id DESC LIMIT 1',(row['id'],)).fetchone()
            if not probe or not probe['healthy'] or probe['target']!=wave['target'] or probe['node_generation']!=node['generation']:
                return {'decision':'blocked','reason':'target_health_unverified'}
            db.execute("UPDATE transitions SET state='complete' WHERE id=?",(x['transition'],))
            db.execute('UPDATE nodes SET version=?,verified_at=NULL WHERE id=?',(wave['target'],row['node_id']))
            left=db.execute("SELECT COUNT(*) FROM transitions WHERE wave_id=? AND state='applying'",(x['id'],)).fetchone()[0]
            if left==0:db.execute("UPDATE waves SET state='complete' WHERE id=?",(x['id'],))
            record(db,'wave',x['transition'],'finish',2,x)
            return {'decision':'complete'}
        raise ValueError(x['op'])
