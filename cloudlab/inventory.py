import json

from .store import transaction,record,audit_run

def scan_history(db,node_id):
    return [dict(r) for r in db.execute(
        'SELECT * FROM node_scans WHERE node_id=? ORDER BY observed_at,generation',(node_id,))]

@audit_run('inventory')
def run(db,x):
    with transaction(db):
        if x['op']=='node':
            old=db.execute('SELECT generation FROM nodes WHERE id=?',(x['id'],)).fetchone()
            if old and x['generation']<=old['generation']:return {'decision':'blocked','reason':'stale_generation'}
            db.execute('INSERT INTO nodes VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET architecture=excluded.architecture,features=excluded.features,generation=excluded.generation,observed_at=excluded.observed_at,version=excluded.version,verified_at=NULL,zone=excluded.zone',
                       (x['id'],x['architecture'],','.join(x['features']),x['generation'],x['observed_at'],x['version'],None,x.get('zone','z')))
            # Accepted node facts are generation scans.  Keeping the scan row
            # lets an incident bind "generation one at minute N" without
            # trusting only the subsequently updated current-node row.
            db.execute('INSERT OR IGNORE INTO node_scans VALUES(?,?,?,?,?,?,?,?,?)',
                       (x['id'],x['generation'],x['observed_at'],x.get('scan_id'),
                        x['architecture'],x['version'],x.get('zone','z'),
                        ','.join(x['features']),json.dumps(x,ensure_ascii=False,sort_keys=True)))
            record(db,'inventory',x['id'],'node',x['generation'],x)
            return {'decision':'observed','scan_recorded':True,'scan_generation':x['generation'],'observed_at':x['observed_at']}
        if x['op']=='usage':
            old=db.execute('SELECT generation FROM api_usage WHERE id=?',(x['id'],)).fetchone()
            if old and x['generation']<=old['generation']:
                return {'decision':'blocked','reason':'stale_usage_generation'}
            db.execute('INSERT INTO api_usage VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET api=excluded.api,generation=excluded.generation,state=excluded.state',(x['id'],x['workload'],x['api'],x['generation'],'observed'))
            record(db,'inventory',x['id'],'usage',x['generation'],x)
            return {'decision':'observed'}
        if x['op']=='verify':
            node=db.execute('SELECT * FROM nodes WHERE id=?',(x['id'],)).fetchone()
            if not node or x['now']-node['observed_at']>x['max_age']:return {'decision':'blocked','reason':'stale_observation'}
            if x['architecture']!=node['architecture'] or not set(x['features']).issubset(set(node['features'].split(','))):return {'decision':'blocked','reason':'missing_capability'}
            deprecated=[r['id'] for r in db.execute("SELECT * FROM api_usage WHERE api=? AND state='observed'",(x['deprecated_api'],))]
            if deprecated:return {'decision':'blocked','reason':'deprecated_api','usages':deprecated}
            db.execute('UPDATE nodes SET verified_at=? WHERE id=?',(x['now'],x['id']))
            record(db,'inventory',x['id'],'verify',node['generation'],x)
            return {'decision':'verified'}
        raise ValueError(x['op'])
