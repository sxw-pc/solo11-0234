from .store import transaction,record,audit_run

@audit_run('inventory')
def run(db,x):
    with transaction(db):
        if x['op']=='node':
            old=db.execute('SELECT generation FROM nodes WHERE id=?',(x['id'],)).fetchone()
            if old and x['generation']<=old['generation']:return {'decision':'blocked','reason':'stale_generation'}
            db.execute('INSERT INTO nodes VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET architecture=excluded.architecture,features=excluded.features,generation=excluded.generation,observed_at=excluded.observed_at,version=excluded.version,verified_at=NULL',
                       (x['id'],x['architecture'],','.join(x['features']),x['generation'],x['observed_at'],x['version'],None))
            record(db,'inventory',x['id'],'node',x['generation'],x)
            return {'decision':'observed'}
        if x['op']=='usage':
            db.execute('INSERT INTO api_usage VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET api=excluded.api,generation=excluded.generation,state=excluded.state',(x['id'],x['workload'],x['api'],x['generation'],'observed'))
            record(db,'inventory',x['id'],'usage',x['generation'],x)
            return {'decision':'observed'}
        if x['op']=='verify':
            node=db.execute('SELECT * FROM nodes WHERE id=?',(x['id'],)).fetchone()
            if not node or x['now']-node['observed_at']>x['max_age']:return {'decision':'blocked','reason':'stale_observation'}
            if x['architecture']!=node['architecture'] or not set(x['features']).issubset(set(node['features'].split(','))):return {'decision':'blocked','reason':'missing_capability'}
            deprecated=[r['id'] for r in db.execute('SELECT * FROM api_usage WHERE api=?',(x['deprecated_api'],))]
            if deprecated:return {'decision':'blocked','reason':'deprecated_api','usages':deprecated}
            db.execute('UPDATE nodes SET verified_at=? WHERE id=?',(x['now'],x['id']))
            record(db,'inventory',x['id'],'verify',node['generation'],x)
            return {'decision':'verified'}
        raise ValueError(x['op'])
