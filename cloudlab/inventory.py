from .store import transaction,record,audit_run

@audit_run('inventory')
def run(db,x):
    with transaction(db):
        if x['op']=='node':
            old=db.execute('SELECT generation FROM nodes WHERE id=?',(x['id'],)).fetchone()
            if old and x['generation']<=old['generation']:return {'decision':'blocked','reason':'stale_generation'}
            db.execute('INSERT INTO nodes VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET architecture=excluded.architecture,features=excluded.features,generation=excluded.generation,observed_at=excluded.observed_at,version=excluded.version,verified_at=NULL,zone=excluded.zone',
                       (x['id'],x['architecture'],','.join(x['features']),x['generation'],x['observed_at'],x['version'],None,x.get('zone','z')))
            record(db,'inventory',x['id'],'node',x['generation'],x)
            return {'decision':'observed'}
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
        if x['op']=='runtime_load':
            node=db.execute('SELECT * FROM nodes WHERE id=?',(x['id'],)).fetchone()
            if not node:return {'decision':'blocked','reason':'unknown_node'}
            if x['generation']!=node['generation']:
                return {'decision':'blocked','reason':'stale_generation'}
            for comp in x['components']:
                missing=[k for k in ('component','source_revision','component_digest','layer_digest','signature') if not comp.get(k)]
                if missing:return {'decision':'blocked','reason':'incomplete_load_proof','missing':missing}
            db.execute('INSERT INTO runtime_attestations VALUES(?,?,?) ON CONFLICT(node_id,generation) DO UPDATE SET attested_at=excluded.attested_at',
                       (x['id'],x['generation'],x['at']))
            for comp in x['components']:
                db.execute('INSERT INTO runtime_loads VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(node_id,generation,component) DO UPDATE SET source_revision=excluded.source_revision,component_digest=excluded.component_digest,layer_digest=excluded.layer_digest,signature=excluded.signature,observed_at=excluded.observed_at',
                           (x['id'],x['generation'],comp['component'],comp['source_revision'],comp['component_digest'],comp['layer_digest'],comp['signature'],x['at']))
            record(db,'inventory',x['id'],'runtime_load',x['generation'],x)
            return {'decision':'attested','components':[c['component'] for c in x['components']]}
        raise ValueError(x['op'])
