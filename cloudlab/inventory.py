from .store import transaction,record,audit_run

def _node_media(db,node_id):
    return [dict(r) for r in db.execute('SELECT * FROM media WHERE node_id=? ORDER BY id',(node_id,))]

def _media_wipe_proven(db,node_id):
    """节点介质的"已清空"主张只能由保管交割事实支持, 版本扫描不算数。"""
    media=_node_media(db,node_id)
    if not media:return False
    for m in media:
        if m['state']=='erased':continue
        if m['state']=='sealed':
            # 托管卷必须属于已出具删除证的案件(甲片段已被见证剔除)。
            case=db.execute('SELECT case_id FROM case_media WHERE media_id=?',(m['id'],)).fetchone()
            if not case:return False
            cert=db.execute("SELECT 1 FROM deletion_certificates WHERE case_id=? AND state='issued'",
                            (case['case_id'],)).fetchone()
            if not cert:return False
            continue
        return False
    return True

@audit_run('inventory')
def run(db,x):
    with transaction(db):
        if x['op']=='node':
            old=db.execute('SELECT generation FROM nodes WHERE id=?',(x['id'],)).fetchone()
            if old and x['generation']<=old['generation']:return {'decision':'blocked','reason':'stale_generation'}
            if x.get('media_wiped') and not _media_wipe_proven(db,x['id']):
                return {'decision':'blocked','reason':'media_wiped_unproven'}
            db.execute('INSERT INTO nodes VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET architecture=excluded.architecture,features=excluded.features,generation=excluded.generation,observed_at=excluded.observed_at,version=excluded.version,verified_at=NULL,zone=excluded.zone',
                       (x['id'],x['architecture'],','.join(x['features']),x['generation'],x['observed_at'],x['version'],None,x.get('zone','z')))
            record(db,'inventory',x['id'],'node',x['generation'],x)
            result={'decision':'observed'}
            media=_node_media(db,x['id'])
            pending=[m['id'] for m in media if m['state'] not in ('erased','sealed')]
            if pending:
                # 高代次扫描覆盖的是节点版本与能力, 不覆盖旧介质上的客户数据。
                result['retired_media_pending']=pending
            return result
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
