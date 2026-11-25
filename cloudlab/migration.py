import json
from .store import transaction,record,audit_run
from .compat import effective

@audit_run('migration')
def run(db,x):
    with transaction(db):
        if x['op']=='verify':
            expected=json.dumps(effective(x['old_manifest'],x['old_api']),sort_keys=True)
            observed=json.dumps(effective(x['new_manifest'],x['new_api']),sort_keys=True)
            state='verified' if expected==observed else 'rejected'
            db.execute('INSERT INTO migrations VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET observed=excluded.observed,state=excluded.state',
                       (x['id'],x['workload'],x['old_api'],x['new_api'],expected,observed,state))
            if state=='verified':
                db.execute('INSERT INTO workload_configs VALUES(?,?,?) ON CONFLICT(workload) DO UPDATE SET version=excluded.version,state=excluded.state',(x['workload'],x.get('new_config_version','migrated'),'active'))
            db.execute("UPDATE api_usage SET state='migrated' WHERE workload=? AND api=? AND ?='verified'",(x['workload'],x['old_api'],state))
            record(db,'migration',x['id'],'verify',1,x)
            return {'decision':state}
        if x['op']=='anchor':
            if not db.execute('SELECT 1 FROM migrations WHERE id=?',(x['migration'],)).fetchone():return {'decision':'blocked','reason':'unknown_migration'}
            if not x['node_version'] or not x['config_version'] or not db.execute('SELECT 1 FROM nodes WHERE id=?',(x['node'],)).fetchone():return {'decision':'blocked','reason':'incomplete_anchor'}
            db.execute('INSERT INTO rollbacks VALUES(?,?,?,?,?,?)',(x['id'],x['migration'],x['node'],x['node_version'],x['config_version'],'ready'))
            record(db,'migration',x['id'],'anchor',1,x)
            return {'decision':'ready'}
        if x['op']=='rollback':
            row=db.execute('SELECT * FROM rollbacks WHERE id=?',(x['id'],)).fetchone()
            if not row or row['state']!='ready':return {'decision':'blocked','reason':'missing_anchor'}
            db.execute("UPDATE rollbacks SET state='applied' WHERE id=?",(x['id'],))
            db.execute("UPDATE migrations SET state='rolled_back' WHERE id=?",(row['migration_id'],))
            db.execute('UPDATE nodes SET version=?,verified_at=NULL WHERE id=?',(row['node_version'],row['node_id']))
            workload=db.execute('SELECT workload FROM migrations WHERE id=?',(row['migration_id'],)).fetchone()['workload']
            db.execute('INSERT INTO workload_configs VALUES(?,?,?) ON CONFLICT(workload) DO UPDATE SET version=excluded.version,state=excluded.state',(workload,row['config_version'],'restored'))
            record(db,'migration',x['id'],'rollback',2,x)
            return {'decision':'rolled_back','node_version':row['node_version'],'config_version':row['config_version']}
        raise ValueError(x['op'])
