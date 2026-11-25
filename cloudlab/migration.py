from .store import transaction,record,audit_run

@audit_run('migration')
def run(db,x):
    with transaction(db):
        if x['op']=='verify':
            state='verified' if x['expected']==x['observed'] else 'rejected'
            db.execute('INSERT INTO migrations VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET observed=excluded.observed,state=excluded.state',
                       (x['id'],x['workload'],x['old_api'],x['new_api'],x['expected'],x['observed'],state))
            db.execute("UPDATE api_usage SET state='migrated' WHERE workload=? AND api=? AND ?='verified'",(x['workload'],x['old_api'],state))
            record(db,'migration',x['id'],'verify',1,x)
            return {'decision':state}
        if x['op']=='anchor':
            if not db.execute('SELECT 1 FROM migrations WHERE id=?',(x['migration'],)).fetchone():return {'decision':'blocked','reason':'unknown_migration'}
            if not x['node_version'] or not x['config_version']:return {'decision':'blocked','reason':'incomplete_anchor'}
            db.execute('INSERT INTO rollbacks VALUES(?,?,?,?,?)',(x['id'],x['migration'],x['node_version'],x['config_version'],'ready'))
            record(db,'migration',x['id'],'anchor',1,x)
            return {'decision':'ready'}
        if x['op']=='rollback':
            row=db.execute('SELECT * FROM rollbacks WHERE id=?',(x['id'],)).fetchone()
            if not row or row['state']!='ready':return {'decision':'blocked','reason':'missing_anchor'}
            db.execute("UPDATE rollbacks SET state='applied' WHERE id=?",(x['id'],))
            db.execute("UPDATE migrations SET state='rolled_back' WHERE id=?",(row['migration_id'],))
            record(db,'migration',x['id'],'rollback',2,x)
            return {'decision':'rolled_back','node_version':row['node_version'],'config_version':row['config_version']}
        raise ValueError(x['op'])
