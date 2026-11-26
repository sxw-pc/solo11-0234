import json
from .store import transaction,record,audit_run
from .compat import effective

@audit_run('migration')
def run(db,x):
    with transaction(db):
        if x['op']=='config':
            old=db.execute('SELECT * FROM workload_configs WHERE workload=?',(x['workload'],)).fetchone()
            if old and old['state']!='restored':
                return {'decision':'blocked','reason':'config_already_registered'}
            db.execute('INSERT INTO workload_configs VALUES(?,?,?) ON CONFLICT(workload) DO UPDATE SET version=excluded.version,state=excluded.state',
                       (x['workload'],x['version'],'baseline'))
            record(db,'migration',x['workload'],'config',1,x)
            return {'decision':'registered'}
        if x['op']=='verify':
            baseline=db.execute('SELECT * FROM workload_configs WHERE workload=?',(x['workload'],)).fetchone()
            if not baseline or baseline['state'] not in ('baseline','restored','active'):
                return {'decision':'blocked','reason':'missing_config_baseline'}
            expected=json.dumps(effective(x['old_manifest'],x['old_api']),sort_keys=True)
            observed=json.dumps(effective(x['new_manifest'],x['new_api']),sort_keys=True)
            state='verified' if expected==observed else 'rejected'
            db.execute('''INSERT INTO migrations(id,workload,old_api,new_api,expected,observed,baseline_config,state)
                          VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET observed=excluded.observed,baseline_config=excluded.baseline_config,state=excluded.state''',
                       (x['id'],x['workload'],x['old_api'],x['new_api'],expected,observed,baseline['version'],state))
            occurred_at=x.get('at',x.get('occurred_at',x.get('now')))
            customer_id=x.get('customer_id') or x.get('customer')
            service=x.get('service') or x.get('service_id') or x['workload']
            db.execute('''UPDATE migrations SET occurred_at=?, customer_id=?, service=?,
                node_id=?, wave_id=?, transition_id=?, command_id=? WHERE id=?''',
                       (occurred_at,customer_id,service,x.get('node_id') or x.get('node'),
                        x.get('wave_id') or x.get('wave'),x.get('transition_id') or x.get('transition'),
                        x.get('command_id'),x['id']))
            if customer_id:
                # Original-event attribution is append-only.  Late mappings go
                # through legal_request.attribute_customer and never rewrite
                # this migration row or its evidence bytes.
                from .legal_request import attribute_customer
                attribute_customer(db,{
                    'mapping_id': f'auto-migration-{x["id"]}',
                    'command_id': f'auto-migration-{x["id"]}',
                    'customer_id': customer_id,'service':service,
                    'subject_type':'migration','subject_id':x['id'],
                    'source':'migration_payload','basis':'recorded_with_original_event',
                    'at':occurred_at or 0,
                })
            if state=='verified':
                db.execute('INSERT INTO workload_configs VALUES(?,?,?) ON CONFLICT(workload) DO UPDATE SET version=excluded.version,state=excluded.state',(x['workload'],x.get('new_config_version','migrated'),'active'))
            db.execute("UPDATE api_usage SET state='migrated' WHERE workload=? AND api=? AND ?='verified'",(x['workload'],x['old_api'],state))
            record(db,'migration',x['id'],'verify',1,x)
            return {'decision':state}
        if x['op']=='anchor':
            migration=db.execute('SELECT * FROM migrations WHERE id=?',(x['migration'],)).fetchone()
            if not migration:return {'decision':'blocked','reason':'unknown_migration'}
            node=db.execute('SELECT * FROM nodes WHERE id=?',(x['node'],)).fetchone()
            if not x['node_version'] or not x['config_version'] or not node:
                return {'decision':'blocked','reason':'incomplete_anchor'}
            if node['version']!=x['node_version'] or migration['baseline_config']!=x['config_version']:
                return {'decision':'blocked','reason':'anchor_version_mismatch'}
            db.execute('INSERT INTO rollbacks VALUES(?,?,?,?,?,?)',(x['id'],x['migration'],x['node'],x['node_version'],x['config_version'],'ready'))
            record(db,'migration',x['id'],'anchor',1,x)
            return {'decision':'ready'}
        if x['op']=='rollback':
            row=db.execute('SELECT * FROM rollbacks WHERE id=?',(x['id'],)).fetchone()
            if not row or row['state']!='ready':return {'decision':'blocked','reason':'missing_anchor'}
            migration=db.execute('SELECT * FROM migrations WHERE id=?',(row['migration_id'],)).fetchone()
            config=db.execute('SELECT * FROM workload_configs WHERE workload=?',(migration['workload'],)).fetchone()
            if not config or (config['version'] not in (row['config_version'],'migrated')):
                return {'decision':'blocked','reason':'config_changed_after_anchor'}
            db.execute("UPDATE rollbacks SET state='applied' WHERE id=?",(x['id'],))
            db.execute("UPDATE migrations SET state='rolled_back' WHERE id=?",(row['migration_id'],))
            db.execute('UPDATE nodes SET version=?,verified_at=NULL WHERE id=?',(row['node_version'],row['node_id']))
            workload=db.execute('SELECT workload FROM migrations WHERE id=?',(row['migration_id'],)).fetchone()['workload']
            db.execute('INSERT INTO workload_configs VALUES(?,?,?) ON CONFLICT(workload) DO UPDATE SET version=excluded.version,state=excluded.state',(workload,row['config_version'],'restored'))
            db.execute("UPDATE api_usage SET state='observed' WHERE workload=? AND api=? AND state='migrated'",
                       (workload,migration['old_api']))
            record(db,'migration',x['id'],'rollback',2,x)
            return {'decision':'rolled_back','node_version':row['node_version'],'config_version':row['config_version']}
        raise ValueError(x['op'])
