import json
from .store import transaction,record,audit_run
from .compat import effective
from . import object_custody
from .object_custody import CustodyLedger, CustodyBlocked

WRITE_OPS={
    'customer_write','object_write','custody_write','write_object',
    'customer_command','record_customer_write',
}
OLD_WRITE_OPS={'old_write','old_api_write','compat_old_write'}
READ_OPS={'old_read','read_old','customer_read'}
FREEZE_OPS={'freeze_writes','custody_freeze','freeze_customer_writes'}
FENCE_OPS={'write_fence','custody_fence','committer_fence'}
HANDOFF_OPS={'handoff_write_fence','write_handoff'}
ASSESS_OPS={'assess_rollback','custody_assess','plan_rollback'}


@audit_run('migration')
def run(db,x):
    with transaction(db):
        ledger=CustodyLedger(db)
        op=x['op']

        if op in WRITE_OPS:
            try:
                return ledger.commit_write(x)
            except CustodyBlocked as blocked:
                return blocked.result()
        if op in OLD_WRITE_OPS:
            try:
                return ledger.old_write(x)
            except CustodyBlocked as blocked:
                return blocked.result()
        if op in READ_OPS:
            return ledger.read_old_payload(x)
        if op in FREEZE_OPS:
            row=ledger.freeze_new_writes(x.get('workload','default'),x.get('at'),x.get('anchor_id'))
            return {'decision':'frozen','epoch':row['epoch'],'state':row['state']}
        if op in FENCE_OPS:
            try:
                if x.get('action')=='handoff' or x.get('takeover'):
                    row=ledger.handoff_write_fence(
                        x['workload'],x.get('to_role','old'),x.get('committer_id'),
                        x.get('fence_token') or x.get('token'),x.get('at'),x.get('anchor_id'))
                else:
                    row=ledger.acquire_committer(
                        x['workload'],x.get('role','new'),x.get('committer_id'),
                        x.get('fence_token') or x.get('token'),x.get('at'),bool(x.get('takeover',False)))
                return {'decision':'committer_ready','fence':{
                    'workload':row['workload'],'epoch':row['epoch'],'state':row['state'],
                    'committer_role':row['committer_role'],'token':row['token']}}
            except CustodyBlocked as blocked:
                return blocked.result()
        if op in HANDOFF_OPS:
            row=ledger.handoff_write_fence(
                x['workload'],x.get('to_role','old'),x.get('committer_id'),
                x.get('fence_token') or x.get('token'),x.get('at'),x.get('anchor_id'))
            return {'decision':'write_fence_handed_off','epoch':row['epoch'],'token':row['token']}
        if op in ASSESS_OPS:
            try:
                return {'decision':'assessed',**ledger.assessment_for_anchor(x.get('id') or x.get('anchor_id'))}
            except CustodyBlocked as blocked:
                return blocked.result()

        if op=='config':
            old=db.execute('SELECT * FROM workload_configs WHERE workload=?',(x['workload'],)).fetchone()
            if old and old['state']!='restored':
                return {'decision':'blocked','reason':'config_already_registered'}
            db.execute('INSERT INTO workload_configs VALUES(?,?,?) ON CONFLICT(workload) DO UPDATE SET version=excluded.version,state=excluded.state',
                       (x['workload'],x['version'],'baseline'))
            record(db,'migration',x['workload'],'config',1,x)
            return {'decision':'registered'}
        if op=='verify':
            baseline=db.execute('SELECT * FROM workload_configs WHERE workload=?',(x['workload'],)).fetchone()
            if not baseline or baseline['state'] not in ('baseline','restored'):
                return {'decision':'blocked','reason':'missing_config_baseline'}
            expected=json.dumps(effective(x['old_manifest'],x['old_api']),sort_keys=True)
            observed=json.dumps(effective(x['new_manifest'],x['new_api']),sort_keys=True)
            state='verified' if expected==observed else 'rejected'
            db.execute('INSERT INTO migrations VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET observed=excluded.observed,baseline_config=excluded.baseline_config,state=excluded.state',
                       (x['id'],x['workload'],x['old_api'],x['new_api'],expected,observed,baseline['version'],state))
            # Bind the old object field boundary and exact old config bytes at
            # verification.  Equality of workload knobs is not object custody.
            raw_config=(x.get('old_config_raw') if x.get('old_config_raw') is not None
                        else x.get('old_config_bytes',x['old_manifest']))
            object_fields=(x.get('object_fields') or x.get('old_object_fields')
                           or x.get('expressible_fields') or x.get('object_field_scope'))
            ledger.save_contract(
                x['id'],x['workload'],x['old_api'],x['new_api'],
                x['old_manifest'],x['new_manifest'],raw_config,
                x.get('at'),object_fields,state)
            if state=='verified':
                db.execute('INSERT INTO workload_configs VALUES(?,?,?) ON CONFLICT(workload) DO UPDATE SET version=excluded.version,state=excluded.state',(x['workload'],x.get('new_config_version','migrated'),'active'))
            db.execute("UPDATE api_usage SET state='migrated' WHERE workload=? AND api=? AND ?='verified'",(x['workload'],x['old_api'],state))
            record(db,'migration',x['id'],'verify',1,x)
            return {'decision':state}
        if op=='anchor':
            migration=db.execute('SELECT * FROM migrations WHERE id=?',(x['migration'],)).fetchone()
            if not migration:return {'decision':'blocked','reason':'unknown_migration'}
            node=db.execute('SELECT * FROM nodes WHERE id=?',(x['node'],)).fetchone()
            if not x.get('node_version') or not x.get('config_version') or not node:
                return {'decision':'blocked','reason':'incomplete_anchor'}
            if node['version']!=x['node_version'] or migration['baseline_config']!=x['config_version']:
                return {'decision':'blocked','reason':'anchor_version_mismatch'}
            if x.get('node_generation') not in (None,'') and int(x['node_generation'])!=int(node['generation']):
                return {'decision':'blocked','reason':'anchor_version_mismatch'}
            if x.get('object_version') not in (None,''):
                fence=ledger.ensure_fence(migration['workload'],x.get('at'))
                if int(x['object_version'])!=int(fence['head_version']):
                    return {'decision':'blocked','reason':'object_version_mismatch',
                            'expected_object_version':fence['head_version']}

            existing=db.execute('SELECT * FROM rollbacks WHERE id=?',(x['id'],)).fetchone()
            if existing and (existing['migration_id'],existing['node_id'],existing['node_version'],existing['config_version']) != (
                    x['migration'],x['node'],x['node_version'],x['config_version']):
                return {'decision':'blocked','reason':'anchor_conflict'}
            try:
                # Bind custody first so a rejected object/byte contract does
                # not leave a seemingly usable ready rollback row behind.
                binding=ledger.bind_anchor(x,migration,node)
            except CustodyBlocked as blocked:
                return blocked.result()
            if not existing:
                db.execute('INSERT INTO rollbacks VALUES(?,?,?,?,?,?)',
                           (x['id'],x['migration'],x['node'],x['node_version'],x['config_version'],'ready'))
            record(db,'migration',x['id'],'anchor',1,x)
            return {'decision':'ready','anchor':binding}
        if op in ('rollback_handoff','rollback_prepare') or (op=='rollback' and x.get('stage') in ('handoff','prepare')):
            row=db.execute('SELECT * FROM rollbacks WHERE id=?',(x['id'],)).fetchone()
            if not row:return {'decision':'blocked','reason':'missing_anchor'}
            migration=db.execute('SELECT * FROM migrations WHERE id=?',(row['migration_id'],)).fetchone()
            config=db.execute('SELECT * FROM workload_configs WHERE workload=?',(migration['workload'],)).fetchone()
            if row['state']=='ready' and (not config or (config['version'] not in (row['config_version'],'migrated') and config['state']!='compat_active')):
                return {'decision':'blocked','reason':'config_changed_after_anchor'}
            try:
                result=ledger.begin_physical_handoff(x,row,migration)
            except CustodyBlocked as blocked:
                return blocked.result()
            if result.get('decision')=='handoff_ready':
                db.execute("UPDATE rollbacks SET state='handoff' WHERE id=?",(x['id'],))
                record(db,'migration',x['id'],'rollback_handoff',2,x)
            elif result.get('decision')=='forward_fix_required':
                db.execute("UPDATE rollbacks SET state='forward_required' WHERE id=?",(x['id'],))
                record(db,'migration',x['id'],'rollback_forward_required',2,x)
            return result
        if op=='rollback':
            row=db.execute('SELECT * FROM rollbacks WHERE id=?',(x['id'],)).fetchone()
            if not row:return {'decision':'blocked','reason':'missing_anchor'}
            migration=db.execute('SELECT * FROM migrations WHERE id=?',(row['migration_id'],)).fetchone()
            config=db.execute('SELECT * FROM workload_configs WHERE workload=?',(migration['workload'],)).fetchone()

            # Completed/repaired receipts are safe idempotent retries.  Ready
            # anchors still enforce configuration drift protection.
            if row['state']=='ready' and (not config or (config['version'] not in (row['config_version'],'migrated') and config['state']!='compat_active')):
                return {'decision':'blocked','reason':'config_changed_after_anchor'}

            try:
                result=ledger.recover(x,row,migration)
            except CustodyBlocked as blocked:
                return blocked.result()

            decision=result.get('decision')
            workload=migration['workload']
            if decision=='forward_fix_required':
                db.execute("UPDATE rollbacks SET state='forward_required' WHERE id=?",(x['id'],))
                db.execute("UPDATE migrations SET state='forward_fix_required' WHERE id=?",(row['migration_id'],))
                record(db,'migration',x['id'],'rollback_forward_required',2,x)
                return result

            if decision=='forward_fix_applied':
                db.execute("UPDATE rollbacks SET state='forward_active' WHERE id=?",(x['id'],))
                db.execute("UPDATE migrations SET state='forward_fixed' WHERE id=?",(row['migration_id'],))
                # Keep the new config/bytes and actual new node version.  The
                # old API is served by the compatibility facade, not by a
                # physically restored old controller.
                db.execute("UPDATE workload_configs SET state='compat_active' WHERE workload=?",(workload,))
                db.execute("UPDATE api_usage SET state='compat_served' WHERE workload=? AND api=?",
                           (workload,migration['old_api']))
                record(db,'migration',x['id'],'forward_fix',2,x)
                return result

            if decision=='rolled_back':
                # Causal object replay has already been committed in custody
                # tables; now bind the infrastructure rows to the old version.
                db.execute("UPDATE rollbacks SET state='applied' WHERE id=?",(x['id'],))
                db.execute("UPDATE migrations SET state='rolled_back' WHERE id=?",(row['migration_id'],))
                db.execute('UPDATE nodes SET version=?,verified_at=NULL WHERE id=?',(row['node_version'],row['node_id']))
                db.execute('INSERT INTO workload_configs VALUES(?,?,?) ON CONFLICT(workload) DO UPDATE SET version=excluded.version,state=excluded.state',
                           (workload,row['config_version'],'restored'))
                db.execute("UPDATE api_usage SET state='observed' WHERE workload=? AND api=? AND state IN ('migrated','compat_served')",
                           (workload,migration['old_api']))
                record(db,'migration',x['id'],'rollback',2,x)
                # Preserve the historical top-level response contract while
                # adding custody evidence.  Values come from the anchor row.
                result.setdefault('node_version',row['node_version'])
                result.setdefault('config_version',row['config_version'])
                result['decision']='rolled_back'
                return result

            return result
        raise ValueError(x['op'])
