import json
from .store import transaction,record,audit_run
from .source_custody import effective_components,active_bundle

METHODS=('direct','written_offer')

def _check_coverage(db, artifact_id, node_id, bundle_row):
    effective=effective_components(db,artifact_id,node_id)
    keys={(r['component'],r['component_digest']) for r in
          db.execute('SELECT component,component_digest FROM bundle_archives WHERE bundle_id=?',(bundle_row['id'],))}
    actual={(c['component'],c['component_digest']) for c in effective}
    return actual==keys,effective

def _active_approval(db, artifact_id, customer, method, at):
    rows=db.execute('SELECT * FROM delivery_approvals WHERE artifact_id=? AND state=? ORDER BY id DESC',(artifact_id,'active')).fetchall()
    for a in rows:
        recipients=json.loads(a['recipients']);methods=json.loads(a['methods'])
        if customer in recipients and method in methods and at<=a['valid_until']:
            return a
    return None

def _bundle_for(db, artifact_id, node_id, bundle_id):
    bundle=db.execute('SELECT * FROM source_bundles WHERE id=?',(bundle_id,)).fetchone()
    if not bundle or bundle['artifact_id']!=artifact_id or bundle['state']!='active':
        return None,'bundle_not_usable'
    if bundle['node_id'] is not None and bundle['node_id']!=node_id:
        return None,'bundle_not_usable'
    covers,_=_check_coverage(db,artifact_id,node_id,bundle)
    if not covers:return None,'bundle_does_not_cover_running_bytes'
    return bundle,None

@audit_run('source_delivery')
def run(db,x):
    with transaction(db):
        op=x['op']
        if op=='custodian':
            old=db.execute('SELECT * FROM custodians WHERE id=?',(x['id'],)).fetchone()
            if old:return {'decision':'reused','custodian':x['id'],'state':old['state']}
            db.execute('INSERT INTO custodians VALUES(?,?,?,?)',(x['id'],x['name'],int(bool(x.get('independent'))),'active'))
            record(db,'source_delivery',x['id'],'custodian',1,x)
            return {'decision':'registered','custodian':x['id']}
        if op=='escrow':
            bundle=db.execute("SELECT * FROM source_bundles WHERE id=? AND state='active'",(x['bundle'],)).fetchone()
            if not bundle:return {'decision':'blocked','reason':'no_active_bundle'}
            custodian=db.execute('SELECT * FROM custodians WHERE id=?',(x['custodian'],)).fetchone()
            if not custodian:return {'decision':'blocked','reason':'unknown_custodian'}
            if not custodian['independent'] or custodian['state']!='active':
                return {'decision':'blocked','reason':'custodian_not_independent'}
            old=db.execute('SELECT * FROM escrows WHERE id=?',(x['id'],)).fetchone()
            if old:return {'decision':'reused','escrow':x['id'],'state':old['state']}
            db.execute('INSERT INTO escrows VALUES(?,?,?,?,?,?,?)',
                       (x['id'],x['custodian'],x['bundle'],bundle['bundle_digest'],'active',None,x['at']))
            record(db,'source_delivery',x['id'],'escrow',1,x)
            return {'decision':'deposited','escrow':x['id'],'bundle_digest':bundle['bundle_digest']}
        if op=='approve':
            if not x.get('methods') or any(m not in METHODS for m in x['methods']):
                return {'decision':'blocked','reason':'invalid_delivery_method'}
            if not x.get('recipients'):return {'decision':'blocked','reason':'missing_recipients'}
            if not x.get('valid_until'):return {'decision':'blocked','reason':'missing_validity'}
            artifact=db.execute('SELECT * FROM artifacts WHERE id=?',(x['artifact'],)).fetchone()
            if not artifact:return {'decision':'blocked','reason':'unknown_artifact'}
            old=db.execute('SELECT * FROM delivery_approvals WHERE id=?',(x['id'],)).fetchone()
            if old:return {'decision':'reused','approval':x['id'],'state':old['state']}
            db.execute('INSERT INTO delivery_approvals VALUES(?,?,?,?,?,?)',
                       (x['id'],x['artifact'],json.dumps(sorted(x['methods'])),json.dumps(sorted(x['recipients'])),
                        x['valid_until'],'active'))
            record(db,'source_delivery',x['id'],'approve',1,x)
            return {'decision':'approved','approval':x['id'],'methods':sorted(x['methods'])}
        if op=='distribute':
            dist=db.execute('SELECT * FROM distributions WHERE id=?',(x['id'],)).fetchone()
            if dist:
                obligation=db.execute('SELECT * FROM delivery_obligations WHERE distribution_id=?',(x['id'],)).fetchone()
                return {'decision':'reused','distribution':x['id'],'state':obligation['state'],'method':obligation['method']}
            node=db.execute('SELECT * FROM nodes WHERE id=?',(x['node'],)).fetchone()
            if not node:return {'decision':'blocked','reason':'unknown_node'}
            artifact=db.execute('SELECT * FROM artifacts WHERE id=?',(x['artifact'],)).fetchone()
            if not artifact:return {'decision':'blocked','reason':'unknown_artifact'}
            if node['architecture']!=artifact['architecture']:
                return {'decision':'blocked','reason':'node_architecture_mismatch'}
            if not db.execute('SELECT 1 FROM runtime_attestations WHERE node_id=?',(node['id'],)).fetchone():
                return {'decision':'blocked','reason':'missing_runtime_attestation'}
            if x.get('entry') and x['entry']!=node['id']:
                return {'decision':'blocked','reason':'traffic_entry_mismatch'}
            method=x['method']
            if method not in METHODS:return {'decision':'blocked','reason':'invalid_delivery_method'}
            approval=_active_approval(db,x['artifact'],x['customer'],method,x['at'])
            if not approval:return {'decision':'blocked','reason':'no_valid_preapproval'}
            if not active_bundle(db,x['artifact'],node['id']):
                return {'decision':'blocked','reason':'no_certified_bundle'}
            db.execute('INSERT INTO distributions VALUES(?,?,?,?,?,?,?)',
                       (x['id'],x['customer'],node['id'],x['artifact'],None,x['at'],'open'))
            db.execute('INSERT INTO delivery_obligations VALUES(?,?,?,?,?,?,?,?)',
                       (x['id'],x['customer'],x['artifact'],method,'open',None,x['at'],x['at']))
            record(db,'source_delivery',x['id'],'distribute',1,x)
            return {'decision':'obligation_opened','distribution':x['id'],'method':method}
        if op=='deliver_direct':
            dist=db.execute('SELECT * FROM distributions WHERE id=?',(x['id'],)).fetchone()
            if not dist:return {'decision':'blocked','reason':'unknown_distribution'}
            obligation=db.execute('SELECT * FROM delivery_obligations WHERE distribution_id=?',(x['id'],)).fetchone()
            receipt=db.execute("SELECT * FROM delivery_receipts WHERE distribution_id=? AND state='valid' ORDER BY received_at DESC,id DESC LIMIT 1",(x['id'],)).fetchone()
            if receipt:
                return {'decision':'reused','receipt':receipt['id'],'method':'direct','bundle':receipt['bundle_id']}
            if obligation['method']!='direct':return {'decision':'blocked','reason':'method_not_approved_for_obligation'}
            bundle,why=_bundle_for(db,dist['artifact_id'],dist['node_id'],x['bundle'])
            if why:return {'decision':'blocked','reason':why}
            approval=_active_approval(db,dist['artifact_id'],dist['customer'],'direct',x['at'])
            if not approval:return {'decision':'blocked','reason':'no_valid_preapproval'}
            rid=x.get('receipt') or ('receipt-'+x['id'])
            db.execute('INSERT INTO delivery_receipts VALUES(?,?,?,?,?,?,?,?,?)',
                       (rid,x['id'],'direct',bundle['id'],bundle['bundle_digest'],dist['customer'],x['at'],'valid',0))
            db.execute("UPDATE distributions SET bundle_id=?,state='fulfilled' WHERE id=?",(bundle['id'],x['id']))
            db.execute("UPDATE delivery_obligations SET state='fulfilled',bundle_id=?,updated_at=? WHERE distribution_id=?",
                       (bundle['id'],x['at'],x['id']))
            record(db,'source_delivery',x['id'],'deliver_direct',2,x)
            return {'decision':'received','receipt':rid,'bundle':bundle['id'],'bundle_digest':bundle['bundle_digest']}
        if op=='offer':
            dist=db.execute('SELECT * FROM distributions WHERE id=?',(x['id'],)).fetchone()
            if not dist:return {'decision':'blocked','reason':'unknown_distribution'}
            obligation=db.execute('SELECT * FROM delivery_obligations WHERE distribution_id=?',(x['id'],)).fetchone()
            existing=db.execute("SELECT * FROM offer_letters WHERE distribution_id=? AND state='issued'",(x['id'],)).fetchone()
            if existing:return {'decision':'reused','offer':existing['id'],'escrow':existing['escrow_id']}
            if obligation['method']!='written_offer':return {'decision':'blocked','reason':'method_not_approved_for_obligation'}
            escrow=db.execute('SELECT * FROM escrows WHERE id=?',(x['escrow'],)).fetchone()
            if not escrow or escrow['state']!='active':return {'decision':'blocked','reason':'escrow_unavailable'}
            custodian=db.execute('SELECT * FROM custodians WHERE id=?',(escrow['custodian_id'],)).fetchone()
            if not custodian or not custodian['independent'] or custodian['state']!='active':
                return {'decision':'blocked','reason':'custodian_not_independent'}
            bundle=db.execute("SELECT * FROM source_bundles WHERE id=? AND state='active'",(escrow['bundle_id'],)).fetchone()
            if not bundle:return {'decision':'blocked','reason':'no_active_bundle'}
            covers,_=_check_coverage(db,dist['artifact_id'],dist['node_id'],bundle)
            if not covers:return {'decision':'blocked','reason':'bundle_does_not_cover_running_bytes'}
            approval=_active_approval(db,dist['artifact_id'],dist['customer'],'written_offer',x['at'])
            if not approval:return {'decision':'blocked','reason':'no_valid_preapproval'}
            if x['at']>=x['valid_until']:return {'decision':'blocked','reason':'offer_expired'}
            db.execute('INSERT INTO offer_letters VALUES(?,?,?,?,?,?,?,?)',
                       (x['offer'],x['id'],x['escrow'],escrow['custodian_id'],x['valid_until'],x['signature'],'issued',x['at']))
            db.execute("UPDATE distributions SET bundle_id=?,state='offered' WHERE id=?",(bundle['id'],x['id']))
            db.execute("UPDATE delivery_obligations SET state='offered',bundle_id=?,updated_at=? WHERE distribution_id=?",
                       (bundle['id'],x['at'],x['id']))
            record(db,'source_delivery',x['id'],'offer',2,x)
            return {'decision':'issued','offer':x['offer'],'escrow':x['escrow'],'valid_until':x['valid_until']}
        if op=='request':
            offer=db.execute('SELECT * FROM offer_letters WHERE id=?',(x['offer'],)).fetchone()
            if not offer:return {'decision':'blocked','reason':'unknown_offer'}
            if offer['state']!='issued':return {'decision':'blocked','reason':'offer_not_active','state':offer['state']}
            if x['at']>offer['valid_until']:return {'decision':'blocked','reason':'offer_expired'}
            old=db.execute('SELECT * FROM source_requests WHERE offer_id=? AND customer=?',(x['offer'],x['customer'])).fetchone()
            if old:return {'decision':'reused','request':old['id'],'state':old['state'],'credential':old['credential']}
            db.execute('INSERT INTO source_requests VALUES(?,?,?,?,?,?,?)',
                       (x['id'],x['offer'],offer['distribution_id'],x['customer'],x['at'],'requested',x.get('credential')))
            record(db,'source_delivery',x['id'],'request',1,x)
            return {'decision':'requested','request':x['id'],'credential':x.get('credential')}
        if op=='fulfill':
            req=db.execute('SELECT * FROM source_requests WHERE id=?',(x['id'],)).fetchone()
            if not req:return {'decision':'blocked','reason':'unknown_request'}
            if req['state']=='fulfilled':
                row=db.execute('SELECT * FROM fulfillments WHERE request_id=?',(req['id'],)).fetchone()
                return {'decision':'reused','fulfillment':row['id'],'state':'fulfilled'}
            offer=db.execute('SELECT * FROM offer_letters WHERE id=?',(req['offer_id'],)).fetchone()
            escrow=db.execute('SELECT * FROM escrows WHERE id=?',(offer['escrow_id'],)).fetchone()
            custodian=db.execute('SELECT * FROM custodians WHERE id=?',(escrow['custodian_id'],)).fetchone()
            if not custodian or custodian['state']!='active':
                return {'decision':'blocked','reason':'custodian_unreachable'}
            if escrow['state']!='active':return {'decision':'blocked','reason':'escrow_unavailable'}
            dist=db.execute('SELECT * FROM distributions WHERE id=?',(req['distribution_id'],)).fetchone()
            bundle=db.execute("SELECT * FROM source_bundles WHERE id=? AND state='active'",(escrow['bundle_id'],)).fetchone()
            if x.get('bundle_digest') and x['bundle_digest']!=escrow['bundle_digest']:
                return {'decision':'blocked','reason':'escrow_digest_mismatch'}
            fid=x.get('fulfillment') or ('ful-'+req['id'])
            db.execute('INSERT INTO fulfillments VALUES(?,?,?,?,?,?,?)',
                       (fid,req['id'],req['distribution_id'],escrow['custodian_id'],escrow['bundle_digest'],x['at'],'fulfilled'))
            db.execute("UPDATE source_requests SET state='fulfilled' WHERE id=?",(req['id'],))
            receipt=db.execute("SELECT * FROM delivery_receipts WHERE distribution_id=? AND state='valid'",(dist['id'],)).fetchone()
            if not receipt:
                rid='receipt-'+fid
                db.execute('INSERT INTO delivery_receipts VALUES(?,?,?,?,?,?,?,?,?)',
                           (rid,dist['id'],'written_offer',bundle['id'],bundle['bundle_digest'],dist['customer'],x['at'],'valid',0))
            db.execute("UPDATE distributions SET state='fulfilled' WHERE id=?",(dist['id'],))
            db.execute("UPDATE delivery_obligations SET state='fulfilled',updated_at=? WHERE distribution_id=?",
                       (x['at'],dist['id']))
            record(db,'source_delivery',x['id'],'fulfill',2,x)
            return {'decision':'fulfilled','fulfillment':fid,'bundle_digest':escrow['bundle_digest']}
        if op=='custodian_lost':
            custodian=db.execute('SELECT * FROM custodians WHERE id=?',(x['id'],)).fetchone()
            if not custodian:return {'decision':'blocked','reason':'unknown_custodian'}
            db.execute("UPDATE custodians SET state='lost' WHERE id=?",(x['id'],))
            affected=[r['id'] for r in db.execute("SELECT id FROM escrows WHERE custodian_id=? AND state='active'",(x['id'],))]
            for eid in affected:
                db.execute("UPDATE escrows SET state='lost' WHERE id=?",(eid,))
                for offer in db.execute("SELECT * FROM offer_letters WHERE escrow_id=? AND state='issued'",(eid,)):
                    db.execute("UPDATE offer_letters SET state='suspended' WHERE id=?",(offer['id'],))
            record(db,'source_delivery',x['id'],'custodian_lost',2,x)
            return {'decision':'suspended','escrows':affected}
        if op=='reescrow':
            old_escrow=db.execute('SELECT * FROM escrows WHERE id=?',(x['old_escrow'],)).fetchone()
            if not old_escrow:return {'decision':'blocked','reason':'unknown_escrow'}
            custodian=db.execute('SELECT * FROM custodians WHERE id=?',(x['custodian'],)).fetchone()
            if not custodian or not custodian['independent'] or custodian['state']!='active':
                return {'decision':'blocked','reason':'custodian_not_independent'}
            bundle=db.execute("SELECT * FROM source_bundles WHERE id=? AND state='active'",(old_escrow['bundle_id'],)).fetchone()
            if not bundle:return {'decision':'blocked','reason':'no_active_bundle'}
            new=db.execute('SELECT * FROM escrows WHERE id=?',(x['id'],)).fetchone()
            if new:return {'decision':'reused','escrow':new['id'],'state':new['state']}
            db.execute("UPDATE escrows SET state='replaced',replaced_by=? WHERE id=?",(x['id'],old_escrow['id']))
            db.execute('INSERT INTO escrows VALUES(?,?,?,?,?,?,?)',
                       (x['id'],x['custodian'],bundle['id'],bundle['bundle_digest'],'active',None,x['at']))
            for offer in db.execute("SELECT * FROM offer_letters WHERE escrow_id=? AND state='suspended'",(old_escrow['id'],)):
                db.execute("UPDATE offer_letters SET escrow_id=?,state='issued' WHERE id=?",(x['id'],offer['id']))
            record(db,'source_delivery',x['id'],'reescrow',2,x)
            return {'decision':'re_escrowed','escrow':x['id']}
        if op=='fallback_direct':
            dist=db.execute('SELECT * FROM distributions WHERE id=?',(x['id'],)).fetchone()
            if not dist:return {'decision':'blocked','reason':'unknown_distribution'}
            receipt=db.execute("SELECT * FROM delivery_receipts WHERE distribution_id=? AND state='valid'",(x['id'],)).fetchone()
            if receipt:return {'decision':'reused','receipt':receipt['id']}
            bundle,why=_bundle_for(db,dist['artifact_id'],dist['node_id'],x['bundle'])
            if why:return {'decision':'blocked','reason':why}
            rid=x.get('receipt') or ('receipt-fb-'+x['id'])
            db.execute('INSERT INTO delivery_receipts VALUES(?,?,?,?,?,?,?,?,?)',
                       (rid,x['id'],'direct_fallback',bundle['id'],bundle['bundle_digest'],dist['customer'],x['at'],'valid',0))
            db.execute("UPDATE distributions SET bundle_id=?,state='fulfilled' WHERE id=?",(bundle['id'],x['id']))
            db.execute("UPDATE delivery_obligations SET state='fulfilled',method='direct_fallback',bundle_id=?,updated_at=? WHERE distribution_id=?",
                       (bundle['id'],x['at'],x['id']))
            for offer in db.execute("SELECT * FROM offer_letters WHERE distribution_id=? AND state IN ('issued','suspended')",(x['id'],)):
                db.execute("UPDATE offer_letters SET state='fulfilled' WHERE id=?",(offer['id'],))
            record(db,'source_delivery',x['id'],'fallback_direct',2,x)
            return {'decision':'received','receipt':rid,'bundle':bundle['id']}
        if op=='supplement':
            dist=db.execute('SELECT * FROM distributions WHERE id=?',(x['id'],)).fetchone()
            if not dist:return {'decision':'blocked','reason':'unknown_distribution'}
            new_bundle=db.execute("SELECT * FROM source_bundles WHERE id=? AND state='active'",(x['bundle'],)).fetchone()
            if not new_bundle:return {'decision':'blocked','reason':'no_active_bundle'}
            covers,_=_check_coverage(db,dist['artifact_id'],dist['node_id'],new_bundle)
            if not covers:return {'decision':'blocked','reason':'bundle_does_not_cover_running_bytes'}
            prior=db.execute("SELECT * FROM delivery_receipts WHERE distribution_id=? AND state='valid' AND superseded=0 ORDER BY received_at DESC,id DESC LIMIT 1",(x['id'],)).fetchone()
            if prior and prior['bundle_id']==new_bundle['id']:
                return {'decision':'reused','receipt':prior['id'],'bundle':new_bundle['id']}
            if prior:
                db.execute("UPDATE delivery_receipts SET state='superseded',superseded=1 WHERE id=?",(prior['id'],))
            rid=x.get('receipt') or ('receipt-sup-'+x['id'])
            db.execute('INSERT INTO delivery_receipts VALUES(?,?,?,?,?,?,?,?,?)',
                       (rid,x['id'],x.get('method','supplement'),new_bundle['id'],new_bundle['bundle_digest'],dist['customer'],x['at'],'valid',0))
            db.execute("UPDATE distributions SET bundle_id=?,state='fulfilled' WHERE id=?",(new_bundle['id'],x['id']))
            db.execute("UPDATE delivery_obligations SET state='fulfilled',bundle_id=?,updated_at=? WHERE distribution_id=?",
                       (new_bundle['id'],x['at'],x['id']))
            db.execute('INSERT OR IGNORE INTO customer_flags VALUES(?,?,?,?,?)',
                       (x['id'],dist['customer'],x.get('reason','runtime_plugin_discovered'),new_bundle['id'],x['at']))
            record(db,'source_delivery',x['id'],'supplement',2,x)
            return {'decision':'supplemented','receipt':rid,'bundle':new_bundle['id'],'prior_retained':bool(prior)}
        raise ValueError(op)
