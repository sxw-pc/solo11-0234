"""Physical metering attribution for payment and invoicing.

Two independently authorized ledgers are built from the same original bytes:

* vendor ledger  - every physical host's real core-seconds per minute are paid
  to the supplier exactly once, regardless of portal re-scans, chassis
  relabels or VM migration during an upgrade window, and only when the batch
  conserves against the independent CPU controller counts;
* customer ledger- a core-second is invoiced only to the tenant that owns it in
  every migration history still compatible with the original evidence. A
  supplier portal tenant label and arrival order are never proof.

Unresolved core-seconds are never guessed or pro-rated. A settlement runs under
one of two pre-authorized financial instructions:

  loss_provision - the operator books its own reserve; tenant A and its group
                   make no external payment;
  group_deposit  - the group's prepaid guarantee contract moves real refundable
                   cash into a deposit liability account, never usage revenue.

Once a bank batch has been sent, old payments and invoices are immutable: late
migration slips create supplements, reversals, recourse or deposit refunds
only, each tracing back to the original document.
"""
from .store import transaction,record,audit_run,fingerprint
from . import meter_capture,vendor_payable,tenant_charge

POLICIES=('loss_provision','group_deposit')

def init(db):
    db.execute('CREATE TABLE IF NOT EXISTS physical_hosts(serial TEXT PRIMARY KEY,vendor TEXT,digest TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS host_aliases(id TEXT PRIMARY KEY,vendor TEXT,alias TEXT,serial TEXT,since_minute INTEGER,digest TEXT,UNIQUE(vendor,alias,since_minute))')
    db.execute('CREATE TABLE IF NOT EXISTS physical_observations(id TEXT PRIMARY KEY,batch TEXT,page TEXT,serial TEXT,minute INTEGER,container TEXT,labeled_tenant TEXT,unit_seconds INTEGER,raw_digest TEXT,digest TEXT,UNIQUE(serial,minute,container))')
    db.execute('CREATE TABLE IF NOT EXISTS controller_counts(id TEXT PRIMARY KEY,batch TEXT,serial TEXT,minute INTEGER,unit_seconds INTEGER,digest TEXT,UNIQUE(batch,serial,minute))')
    db.execute('CREATE TABLE IF NOT EXISTS migration_slips(id TEXT PRIMARY KEY,batch TEXT,serial TEXT,container TEXT,from_minute INTEGER,to_minute INTEGER,barcode TEXT,complete INTEGER,tenant TEXT,motion_ref TEXT,digest TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS settlements(batch TEXT PRIMARY KEY,policy TEXT,state TEXT,physical_total INTEGER,controller_total INTEGER,unresolved_seconds INTEGER,digest TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS settlement_entries(id TEXT PRIMARY KEY,batch TEXT,serial TEXT,minute INTEGER,container TEXT,unit_seconds INTEGER,status TEXT,tenant TEXT,evidence_digest TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS loss_provisions(id TEXT PRIMARY KEY,batch TEXT,unit_seconds INTEGER,state TEXT,digest TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS group_deposits(id TEXT PRIMARY KEY,batch TEXT,unit_seconds INTEGER,state TEXT,bank_batch TEXT,digest TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS bank_batches(id TEXT PRIMARY KEY,batch TEXT,kind TEXT,outbound INTEGER,unit_seconds INTEGER,digest TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS late_resolutions(id TEXT PRIMARY KEY,batch TEXT,slip TEXT,digest TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS owner_assertions(id TEXT PRIMARY KEY,batch TEXT,serial TEXT,container TEXT,tenant TEXT,anchor TEXT,digest TEXT,UNIQUE(batch,serial,container,tenant))')

def _replay_or_conflict(db,table,obj_id,payload,digest,id_column='id'):
    old=db.execute('SELECT digest FROM '+table+' WHERE '+id_column+'=?',(obj_id,)).fetchone()
    if not old:return None
    return {'decision':'replay','digest':digest} if old['digest']==digest else {'decision':'blocked','reason':'identity_conflict'}

def _resolve_alias(db,vendor,alias,minute=None):
    if minute is None:
        row=db.execute('''SELECT serial FROM host_aliases WHERE vendor=? AND alias=?
                          ORDER BY since_minute DESC LIMIT 1''',(vendor,alias)).fetchone()
    else:
        row=db.execute('''SELECT serial FROM host_aliases WHERE vendor=? AND alias=? AND since_minute<=?
                          ORDER BY since_minute DESC LIMIT 1''',(vendor,alias,minute)).fetchone()
    return row['serial'] if row else None

def _slip_complete(slip):
    barcode=slip.get('barcode') or ''
    return bool(slip.get('complete') and slip.get('tenant') and barcode and not barcode.endswith('XXXX'))

def _attribution_candidates(db,batch_id,serial,container,minute):
    """Return (tenants, complete_slips). Tenants is the set of possible owners
    across every migration history compatible with the evidence; more than one
    member means the original barcode cannot determine the customer.

    Complete migration slips are hard proof. A registered owner assertion (the
    anchored version of a portal label) is a candidate only when no complete
    slip contradicts it; an unanchored label is never considered.
    """
    slips=db.execute('''SELECT * FROM migration_slips WHERE batch=? AND serial=? AND container=?
                        AND from_minute<=? AND to_minute>?''',(batch_id,serial,container,minute,minute)).fetchall()
    complete=[s for s in slips if s['complete']]
    tenants={s['tenant'] for s in complete}
    if not tenants:
        assertions=db.execute('SELECT tenant FROM owner_assertions WHERE batch=? AND serial=? AND container=?',
                              (batch_id,serial,container)).fetchall()
        tenants={r['tenant'] for r in assertions}
    return tenants,complete

@audit_run('physical')
def run(db,x):
    with transaction(db):
        init(db)
        op=x['op']
        if op=='register_host':
            payload={'serial':x['serial'],'vendor':x['vendor']}
            digest=fingerprint(payload)
            hit=_replay_or_conflict(db,'physical_hosts',x['serial'],payload,digest,id_column='serial')
            if hit:return hit
            db.execute('INSERT INTO physical_hosts VALUES(?,?,?)',(x['serial'],x['vendor'],digest))
            record(db,'physical',x['serial'],'register_host',1,payload)
            return {'decision':'registered','serial':x['serial'],'digest':digest}

        if op=='register_alias':
            # A chassis relabel is just a new (vendor, alias) binding to the same
            # hardware serial; observations resolve through the alias history.
            payload={'vendor':x['vendor'],'alias':x['alias'],'serial':x['serial'],'since_minute':x['since_minute']}
            digest=fingerprint(payload)
            aid='%s:%s@%s'%(x['vendor'],x['alias'],x['since_minute'])
            hit=_replay_or_conflict(db,'host_aliases',aid,payload,digest)
            if hit:return hit
            if not db.execute('SELECT 1 FROM physical_hosts WHERE serial=?',(x['serial'],)).fetchone():
                return {'decision':'blocked','reason':'unknown_physical_host'}
            db.execute('INSERT INTO host_aliases VALUES(?,?,?,?,?,?)',
                       (aid,x['vendor'],x['alias'],x['serial'],x['since_minute'],digest))
            record(db,'physical',aid,'register_alias',1,payload)
            return {'decision':'registered','alias_id':aid,'serial':x['serial'],'digest':digest}

        if op=='ingest_page':
            meter_capture.init(db)
            page_id=x['page_id'];vendor=x['vendor'];lines=x['lines'];evidence=x.get('evidence')
            # 1. page summary, clock calibration and host serial chain must link
            #    to the original bytes before anything is trusted.
            chain=meter_capture.verify_page_chain(evidence)
            if not chain['ok']:return {'decision':'blocked','reason':chain['reason']}
            if not chain.get('linked'):return {'decision':'blocked','reason':'raw_evidence_not_linked'}
            import_result=meter_capture.import_page(db,page_id,vendor,x.get('digest',chain['page_digest']),lines,evidence)
            if import_result['decision'] not in ('imported','replay'):return import_result
            accepted=[];skipped=[]
            for i,line in enumerate(lines):
                serial=_resolve_alias(db,vendor,line['host'],line['minute'])
                if not serial:
                    return {'decision':'blocked','reason':'unregistered_host_alias','host':line['host'],'line':i}
                payload={'batch':x['batch'],'serial':serial,'minute':line['minute'],'container':line.get('container',line['host']),
                         'unit_seconds':line['unit_seconds']}
                digest=fingerprint(payload)
                oid='%s|%s|%s|%s'%(x['batch'],serial,line['minute'],payload['container'])
                old=db.execute('SELECT digest,unit_seconds FROM physical_observations WHERE id=?',(oid,)).fetchone()
                if old:
                    if old['digest']!=digest:return {'decision':'blocked','reason':'observation_conflict','observation':oid}
                    skipped.append(oid);continue
                db.execute('INSERT INTO physical_observations VALUES(?,?,?,?,?,?,?,?,?,?)',
                           (oid,x['batch'],page_id,serial,line['minute'],payload['container'],line.get('tenant'),
                            line['unit_seconds'],(evidence or {}).get('raw_digest'),digest))
                accepted.append(oid)
            record(db,'physical',page_id,'ingest_page',1,
                   {'batch':x['batch'],'page':page_id,'vendor':vendor,'accepted':accepted,'skipped':skipped})
            return {'decision':'ingested','page':page_id,'accepted':len(accepted),'duplicates':len(skipped)}

        if op=='controller_count':
            payload={'batch':x['batch'],'serial':x['serial'],'minute':x['minute'],'unit_seconds':x['unit_seconds']}
            digest=fingerprint(payload)
            cid='%s|%s|%s'%(x['batch'],x['serial'],x['minute'])
            hit=_replay_or_conflict(db,'controller_counts',cid,payload,digest)
            if hit:return hit
            db.execute('INSERT INTO controller_counts VALUES(?,?,?,?,?,?)',
                       (cid,x['batch'],x['serial'],x['minute'],x['unit_seconds'],digest))
            record(db,'physical',cid,'controller_count',1,payload)
            return {'decision':'registered','count_id':cid,'digest':digest}

        if op=='assert_owner':
            # A portal label only becomes evidence once it is anchored as an
            # explicit owner assertion; even then, a complete migration slip for
            # the same window can later prove it wrong (reversal, not overwrite).
            payload={'batch':x['batch'],'serial':x['serial'],'container':x['container'],'tenant':x['tenant'],'anchor':x['anchor']}
            digest=fingerprint(payload)
            aid=x['id']
            hit=_replay_or_conflict(db,'owner_assertions',aid,payload,digest)
            if hit:return hit
            if not db.execute('SELECT 1 FROM physical_hosts WHERE serial=?',(x['serial'],)).fetchone():
                return {'decision':'blocked','reason':'unknown_physical_host'}
            db.execute('INSERT INTO owner_assertions VALUES(?,?,?,?,?,?,?)',
                       (aid,x['batch'],x['serial'],x['container'],x['tenant'],x['anchor'],digest))
            record(db,'physical',aid,'assert_owner',1,payload)
            return {'decision':'registered','assertion_id':aid,'digest':digest}

        if op=='migration_slip':
            # The portal label is not evidence; only a complete migration barcode
            # that anchors to a registered upgrade-window motion can prove a tenant.
            payload={'batch':x['batch'],'serial':x['serial'],'container':x['container'],
                     'from_minute':x['from_minute'],'to_minute':x['to_minute'],
                     'barcode':x.get('barcode'),'tenant':x.get('tenant'),'motion_ref':x.get('motion_ref')}
            digest=fingerprint(payload)
            complete=_slip_complete(x)
            if x.get('motion_ref'):
                motion=db.execute('SELECT * FROM vm_motions WHERE id=?',(x['motion_ref'],)).fetchone()
                if not motion:return {'decision':'blocked','reason':'unknown_motion_ref'}
                if motion['serial']!=x['serial'] or motion['container']!=x['container']:
                    return {'decision':'blocked','reason':'motion_identity_conflict'}
            elif complete:
                return {'decision':'blocked','reason':'complete_slip_requires_motion_ref'}
            hit=_replay_or_conflict(db,'migration_slips',x['id'],payload,digest)
            if hit:return dict(hit,complete=complete)
            db.execute('INSERT INTO migration_slips VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                       (x['id'],x['batch'],x['serial'],x['container'],x['from_minute'],x['to_minute'],
                        x.get('barcode'),int(complete),x.get('tenant'),x.get('motion_ref'),digest))
            record(db,'physical',x['id'],'migration_slip',1,dict(payload,complete=complete))
            return {'decision':'registered','slip_id':x['id'],'complete':complete,'digest':digest}

        if op=='settle':
            return _settle(db,x)

        if op=='dispatch_bank':
            return _dispatch(db,x)

        if op=='resolve_late':
            return _resolve_late(db,x)

        if op=='recourse_vendor':
            return _recourse(db,x)

        raise ValueError(op)

def _observed_map(db,batch_id):
    rows=db.execute('SELECT * FROM physical_observations WHERE batch=?',(batch_id,)).fetchall()
    observed={}
    for r in rows:
        key=(r['serial'],r['minute'])
        observed.setdefault(key,[]).append(r)
    return observed

def _conservation(db,batch_id,observed):
    physical={key:sum(r['unit_seconds'] for r in rs) for key,rs in observed.items()}
    controller={(r['serial'],r['minute']):r['unit_seconds']
                for r in db.execute('SELECT * FROM controller_counts WHERE batch=?',(batch_id,))}
    if set(physical)!=set(controller):
        return False,physical,controller,{'missing_controller':sorted(k for k in physical if k not in controller),
                                          'unobserved_count':sorted(k for k in controller if k not in physical)}
    deviations=[{'serial':s,'minute':m,'observed':physical[(s,m)],'controller':controller[(s,m)]}
                for (s,m) in physical if physical[(s,m)]!=controller[(s,m)]]
    return not deviations,physical,controller,{'deviations':deviations}

def _settle(db,x):
    batch_id=x['batch'];policy=x['policy']
    if policy not in POLICIES:return {'decision':'blocked','reason':'unknown_policy'}
    digest=fingerprint({'batch':batch_id,'policy':policy})
    old=db.execute('SELECT * FROM settlements WHERE batch=?',(batch_id,)).fetchone()
    if old:
        if old['digest']!=digest:return {'decision':'blocked','reason':'settlement_conflict'}
        return {'decision':'replay','batch':batch_id,'state':old['state'],'physical_total':old['physical_total']}
    observed=_observed_map(db,batch_id)
    if not observed:return {'decision':'blocked','reason':'no_observations'}
    conserved,physical,controller,detail=_conservation(db,batch_id,observed)
    if not conserved:
        record(db,'physical',batch_id,'settle_blocked',1,{'reason':'controller_deviation','detail':detail})
        return {'decision':'blocked','reason':'controller_deviation','detail':detail}
    physical_total=sum(physical.values());controller_total=sum(controller.values())
    entries=[];confirmed={};unresolved_seconds=0
    for (serial,minute),rows in sorted(observed.items()):
        for r in rows:
            tenants,_=_attribution_candidates(db,batch_id,serial,r['container'],minute)
            if len(tenants)==1:
                tenant=next(iter(tenants));status='confirmed'
                confirmed.setdefault(tenant,[]).append((r,tenant))
            else:
                tenant=None;status='unresolved';unresolved_seconds+=r['unit_seconds']
            eid='%s|%s|%s|%s'%(batch_id,serial,minute,r['container'])
            db.execute('INSERT INTO settlement_entries VALUES(?,?,?,?,?,?,?,?,?)',
                       (eid,batch_id,serial,minute,r['container'],r['unit_seconds'],status,tenant,r['digest']))
            entries.append({'entry':eid,'serial':serial,'minute':minute,'container':r['container'],
                            'unit_seconds':r['unit_seconds'],'status':status,'tenant':tenant})
    # Vendor ledger: one payable per physical host per minute, paid once.
    payables=[]
    for (serial,minute),total in sorted(physical.items()):
        host=db.execute('SELECT vendor FROM physical_hosts WHERE serial=?',(serial,)).fetchone()
        payload={'batch':batch_id,'serial':serial,'minute':minute,'unit_seconds':total}
        pdigest=fingerprint(payload)
        pid='%s|pay|%s|%s'%(batch_id,serial,minute)
        res=vendor_payable.physical_close(db,pid,batch_id,host['vendor'],serial,minute,total,pdigest)
        if res['decision']=='blocked':return res
        payables.append({'payable':pid,'vendor':host['vendor'],'serial':serial,'minute':minute,'unit_seconds':total})
    # Customer ledger: confirmed tenants only; unresolved core-seconds are never
    # guessed, pro-rated or treated as usage revenue.
    invoices=[]
    for tenant,items in sorted(confirmed.items()):
        for r,_ in items:
            payload={'batch':batch_id,'tenant':tenant,'serial':r['serial'],'minute':r['minute'],'unit_seconds':r['unit_seconds']}
            idigest=fingerprint(payload)
            iid='%s|inv|%s|%s|%s'%(batch_id,r['serial'],r['minute'],tenant)
            res=tenant_charge.confirmed_issue(db,iid,batch_id,tenant,r['serial'],r['minute'],r['unit_seconds'],idigest)
            if res['decision']=='blocked':return res
            invoices.append({'invoice':iid,'tenant':tenant,'serial':r['serial'],'minute':r['minute'],'unit_seconds':r['unit_seconds']})
    provisions=[];deposits=[]
    if unresolved_seconds:
        if policy=='loss_provision':
            lid='%s|loss'%batch_id
            ldigest=fingerprint({'batch':batch_id,'unit_seconds':unresolved_seconds})
            db.execute('INSERT INTO loss_provisions VALUES(?,?,?,?,?)',(lid,batch_id,unresolved_seconds,'reserved',ldigest))
            provisions.append({'provision':lid,'unit_seconds':unresolved_seconds,'state':'reserved'})
        else:
            did='%s|deposit'%batch_id
            ddigest=fingerprint({'batch':batch_id,'unit_seconds':unresolved_seconds})
            # Liability until the contract offset or refund happens; never revenue.
            db.execute('INSERT INTO group_deposits VALUES(?,?,?,?,?,?)',(did,batch_id,unresolved_seconds,'awaiting',None,ddigest))
            deposits.append({'deposit':did,'unit_seconds':unresolved_seconds,'state':'awaiting'})
    db.execute('INSERT INTO settlements VALUES(?,?,?,?,?,?,?)',
               (batch_id,policy,'settled',physical_total,controller_total,unresolved_seconds,digest))
    record(db,'physical',batch_id,'settle',1,
           {'batch':batch_id,'policy':policy,'physical_total':physical_total,'controller_total':controller_total,
            'unresolved_seconds':unresolved_seconds,'payables':payables,'invoices':invoices,
            'provisions':provisions,'deposits':deposits,'entries':entries})
    return {'decision':'settled','batch':batch_id,'policy':policy,'physical_total':physical_total,
            'controller_total':controller_total,'unresolved_seconds':unresolved_seconds,
            'payables':payables,'invoices':invoices,'provisions':provisions,'deposits':deposits}

def _dispatch(db,x):
    batch_id=x['batch'];bank_batch=x['bank_batch'];kind=x['kind']
    if kind not in ('payment','deposit_receipt'):return {'decision':'blocked','reason':'unknown_bank_kind'}
    bdigest=fingerprint({'batch':batch_id,'bank_batch':bank_batch,'kind':kind,'unit_seconds':x['unit_seconds']})
    old=db.execute('SELECT digest FROM bank_batches WHERE id=?',(bank_batch,)).fetchone()
    if old:
        if old['digest']!=bdigest:return {'decision':'blocked','reason':'bank_batch_conflict'}
        return {'decision':'replay','bank_batch':bank_batch}
    settlement=db.execute('SELECT * FROM settlements WHERE batch=?',(batch_id,)).fetchone()
    if not settlement or settlement['state']!='settled':return {'decision':'blocked','reason':'settlement_not_ready'}
    outbound=0
    if kind=='payment':
        rows=db.execute("SELECT id FROM physical_payables WHERE batch=? AND state='open'",(batch_id,)).fetchall()
        for r in rows:
            res=vendor_payable.mark_paid(db,r['id'],bank_batch)
            if res['decision']=='blocked':return res
        inv=db.execute("SELECT id FROM tenant_invoices WHERE batch=? AND state='open'",(batch_id,)).fetchall()
        for r in inv:
            res=tenant_charge.mark_invoiced(db,r['id'],bank_batch)
            if res['decision']=='blocked':return res
        outbound=db.execute("SELECT COALESCE(SUM(unit_seconds),0) FROM physical_payables WHERE batch=?",(batch_id,)).fetchone()[0]
    else:
        if settlement['policy']!='group_deposit':return {'decision':'blocked','reason':'deposit_requires_group_deposit'}
        dep=db.execute('SELECT * FROM group_deposits WHERE batch=?',(batch_id,)).fetchone()
        if not dep:return {'decision':'blocked','reason':'deposit_not_registered'}
        if dep['unit_seconds']!=x['unit_seconds']:return {'decision':'blocked','reason':'deposit_amount_conflict'}
        if dep['state']!='awaiting':return {'decision':'blocked','reason':'deposit_not_awaiting'}
        db.execute("UPDATE group_deposits SET state='received',bank_batch=? WHERE id=?",(bank_batch,dep['id']))
        outbound=0
    db.execute('INSERT INTO bank_batches VALUES(?,?,?,?,?,?)',(bank_batch,batch_id,kind,outbound,x['unit_seconds'],bdigest))
    record(db,'physical',bank_batch,'dispatch_bank',1,
           {'batch':batch_id,'bank_batch':bank_batch,'kind':kind,'outbound':outbound,'unit_seconds':x['unit_seconds']})
    return {'decision':'banked','bank_batch':bank_batch,'kind':kind,'outbound':outbound,'unit_seconds':x['unit_seconds']}

def _is_banked(db,batch_id):
    return db.execute("SELECT 1 FROM bank_batches WHERE batch=? LIMIT 1",(batch_id,)).fetchone() is not None

def _resolve_late(db,x):
    """A complete migration slip arriving after the bank batch cannot overwrite
    anything. It releases a reserve, or offsets/refunds the group deposit, and
    only then creates the final usage invoice. If the slip proves a banked
    invoice went to the wrong tenant, that invoice is kept and reversed through
    a traceable voucher while the real tenant receives a supplement."""
    batch_id=x['batch'];slip_id=x['slip_id'];action=x.get('action','offset')
    if action not in ('offset','refund'):return {'decision':'blocked','reason':'unknown_action'}
    settlement=db.execute('SELECT * FROM settlements WHERE batch=?',(batch_id,)).fetchone()
    if not settlement:return {'decision':'blocked','reason':'unknown_settlement'}
    if not _is_banked(db,batch_id):return {'decision':'blocked','reason':'batch_not_banked'}
    slip=db.execute('SELECT * FROM migration_slips WHERE id=? AND batch=?',(slip_id,batch_id)).fetchone()
    if not slip or not slip['complete']:return {'decision':'blocked','reason':'slip_not_complete'}
    rid='%s|resolve|%s'%(batch_id,slip_id)
    previous=db.execute('SELECT digest FROM late_resolutions WHERE id=?',(rid,)).fetchone()
    rdigest=fingerprint({'batch':batch_id,'slip':slip_id,'action':action})
    if previous:
        return {'decision':'replay','resolution':rid} if previous['digest']==rdigest else {'decision':'blocked','reason':'resolution_conflict'}
    window=db.execute('''SELECT * FROM settlement_entries WHERE batch=? AND serial=? AND container=?
                         AND minute>=? AND minute<?''',
                      (batch_id,slip['serial'],slip['container'],slip['from_minute'],slip['to_minute'])).fetchall()
    if not window:return {'decision':'blocked','reason':'no_entries_in_slip_window'}
    unresolved=[e for e in window if e['status']=='unresolved']
    misattributed=[e for e in window if e['status']=='confirmed' and e['tenant']!=slip['tenant']]
    if not unresolved and not misattributed:
        return {'decision':'blocked','reason':'nothing_to_resolve'}
    total=sum(e['unit_seconds'] for e in unresolved)+sum(e['unit_seconds'] for e in misattributed)
    adjustments=[];new_invoices=[];deposit_event=None;provision_event=None
    needs_balance=bool(unresolved)
    if needs_balance:
        if settlement['policy']=='loss_provision':
            prov=db.execute("SELECT * FROM loss_provisions WHERE batch=? AND state='reserved'",(batch_id,)).fetchone()
            if not prov or prov['unit_seconds']<sum(e['unit_seconds'] for e in unresolved):
                return {'decision':'blocked','reason':'provision_unavailable'}
            db.execute("UPDATE loss_provisions SET state='released' WHERE id=?",(prov['id'],))
            provision_event={'provision':prov['id'],'state':'released','unit_seconds':sum(e['unit_seconds'] for e in unresolved)}
        else:
            dep=db.execute("SELECT * FROM group_deposits WHERE batch=? AND state='received'",(batch_id,)).fetchone()
            if not dep or dep['unit_seconds']<sum(e['unit_seconds'] for e in unresolved):
                return {'decision':'blocked','reason':'deposit_unavailable'}
            new_state='offset' if action=='offset' else 'refunded'
            # Double-collect guard: the final usage invoice may exist only after
            # the deposit covering those core-seconds has been offset or refunded.
            db.execute('UPDATE group_deposits SET state=? WHERE id=?',(new_state,dep['id']))
            deposit_event={'deposit':dep['id'],'state':new_state,'unit_seconds':sum(e['unit_seconds'] for e in unresolved)}
    for e in misattributed:
        old_invoice='%s|inv|%s|%s|%s'%(batch_id,e['serial'],e['minute'],e['tenant'])
        adj_id='%s|rev|%s|%s'%(batch_id,e['id'],slip['tenant'])
        adj_digest=fingerprint({'invoice':old_invoice,'kind':'reversal','unit_seconds':e['unit_seconds'],'slip':slip_id})
        res=tenant_charge.add_adjustment(db,adj_id,batch_id,old_invoice,'reversal',e['unit_seconds'],
                                         'late_migration_slip:%s'%slip_id,adj_digest)
        if res['decision']=='blocked':return res
        adjustments.append({'adjustment':adj_id,'invoice':old_invoice,'kind':'reversal','unit_seconds':e['unit_seconds']})
        db.execute("UPDATE settlement_entries SET tenant=? WHERE id=?",(slip['tenant'],e['id']))
    for e in unresolved+misattributed:
        if e in unresolved:
            db.execute("UPDATE settlement_entries SET status='confirmed',tenant=? WHERE id=?",(slip['tenant'],e['id']))
        iid='%s|late|%s|%s|%s'%(batch_id,e['serial'],e['minute'],slip['tenant'])
        idigest=fingerprint({'batch':batch_id,'tenant':slip['tenant'],'serial':e['serial'],'minute':e['minute'],'unit_seconds':e['unit_seconds'],'late':True})
        res=tenant_charge.confirmed_issue(db,iid,batch_id,slip['tenant'],e['serial'],e['minute'],e['unit_seconds'],idigest)
        if res['decision']=='blocked':return res
        # The invoice itself stays open; only an actual bank batch marks it issued.
        new_invoices.append({'invoice':iid,'tenant':slip['tenant'],'serial':e['serial'],'minute':e['minute'],'unit_seconds':e['unit_seconds']})
    if unresolved:
        db.execute('UPDATE settlements SET unresolved_seconds=unresolved_seconds-? WHERE batch=?',
                   (sum(e['unit_seconds'] for e in unresolved),batch_id))
    db.execute('INSERT INTO late_resolutions VALUES(?,?,?,?)',(rid,batch_id,slip_id,rdigest))
    record(db,'physical',rid,'resolve_late',1,
           {'batch':batch_id,'slip':slip_id,'action':action,'unit_seconds':total,'tenant':slip['tenant'],
            'new_invoices':new_invoices,'deposit':deposit_event,'provision':provision_event,'adjustments':adjustments})
    return {'decision':'resolved','batch':batch_id,'slip':slip_id,'tenant':slip['tenant'],'unit_seconds':total,
            'action':action,'new_invoices':new_invoices,'deposit':deposit_event,'provision':provision_event,'adjustments':adjustments}

def _recourse(db,x):
    batch_id=x['batch']
    digest=fingerprint({'batch':batch_id,'payable':x['payable'],'unit_seconds':x['unit_seconds'],'reason':x['reason']})
    res=vendor_payable.add_recourse(db,x['id'],batch_id,x['payable'],x['unit_seconds'],x['reason'],digest)
    if res['decision']=='blocked':return res
    record(db,'physical',x['id'],'recourse_vendor',1,
           {'batch':batch_id,'payable':x['payable'],'unit_seconds':x['unit_seconds'],'reason':x['reason']})
    return res

def physical_state(db,batch_id):
    """Read-only view used by audit and tests: what the two ledgers currently say."""
    init(db)
    settlement=db.execute('SELECT * FROM settlements WHERE batch=?',(batch_id,)).fetchone()
    if not settlement:return {'decision':'unknown_batch','batch':batch_id}
    obs=db.execute('SELECT serial,minute,COALESCE(SUM(unit_seconds),0) AS s FROM physical_observations WHERE batch=? GROUP BY serial,minute ORDER BY serial,minute',(batch_id,)).fetchall()
    ctl=db.execute('SELECT serial,minute,unit_seconds FROM controller_counts WHERE batch=? ORDER BY serial,minute',(batch_id,)).fetchall()
    return {'decision':'state','batch':batch_id,
            'observed':[dict(r) for r in obs],'controller':[dict(r) for r in ctl],
            'settlement':dict(settlement),
            'payables':[dict(r) for r in db.execute('SELECT * FROM physical_payables WHERE batch=? ORDER BY id',(batch_id,))],
            'invoices':[dict(r) for r in db.execute('SELECT * FROM tenant_invoices WHERE batch=? ORDER BY id',(batch_id,))],
            'invoice_adjustments':[dict(r) for r in db.execute('SELECT * FROM tenant_invoice_adjustments ORDER BY id')],
            'recourse':[dict(r) for r in db.execute('SELECT * FROM vendor_adjustments ORDER BY id')],
            'provisions':[dict(r) for r in db.execute('SELECT * FROM loss_provisions WHERE batch=? ORDER BY id',(batch_id,))],
            'deposits':[dict(r) for r in db.execute('SELECT * FROM group_deposits WHERE batch=? ORDER BY id',(batch_id,))],
            'bank_batches':[dict(r) for r in db.execute('SELECT * FROM bank_batches WHERE batch=? ORDER BY id',(batch_id,))],
            'entries':[dict(r) for r in db.execute('SELECT * FROM settlement_entries WHERE batch=? ORDER BY id',(batch_id,))]}

def unresolved(db,batch_id):
    init(db)
    return [dict(r) for r in db.execute("SELECT * FROM settlement_entries WHERE batch=? AND status='unresolved' ORDER BY id",(batch_id,))]
