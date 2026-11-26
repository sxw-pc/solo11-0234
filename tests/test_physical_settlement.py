import tempfile,unittest
from pathlib import Path
from cloudlab.store import connect,fingerprint,digest_bytes,snapshot_tables,rebuild
from cloudlab import physical_meter,meter_capture,vendor_payable,tenant_charge,wave
import cloudlab

BATCH='B1'
SERIAL_A='serial-A';SERIAL_B='serial-B'
T1='t1';T2='t2'

def make_evidence(page_id,lines,serials,tamper=None):
    page_digest=fingerprint({'page':page_id,'lines':lines})
    raw='RAW|%s'%page_id
    clock_parent={'clock':'genesis'}
    clock={'digest':fingerprint(clock_parent),'parent':clock_parent}
    chain=[];previous=page_digest
    for serial in serials:
        entry={'serial':serial,'digest':fingerprint({'previous':previous,'serial':serial})}
        chain.append(entry);previous=entry['digest']
    ev={'page_digest':page_digest,'raw':raw,'raw_digest':digest_bytes(raw),
        'clock':clock,'serial_chain':chain}
    if tamper=='raw':ev['raw_digest']='0'*64
    if tamper=='chain':ev['serial_chain'][0]['digest']='broken'
    if tamper=='clock':ev['clock']['digest']='broken'
    return ev

def line(host,tenant,minute,seconds,container):
    return {'host':host,'tenant':tenant,'minute':minute,'unit_seconds':seconds,'container':container}

class PhysicalSettlementTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.db=connect(str(Path(self.tmp.name)/'physical.sqlite'))
        physical_meter.init(self.db);vendor_payable.init(self.db);tenant_charge.init(self.db);wave.init(self.db)

    def tearDown(self):
        self.db.close();self.tmp.cleanup()

    def register_topology(self,relabel=False):
        pm=physical_meter
        self.assertEqual(pm.run(self.db,{'op':'register_host','id':'hA','serial':SERIAL_A,'vendor':'v-alpha'})['decision'],'registered')
        self.assertEqual(pm.run(self.db,{'op':'register_host','id':'hB','serial':SERIAL_B,'vendor':'v-alpha'})['decision'],'registered')
        for vendor,alias_a,alias_b in (('v-alpha','alpha-A','alpha-B'),('v-beta','beta-A','beta-B')):
            self.assertEqual(pm.run(self.db,{'op':'register_alias','id':'%s-a'%vendor,'vendor':vendor,'alias':alias_a,'serial':SERIAL_A,'since_minute':0})['decision'],'registered')
            self.assertEqual(pm.run(self.db,{'op':'register_alias','id':'%s-b'%vendor,'vendor':vendor,'alias':alias_b,'serial':SERIAL_B,'since_minute':0})['decision'],'registered')
        if relabel:
            self.assertEqual(pm.run(self.db,{'op':'register_alias','id':'relabel-a','vendor':'v-alpha','alias':'alpha-R','serial':SERIAL_A,'since_minute':11})['decision'],'registered')

    def register_motion(self,motion_id='M1',barcode='MB-0010-7788',window_id='W1'):
        wave_id='w1' if window_id=='W1' else 'w2'
        self.assertEqual(wave.run(self.db,{'op':'physical_window','id':window_id,'wave_id':wave_id,
                                           'serial':SERIAL_A,'from_minute':9,'to_minute':11})['decision'],'registered')
        self.assertEqual(wave.run(self.db,{'op':'vm_motion','id':motion_id,'window_id':window_id,'serial':SERIAL_A,'container':'c1',
                                           'from_minute':9,'to_minute':11,'barcode':barcode})['decision'],'registered')

    def controller_counts(self,a=60,b=30):
        for serial,minute,seconds in ((SERIAL_A,10,a),(SERIAL_B,10,b)):
            r=physical_meter.run(self.db,{'op':'controller_count','id':'%s-%s'%(serial,minute),'batch':BATCH,
                                          'serial':serial,'minute':minute,'unit_seconds':seconds})
            self.assertEqual(r['decision'],'registered')

    def ingest_portal_pages(self,relabel=False):
        lines_alpha=[line('alpha-A',T1,10,60,'c1'),line('alpha-B',T2,10,30,'c2')]
        lines_beta=[line('beta-A',T1,10,60,'c1'),line('beta-B',T2,10,30,'c2')]
        ev1=make_evidence('p-alpha',lines_alpha,[SERIAL_A,SERIAL_B])
        ev2=make_evidence('p-beta',lines_beta,[SERIAL_A,SERIAL_B])
        r1=physical_meter.run(self.db,{'op':'ingest_page','id':'p-alpha','batch':BATCH,'page_id':'p-alpha',
                                       'vendor':'v-alpha','lines':lines_alpha,'evidence':ev1})
        self.assertEqual(r1['decision'],'ingested');self.assertEqual(r1['accepted'],2)
        r2=physical_meter.run(self.db,{'op':'ingest_page','id':'p-beta','batch':BATCH,'page_id':'p-beta',
                                       'vendor':'v-beta','lines':lines_beta,'evidence':ev2})
        self.assertEqual(r2['accepted'],0);self.assertEqual(r2['duplicates'],2)
        # Host B's 30 core-seconds are undisputed: the portal label is promoted
        # to an anchored owner assertion. Host A is deliberately left unasserted.
        self.assertEqual(physical_meter.run(self.db,{'op':'assert_owner','id':'own-b','batch':BATCH,
                                                     'serial':SERIAL_B,'container':'c2','tenant':T2,
                                                     'anchor':'controller-anchor-B'})['decision'],'registered')
        return lines_alpha,lines_beta

    def add_slip(self,slip_id,complete,tenant=T1,barcode='MB-0010-XXXX',motion_ref=None):
        payload={'op':'migration_slip','id':slip_id,'batch':BATCH,'serial':SERIAL_A,'container':'c1',
                 'from_minute':9,'to_minute':11,'barcode':barcode,'tenant':tenant if complete else None,
                 'motion_ref':motion_ref,'complete':complete}
        return physical_meter.run(self.db,payload)

    def settle(self,policy='loss_provision'):
        return physical_meter.run(self.db,{'op':'settle','id':'settle','batch':BATCH,'policy':policy})

    def dispatch_payment(self,bank_id='BK1'):
        return physical_meter.run(self.db,{'op':'dispatch_bank','id':bank_id,'batch':BATCH,'bank_batch':bank_id,
                                           'kind':'payment','unit_seconds':90})

    def canonical(self,policy='loss_provision',slip='partial',bank=True):
        self.register_topology()
        self.ingest_portal_pages()
        self.controller_counts()
        if slip=='partial':
            r=self.add_slip('s1',complete=False)
            self.assertFalse(r['complete'])
        elif slip=='complete-t1':
            self.register_motion()
            r=self.add_slip('s1',complete=True,tenant=T1,barcode='MB-0010-7788',motion_ref='M1')
            self.assertTrue(r['complete'])
        settled=self.settle(policy)
        if bank:
            self.assertEqual(self.dispatch_payment()['decision'],'banked')
            if policy=='group_deposit':
                self.assertEqual(physical_meter.run(self.db,{'op':'dispatch_bank','id':'DP1','batch':BATCH,'bank_batch':'DP1',
                                                              'kind':'deposit_receipt','unit_seconds':60})['decision'],'banked')
        return settled

    # 1. cross-vendor duplicate pages: each physical host-minute is paid once
    def test_cross_vendor_duplicate_pages_pay_once(self):
        settled=self.canonical(bank=False)
        self.assertEqual(settled['physical_total'],90)
        rows=self.db.execute('SELECT serial,minute,SUM(unit_seconds) FROM physical_payables GROUP BY serial,minute').fetchall()
        self.assertEqual({(r[0],r[1],r[2]) for r in rows},{(SERIAL_A,10,60),(SERIAL_B,10,30)})
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM physical_payables').fetchone()[0],2)
        self.assertEqual(self.db.execute('SELECT COALESCE(SUM(unit_seconds),0) FROM physical_payables').fetchone()[0],90)

    # 2. chassis relabel: alias history resolves both labels to one physical host
    def test_chassis_relabel_does_not_create_compute(self):
        self.register_topology(relabel=True)
        lines_old=[line('alpha-A',T1,10,60,'c1'),line('alpha-B',T2,10,30,'c2')]
        lines_new=[line('alpha-R',T1,11,40,'c1')]
        physical_meter.run(self.db,{'op':'ingest_page','id':'p1','batch':BATCH,'page_id':'p1','vendor':'v-alpha',
                                    'lines':lines_old,'evidence':make_evidence('p1',lines_old,[SERIAL_A,SERIAL_B])})
        physical_meter.run(self.db,{'op':'ingest_page','id':'p2','batch':BATCH,'page_id':'p2','vendor':'v-alpha',
                                    'lines':lines_new,'evidence':make_evidence('p2',lines_new,[SERIAL_A])})
        self.controller_counts(a=60,b=30)
        physical_meter.run(self.db,{'op':'controller_count','id':'%s-11'%SERIAL_A,'batch':BATCH,
                                    'serial':SERIAL_A,'minute':11,'unit_seconds':40})
        settled=self.settle()
        serials={p['serial'] for p in settled['payables']}
        self.assertEqual(serials,{SERIAL_A,SERIAL_B})
        self.assertEqual(settled['physical_total'],130)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM physical_hosts').fetchone()[0],2)

    # 3. raw byte chain: page summary, clock calibration, serial chain
    def test_evidence_chain_tamper_is_blocked(self):
        self.register_topology()
        lines=[line('alpha-A',T1,10,60,'c1')]
        for tamper,reason in (('raw','raw_digest_mismatch'),('chain','serial_chain_broken'),('clock','clock_chain_broken')):
            ev=make_evidence('bad-%s'%tamper,lines,[SERIAL_A],tamper=tamper)
            r=physical_meter.run(self.db,{'op':'ingest_page','id':'bad-%s'%tamper,'batch':BATCH,'page_id':'bad-%s'%tamper,
                                          'vendor':'v-alpha','lines':lines,'evidence':ev})
            self.assertEqual((r['decision'],r['reason']),('blocked',reason))
        r=physical_meter.run(self.db,{'op':'ingest_page','id':'noev','batch':BATCH,'page_id':'noev',
                                      'vendor':'v-alpha','lines':lines,'evidence':None})
        self.assertEqual((r['decision'],r['reason']),('blocked','raw_evidence_not_linked'))
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM meter_raw_pages').fetchone()[0],0)

    # 4. independent controller deviation blocks the whole money batch
    def test_controller_deviation_blocks_settlement(self):
        self.register_topology();self.ingest_portal_pages()
        self.controller_counts(a=61,b=30)
        r=self.settle()
        self.assertEqual((r['decision'],r['reason']),('blocked','controller_deviation'))
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM physical_payables').fetchone()[0],0)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM tenant_invoices').fetchone()[0],0)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM settlements').fetchone()[0],0)

    def test_missing_controller_count_blocks_settlement(self):
        self.register_topology();self.ingest_portal_pages()
        physical_meter.run(self.db,{'op':'controller_count','id':'only-a','batch':BATCH,'serial':SERIAL_A,'minute':10,'unit_seconds':60})
        r=self.settle()
        self.assertEqual(r['reason'],'controller_deviation')
        self.assertIn('missing_controller',r['detail'])

    # 5. portal label and earliest page are not ownership proof
    def test_label_and_arrival_order_are_not_proof(self):
        settled=self.canonical(bank=False)
        self.assertEqual(settled['unresolved_seconds'],60)
        invoices=settled['invoices']
        self.assertEqual(len(invoices),1)
        self.assertEqual((invoices[0]['tenant'],invoices[0]['unit_seconds']),(T2,30))
        unresolved=physical_meter.unresolved(self.db,BATCH)
        self.assertEqual(len(unresolved),1)
        self.assertEqual(unresolved[0]['unit_seconds'],60)
        self.assertIsNone(unresolved[0]['tenant'])

    # 6. migration across minutes with a complete barcode proves the tenant
    def test_migration_across_minutes_confirms_attribution(self):
        self.register_topology();self.ingest_portal_pages();self.controller_counts()
        self.register_motion()
        r=self.add_slip('s1',complete=True,tenant=T2,barcode='MB-0010-7788',motion_ref='M1')
        self.assertTrue(r['complete'])
        settled=self.settle()
        self.assertEqual(settled['unresolved_seconds'],0)
        tenants=sorted((i['tenant'],i['unit_seconds']) for i in settled['invoices'])
        self.assertEqual(tenants,[(T2,30),(T2,60)])
        # a complete slip claiming a tenant without a window motion is rejected
        bad=self.add_slip('s-bad',complete=True,tenant=T1,barcode='MB-0010-1111',motion_ref='NOPE')
        self.assertEqual((bad['decision'],bad['reason']),('blocked','unknown_motion_ref'))

    # 6b. two complete but contradictory histories keep the seconds unresolved
    def test_contradictory_complete_histories_remain_unresolved(self):
        self.register_topology();self.ingest_portal_pages();self.controller_counts()
        self.register_motion('M1',barcode='MB-0010-7788')
        self.register_motion('M3',window_id='W2',barcode='MB-0010-7799')
        self.add_slip('s-t1',complete=True,tenant=T1,barcode='MB-0010-7788',motion_ref='M1')
        self.add_slip('s-t2',complete=True,tenant=T2,barcode='MB-0010-7799',motion_ref='M3')
        settled=self.settle()
        # both histories are compatible with the original bytes, so host A stays unowned
        self.assertEqual(settled['unresolved_seconds'],60)
        self.assertEqual([i['tenant'] for i in settled['invoices']],[T2])
        # vendor is still paid the full physical total; only the customer bill waits
        self.assertEqual(sum(p['unit_seconds'] for p in settled['payables']),90)

    # 5b. even anchored owner assertions split between two tenants cannot pick one
    def test_conflicting_owner_assertions_are_not_invoiced(self):
        self.register_topology();self.ingest_portal_pages();self.controller_counts()
        physical_meter.run(self.db,{'op':'assert_owner','id':'own-a1','batch':BATCH,'serial':SERIAL_A,
                                    'container':'c1','tenant':T1,'anchor':'anchor-1'})
        physical_meter.run(self.db,{'op':'assert_owner','id':'own-a2','batch':BATCH,'serial':SERIAL_A,
                                    'container':'c1','tenant':T2,'anchor':'anchor-2'})
        settled=self.settle()
        self.assertEqual(settled['unresolved_seconds'],60)
        self.assertEqual(sorted(i['tenant'] for i in settled['invoices']),[T2])
        self.assertEqual(tenant_charge.net_billed(self.db,T1),0)

    # 6c. a motion spanning multiple minutes attributes each minute independently
    def test_motion_spanning_minutes_attributes_each_minute(self):
        pm=physical_meter
        self.register_topology()
        lines=[line('alpha-A',T1,10,60,'c1'),line('alpha-A',T1,11,40,'c1'),
               line('alpha-B',T2,10,30,'c2'),line('alpha-B',T2,11,20,'c2')]
        pm.run(self.db,{'op':'ingest_page','id':'p','batch':BATCH,'page_id':'p','vendor':'v-alpha',
                        'lines':lines,'evidence':make_evidence('p',lines,[SERIAL_A,SERIAL_B])})
        pm.run(self.db,{'op':'assert_owner','id':'own-b','batch':BATCH,'serial':SERIAL_B,'container':'c2','tenant':T2,'anchor':'anchor-B'})
        for serial,minute,seconds in ((SERIAL_A,10,60),(SERIAL_A,11,40),(SERIAL_B,10,30),(SERIAL_B,11,20)):
            pm.run(self.db,{'op':'controller_count','id':'%s-%s'%(serial,minute),'batch':BATCH,'serial':serial,'minute':minute,'unit_seconds':seconds})
        # motion covers minute 10 only; minute 11 on host A has no proof
        self.assertEqual(wave.run(self.db,{'op':'physical_window','id':'W1','wave_id':'w1','serial':SERIAL_A,'from_minute':9,'to_minute':11})['decision'],'registered')
        wave.run(self.db,{'op':'vm_motion','id':'M1','window_id':'W1','serial':SERIAL_A,'container':'c1',
                          'from_minute':9,'to_minute':11,'barcode':'MB-0010-7788'})
        pm.run(self.db,{'op':'migration_slip','id':'s1','batch':BATCH,'serial':SERIAL_A,'container':'c1',
                        'from_minute':9,'to_minute':11,'barcode':'MB-0010-7788','tenant':T1,'motion_ref':'M1','complete':True})
        settled=self.settle()
        by_key={(e['serial'],e['minute']):(e['status'],e['tenant']) for e in physical_meter.physical_state(self.db,BATCH)['entries']}
        self.assertEqual(by_key[(SERIAL_A,10)],('confirmed',T1))
        self.assertEqual(by_key[(SERIAL_A,11)],('unresolved',None))
        self.assertEqual(settled['unresolved_seconds'],40)
        self.assertEqual(settled['physical_total'],150)

    # 7. instruction one: operator loss reserve, no external payment from tenant A
    def test_loss_provision_policy(self):
        settled=self.canonical(policy='loss_provision')
        self.assertEqual(settled['physical_total'],90)
        prov=self.db.execute('SELECT * FROM loss_provisions').fetchone()
        self.assertEqual((prov['unit_seconds'],prov['state']),(60,'reserved'))
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM group_deposits').fetchone()[0],0)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM tenant_invoices WHERE tenant=?',(T1,)).fetchone()[0],0)
        bank=self.db.execute('SELECT * FROM bank_batches').fetchone()
        self.assertEqual((bank['kind'],bank['outbound']),('payment',90))
        self.assertTrue(all(r['state']=='paid' for r in self.db.execute('SELECT state FROM physical_payables')))
        self.assertEqual(tenant_charge.net_billed(self.db),30)

    # 8. instruction two: group prepaid guarantee is a liability, never usage revenue
    def test_group_deposit_is_liability_not_revenue(self):
        self.canonical(policy='group_deposit',bank=False)
        self.dispatch_payment()
        # deposit amount must match the unresolved core-seconds before receipt
        bad=physical_meter.run(self.db,{'op':'dispatch_bank','id':'DP2','batch':BATCH,'bank_batch':'DP2',
                                        'kind':'deposit_receipt','unit_seconds':59})
        self.assertEqual(bad['reason'],'deposit_amount_conflict')
        self.assertEqual(physical_meter.run(self.db,{'op':'dispatch_bank','id':'DP1','batch':BATCH,'bank_batch':'DP1',
                                                      'kind':'deposit_receipt','unit_seconds':60})['decision'],'banked')
        dep=self.db.execute('SELECT * FROM group_deposits').fetchone()
        self.assertEqual((dep['unit_seconds'],dep['state']),(60,'received'))
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM loss_provisions').fetchone()[0],0)
        self.assertEqual(tenant_charge.net_billed(self.db),30)
        kinds={r['kind'] for r in self.db.execute('SELECT kind FROM bank_batches')}
        self.assertEqual(kinds,{'payment','deposit_receipt'})

    # 9. same physical facts, both legal instructions: identical resource ledgers, different cash
    def test_both_policies_share_physical_facts_but_diverge_in_cash(self):
        def build(policy):
            db=connect(str(Path(self.tmp.name)/('%s.sqlite'%policy)))
            saved=self.db;self.db=db
            self.canonical(policy=policy)
            state=physical_meter.physical_state(db,BATCH)
            self.db=saved
            return state
        loss=build('loss_provision');deposit=build('group_deposit')
        self.assertEqual([(p['serial'],p['minute'],p['unit_seconds'],p['state']) for p in loss['payables']],
                         [(p['serial'],p['minute'],p['unit_seconds'],p['state']) for p in deposit['payables']])
        self.assertEqual([(i['tenant'],i['unit_seconds']) for i in loss['invoices']],
                         [(i['tenant'],i['unit_seconds']) for i in deposit['invoices']])
        self.assertEqual(loss['settlement']['physical_total'],deposit['settlement']['physical_total'])
        self.assertEqual({b['kind'] for b in loss['bank_batches']},{'payment'})
        self.assertEqual({b['kind'] for b in deposit['bank_batches']},{'payment','deposit_receipt'})
        self.assertEqual(loss['provisions'][0]['state'],'reserved')
        self.assertEqual(deposit['deposits'][0]['state'],'received')

    # 10. banked documents are immutable; late slip releases reserve and supplements
    def test_late_slip_after_bank_releases_provision_and_keeps_originals(self):
        self.canonical(policy='loss_provision')
        before_pay=[tuple(r) for r in self.db.execute('SELECT * FROM physical_payables ORDER BY id')]
        before_inv=[tuple(r) for r in self.db.execute('SELECT * FROM tenant_invoices ORDER BY id')]
        self.register_motion('M2',window_id='W2',barcode='MB-0010-7788')
        late=self.add_slip('s-late',complete=True,tenant=T1,barcode='MB-0010-7788',motion_ref='M2')
        self.assertTrue(late['complete'])
        r=physical_meter.run(self.db,{'op':'resolve_late','id':'r1','batch':BATCH,'slip_id':'s-late'})
        self.assertEqual((r['decision'],r['unit_seconds'],r['tenant']),('resolved',60,T1))
        self.assertEqual(self.db.execute("SELECT state FROM loss_provisions").fetchone()[0],'released')
        late_inv=self.db.execute("SELECT * FROM tenant_invoices WHERE id LIKE '%late%'").fetchone()
        self.assertEqual((late_inv['tenant'],late_inv['unit_seconds'],late_inv['state']),(T1,60,'open'))
        # originals remain byte-identical
        self.assertEqual(before_pay,[tuple(r) for r in self.db.execute('SELECT * FROM physical_payables ORDER BY id')])
        self.assertEqual(before_inv,[tuple(r) for r in self.db.execute('SELECT * FROM tenant_invoices WHERE id NOT LIKE "%late%" ORDER BY id')])
        # the new invoice rides a new bank batch; the old batch is untouched
        physical_meter.run(self.db,{'op':'dispatch_bank','id':'BK2','batch':BATCH,'bank_batch':'BK2',
                                    'kind':'payment','unit_seconds':0})
        self.assertEqual(self.db.execute("SELECT state FROM tenant_invoices WHERE id=?",(late_inv['id'],)).fetchone()[0],'issued')
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM bank_batches').fetchone()[0],2)
        # retry is idempotent
        self.assertEqual(physical_meter.run(self.db,{'op':'resolve_late','id':'r1','batch':BATCH,'slip_id':'s-late'})['decision'],'replay')

    # 11. late evidence proving another real tenant: reversal voucher + supplement, no double collect
    def test_late_slip_reverses_wrong_invoice_and_supplements_real_tenant(self):
        self.canonical(slip='complete-t1',policy='loss_provision')
        self.assertEqual(tenant_charge.net_billed(self.db,T1),60)
        self.register_motion('M2',window_id='W2',barcode='MB-0010-9900')
        self.add_slip('s-late',complete=True,tenant=T2,barcode='MB-0010-9900',motion_ref='M2')
        r=physical_meter.run(self.db,{'op':'resolve_late','id':'r2','batch':BATCH,'slip_id':'s-late'})
        self.assertEqual(r['decision'],'resolved')
        adj=self.db.execute("SELECT * FROM tenant_invoice_adjustments WHERE kind='reversal'").fetchall()
        self.assertEqual(len(adj),1)
        self.assertEqual(adj[0]['unit_seconds'],60)
        # original wrong invoice is retained and traceable
        original=self.db.execute("SELECT * FROM tenant_invoices WHERE tenant=? AND id NOT LIKE '%late%'",(T1,)).fetchone()
        self.assertEqual(original['state'],'issued')
        self.assertEqual(adj[0]['invoice'],original['id'])
        self.assertEqual(tenant_charge.net_billed(self.db,T1),0)
        self.assertEqual(tenant_charge.net_billed(self.db,T2),90)

    # 12. group deposit double-collect guard and idempotent offset
    def test_deposit_double_collect_guard(self):
        self.canonical(policy='group_deposit',bank=False)
        self.dispatch_payment()
        self.register_motion('M2',window_id='W2',barcode='MB-0010-7788')
        self.add_slip('s-late',complete=True,tenant=T1,barcode='MB-0010-7788',motion_ref='M2')
        # before the group actually funds the guarantee, no final usage invoice may appear
        r=physical_meter.run(self.db,{'op':'resolve_late','id':'r3','batch':BATCH,'slip_id':'s-late'})
        self.assertEqual((r['decision'],r['reason']),('blocked','deposit_unavailable'))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM tenant_invoices WHERE id LIKE '%late%'").fetchone()[0],0)
        physical_meter.run(self.db,{'op':'dispatch_bank','id':'DP1','batch':BATCH,'bank_batch':'DP1',
                                    'kind':'deposit_receipt','unit_seconds':60})
        ok=physical_meter.run(self.db,{'op':'resolve_late','id':'r3','batch':BATCH,'slip_id':'s-late','action':'offset'})
        self.assertEqual(ok['decision'],'resolved')
        self.assertEqual(self.db.execute("SELECT state FROM group_deposits").fetchone()[0],'offset')
        self.assertEqual(physical_meter.run(self.db,{'op':'resolve_late','id':'r3','batch':BATCH,'slip_id':'s-late','action':'offset'})['decision'],'replay')

    # 13. refund path: guarantee cash goes back before/while final invoice is issued
    def test_deposit_refund_path(self):
        self.canonical(policy='group_deposit')
        self.register_motion('M2',window_id='W2',barcode='MB-0010-7788')
        self.add_slip('s-late',complete=True,tenant=T1,barcode='MB-0010-7788',motion_ref='M2')
        r=physical_meter.run(self.db,{'op':'resolve_late','id':'r4','batch':BATCH,'slip_id':'s-late','action':'refund'})
        self.assertEqual(r['decision'],'resolved')
        self.assertEqual(self.db.execute("SELECT state FROM group_deposits").fetchone()[0],'refunded')
        self.assertEqual([tuple(r) for r in self.db.execute("SELECT tenant,SUM(unit_seconds) FROM tenant_invoices GROUP BY tenant").fetchall()],
                         [(T1,60),(T2,30)])

    # 14. vendor recourse is only possible after the bank batch
    def test_vendor_recourse_requires_banked_payment(self):
        self.canonical(bank=False)
        payable=self.db.execute('SELECT id FROM physical_payables LIMIT 1').fetchone()[0]
        early=physical_meter.run(self.db,{'op':'recourse_vendor','id':'rc1','batch':BATCH,'payable':payable,
                                          'unit_seconds':5,'reason':'late_credit'})
        self.assertEqual((early['decision'],early['reason']),('blocked','payable_not_banked'))
        self.dispatch_payment()
        ok=physical_meter.run(self.db,{'op':'recourse_vendor','id':'rc1','batch':BATCH,'payable':payable,
                                       'unit_seconds':5,'reason':'late_credit'})
        self.assertEqual(ok['decision'],'recorded')
        row=self.db.execute('SELECT * FROM vendor_adjustments').fetchone()
        self.assertEqual((row['kind'],row['unit_seconds'],row['payable']),('recourse',5,payable))
        # the paid payable itself is untouched
        self.assertEqual(tuple(self.db.execute('SELECT unit_seconds,state FROM physical_payables WHERE id=?',(payable,)).fetchone()),
                         (60 if SERIAL_A in payable else 30,'paid'))
        self.assertEqual(physical_meter.run(self.db,{'op':'recourse_vendor','id':'rc1','batch':BATCH,'payable':payable,
                                                     'unit_seconds':5,'reason':'late_credit'})['decision'],'replay')

    # 15. audit / power loss: both real ledgers rebuild from the evidence log
    def test_rebuild_both_ledgers_from_evidence(self):
        self.canonical(policy='group_deposit')
        self.register_motion('M2',window_id='W2',barcode='MB-0010-7788')
        self.add_slip('s-late',complete=True,tenant=T1,barcode='MB-0010-7788',motion_ref='M2')
        physical_meter.run(self.db,{'op':'resolve_late','id':'r5','batch':BATCH,'slip_id':'s-late'})
        path=str(Path(self.tmp.name)/'physical.sqlite')
        modules={'physical':physical_meter,'wave':wave}
        fresh,verification=rebuild(path,modules)
        self.assertTrue(verification['verified'],verification['divergences'])
        tables=['physical_hosts','host_aliases','physical_observations','controller_counts','migration_slips',
                'settlements','settlement_entries','physical_payables','tenant_invoices','group_deposits',
                'bank_batches','late_resolutions','meter_pages','meter_lines','meter_raw_pages',
                'physical_windows','vm_motions','vendor_adjustments','tenant_invoice_adjustments','loss_provisions']
        self.assertEqual(snapshot_tables(self.db,tables),snapshot_tables(fresh,tables))
        fresh.close()

    # 16. retries never create duplicate money documents
    def test_idempotent_retries_and_conflict_detection(self):
        self.register_topology()
        host_payload={'op':'register_host','id':'hA','serial':SERIAL_A,'vendor':'v-alpha'}
        self.assertEqual(physical_meter.run(self.db,host_payload)['decision'],'replay')
        conflict=dict(host_payload,vendor='v-other')
        self.assertEqual(physical_meter.run(self.db,conflict)['reason'],'identity_conflict')
        self.ingest_portal_pages();self.controller_counts();self.add_slip('s1',complete=False)
        self.assertEqual(self.settle()['decision'],'settled')
        self.assertEqual(self.settle()['decision'],'replay')
        self.assertEqual(self.dispatch_payment()['decision'],'banked')
        self.assertEqual(self.dispatch_payment()['decision'],'replay')
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM physical_payables').fetchone()[0],2)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM bank_batches').fetchone()[0],1)
        # same bank batch id with different content is rejected
        clash=physical_meter.run(self.db,{'op':'dispatch_bank','id':'BK1','batch':BATCH,'bank_batch':'BK1',
                                          'kind':'payment','unit_seconds':91})
        self.assertEqual(clash['reason'],'bank_batch_conflict')

    # 17. unknown alias and conflicting page re-delivery
    def test_unknown_alias_and_page_conflict(self):
        self.register_topology()
        lines=[line('ghost-A',T1,10,60,'c1')]
        r=physical_meter.run(self.db,{'op':'ingest_page','id':'pg','batch':BATCH,'page_id':'pg','vendor':'v-alpha',
                                      'lines':lines,'evidence':make_evidence('pg',lines,[SERIAL_A])})
        self.assertEqual((r['decision'],r['reason']),('blocked','unregistered_host_alias'))
        good=[line('alpha-A',T1,10,60,'c1')]
        self.assertEqual(meter_capture.import_page(self.db,'dup','v-alpha','d1',good)['decision'],'imported')
        self.assertEqual(meter_capture.import_page(self.db,'dup','v-alpha','d2',good)['decision'],'page_conflict')
        self.assertEqual(meter_capture.import_page(self.db,'dup','v-alpha','d1',good)['decision'],'replay')

    # 18. unresolved core-seconds can never be pro-rated into a guessed invoice
    def test_unresolved_seconds_never_become_usage_revenue(self):
        settled=self.canonical(policy='loss_provision',bank=False)
        self.assertEqual(settled['unresolved_seconds'],60)
        # vendor obligation still lands even though customer attribution is open
        self.assertEqual(self.db.execute('SELECT COALESCE(SUM(unit_seconds),0) FROM physical_payables').fetchone()[0],90)
        # only the confirmed 30 may be invoiced
        self.assertEqual(tenant_charge.net_billed(self.db),30)
        states={e['status'] for e in physical_meter.physical_state(self.db,BATCH)['entries']}
        self.assertEqual(states,{'confirmed','unresolved'})

assert Path(cloudlab.__file__).resolve().is_relative_to(Path(__file__).resolve().parents[1])
if __name__=='__main__':unittest.main()
