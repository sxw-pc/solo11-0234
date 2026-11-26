import tempfile
import unittest
from pathlib import Path
import cloudlab
from cloudlab.store import connect,replay
from cloudlab import inventory,wave,source_custody,source_delivery


class SourceDelivery(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.db=connect(str(Path(self.tmp.name)/'x.sqlite'))

    def tearDown(self):
        self.db.close();self.tmp.cleanup()

    def _node(self,node,arch,gen=1,version='v1',zone='z'):
        inventory.run(self.db,dict(op='node',id=node,architecture=arch,features=['cgroup2'],
                                   generation=gen,observed_at=10,version=version,zone=zone))
        inventory.run(self.db,dict(op='verify',id=node,now=12,max_age=100,architecture=arch,
                                   features=['cgroup2'],deprecated_api='old/v1'))

    def _build(self,artifact,arch,bin_digest,rebuild=True):
        return source_custody.run(self.db,dict(
            op='build',id=artifact,target='v2',architecture=arch,binary_digest=bin_digest,
            build_inputs_digest='inputs-'+artifact,compiler='gcc-13.2',
            generated_code_digest='gen-'+artifact,embedded_resources_digest='res-'+artifact,
            rebuild_digest='rb-'+artifact,rebuild_verified=rebuild))

    def _component(self,artifact,revision,cdig,stage='build',parent=None,layer=None,sig=None):
        name='P'
        return source_custody.run(self.db,dict(
            op='component',artifact=artifact,component=name,stage=stage,
            source_revision=revision,component_digest=cdig,license='GPL-2.0',
            origin='https://example.test/P',parent_component=parent,layer_digest=layer,signature=sig))

    def _archive(self,aid,revision,cdig,complete=True):
        return source_custody.run(self.db,dict(
            op='archive',id=aid,component='P',source_revision=revision,component_digest=cdig,
            source_digest='src-'+aid,license='GPL-2.0',
            build_instructions_digest='build-'+aid,contents_digest='contents-'+aid,
            incomplete=not complete,at=20))

    def _attest(self,node,gen,revision,cdig):
        return inventory.run(self.db,dict(
            op='runtime_load',id=node,generation=gen,at=30,components=[
                dict(component='P',source_revision=revision,component_digest=cdig,
                     layer_digest='layer-'+cdig,signature='sig-'+cdig)]))

    def _certify(self,bundle,artifact,node=None,at=40):
        return source_custody.run(self.db,dict(
            op='certify',id=bundle,artifact=artifact,node=node,at=at))

    def _multiarch_fixture(self):
        # 固定原件: 同一目标字符串 v2, 两个架构各自构建, 二进制摘要不同
        self._node('n甲','amd64');self._node('n乙','arm64')
        self._build('art-amd64','amd64','digest-amd64')
        self._build('art-arm64','arm64','digest-arm64')
        self._component('art-amd64','revA','digA')
        self._component('art-arm64','revA','digA')
        self._archive('arc-A','revA','digA')
        # 启动后从签名镜像层加载同名组件修订乙 (仅 arm64)
        self._component('art-arm64','revB','digB',stage='runtime',layer='layer-digB',sig='sig-digB')
        # n甲 给出空装载证明 (静态二进制, 无启动后插件); n乙 证明实际加载修订乙
        inventory.run(self.db,dict(op='runtime_load',id='n甲',generation=1,at=30,components=[]))
        self._attest('n乙',1,'revB','digB')

    # 1. 多架构同版本: 同一 v2 字符串对应不同字节, 来源按二进制摘要分别固定
    def test_multiarch_same_target_has_distinct_artifact_identity(self):
        self._multiarch_fixture()
        a=source_custody.run(self.db,dict(op='shipping_manifest',artifact='art-amd64'))
        self.assertEqual(a['reason'],'no_active_bundle')
        self.assertEqual(self._certify('b-amd64','art-amd64','n甲')['decision'],'certified')
        # arm64 节点实际运行修订乙, 但修订乙源码尚未归档 -> 无法证明源码对应
        blocked=self._certify('b-arm64','art-arm64','n乙')
        self.assertEqual(blocked['reason'],'source_package_incomplete')
        self.assertEqual(blocked['missing'],[{'component':'P','component_digest':'digB','source_revision':'revB'}])
        rows=self.db.execute('SELECT architecture,binary_digest FROM artifacts ORDER BY architecture').fetchall()
        self.assertEqual([tuple(r) for r in rows],[('amd64','digest-amd64'),('arm64','digest-arm64')])

    # 2. 运行时插件替换: 出货清单必须以节点实际装载证明为准, 不能只列主镜像修订甲
    def test_runtime_plugin_revision_b_must_reach_customer_not_revision_a(self):
        self._multiarch_fixture()
        self._certify('b-amd64','art-amd64','n甲')
        self._archive('arc-B','revB','digB')
        cert=self._certify('b-arm64','art-arm64','n乙')
        self.assertEqual(cert['decision'],'certified')
        manifest=source_custody.run(self.db,dict(op='shipping_manifest',artifact='art-arm64',node='n乙'))
        self.assertEqual(manifest['archives'],
                         [{'bundle_id':'b-arm64','archive_id':'arc-B','component':'P','component_digest':'digB'}])
        eff=source_custody.effective_components(self.db,'art-arm64','n乙')
        self.assertEqual([(c['component'],c['source_revision'],c['stage']) for c in eff],[('P','revB','runtime')])

    # 3. 源码包缺件: 缺对应源码/构建说明时不签发完整出货清单
    def test_incomplete_archive_and_missing_material_block_certification(self):
        self._node('n甲','amd64')
        bad=self._build('art-bad','amd64','digest-bad',rebuild=False)
        self.assertEqual(bad['decision'],'registered')
        self._component('art-bad','revA','digA')
        inventory.run(self.db,dict(op='runtime_load',id='n甲',generation=1,at=30,components=[]))
        # 静态二进制无法重建 -> 不能签发
        self.assertEqual(self._certify('b-bad','art-bad','n甲')['reason'],'static_rebuild_unverified')
        good=self._build('art-good','amd64','digest-good')
        self._component('art-good','revA','digA')
        self._archive('arc-incomplete','revA','digA',complete=False)
        self.assertEqual(self._certify('b-good','art-good','n甲')['reason'],'source_package_incomplete')
        self.assertEqual(self.db.execute("SELECT state FROM source_bundles WHERE id='b-good'").fetchone()[0],'incomplete')

    def test_build_material_and_proof_fields_are_required(self):
        r=source_custody.run(self.db,dict(op='build',id='x',target='v2',architecture='amd64',
                                          binary_digest='d',compiler='gcc'))
        self.assertEqual(r['reason'],'incomplete_build_material')
        self.assertIn('build_inputs_digest',r['missing'])
        self.assertEqual(inventory.run(self.db,dict(
            op='runtime_load',id='ghost',generation=1,at=1,components=[]))['reason'],'unknown_node')
        self._node('n甲','amd64')
        stale=inventory.run(self.db,dict(op='runtime_load',id='n甲',generation=9,at=1,components=[]))
        self.assertEqual(stale['reason'],'stale_generation')
        bad_proof=inventory.run(self.db,dict(op='runtime_load',id='n甲',generation=1,at=1,components=[
            dict(component='P',source_revision='revB')]))
        self.assertEqual(bad_proof['reason'],'incomplete_load_proof')

    # 4. 直接附带交付: 客户立即取得与实际字节核对一致的源码包与回执
    def test_direct_delivery_customer_receives_matching_sources(self):
        self._multiarch_fixture();self._archive('arc-B','revB','digB')
        self._certify('b-arm64','art-arm64','n乙')
        source_delivery.run(self.db,dict(op='approve',id='ap',artifact='art-arm64',
                                         methods=['direct'],recipients=['C'],valid_until=100))
        dist=source_delivery.run(self.db,dict(op='distribute',id='d1',customer='C',node='n乙',
                                              artifact='art-arm64',entry='n乙',at=50,method='direct'))
        self.assertEqual(dist['decision'],'obligation_opened')
        # 修订甲的源码包不覆盖 n乙 实际运行的乙 -> 阻断
        self._certify('b-A-static','art-arm64')  # 无节点证明的静态清单, 仅含构建依赖 revA
        wrong=source_delivery.run(self.db,dict(op='deliver_direct',id='d1',bundle='b-A-static',at=51))
        self.assertEqual(wrong['reason'],'bundle_does_not_cover_running_bytes')
        ok=source_delivery.run(self.db,dict(op='deliver_direct',id='d1',bundle='b-arm64',at=52))
        self.assertEqual(ok['decision'],'received')
        self.assertEqual(ok['bundle_digest'],
                         self.db.execute("SELECT bundle_digest FROM source_bundles WHERE id='b-arm64'").fetchone()[0])
        receipt=self.db.execute("SELECT * FROM delivery_receipts WHERE distribution_id='d1' AND state='valid'").fetchone()
        self.assertEqual(receipt['method'],'direct')
        # 断电重试: 同一分发不得产生第二份相矛盾义务记录/回执
        again=source_delivery.run(self.db,dict(op='deliver_direct',id='d1',bundle='b-arm64',at=53))
        self.assertEqual(again['decision'],'reused')
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM delivery_obligations WHERE distribution_id='d1'").fetchone()[0],1)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM delivery_receipts WHERE distribution_id='d1'").fetchone()[0],1)
        redeliver=source_delivery.run(self.db,dict(op='distribute',id='d1',customer='C',node='n乙',
                                                   artifact='art-arm64',at=54,method='direct'))
        self.assertEqual(redeliver['decision'],'reused')

    # 5. 书面提供 + 独立托管: 函、申请、兑现凭据, 以及客户重复申请
    def test_written_offer_escrow_request_and_fulfillment(self):
        self._multiarch_fixture();self._archive('arc-B','revB','digB')
        self._certify('b-arm64','art-arm64','n乙')
        # 非独立保管人不接受
        source_delivery.run(self.db,dict(op='custodian',id='dep-internal',name='internal',independent=False))
        source_delivery.run(self.db,dict(op='custodian',id='dep1',name='escrow-co',independent=True))
        bad_escrow=source_delivery.run(self.db,dict(op='escrow',id='e-bad',custodian='dep-internal',
                                                    bundle='b-arm64',at=45))
        self.assertEqual(bad_escrow['reason'],'custodian_not_independent')
        source_delivery.run(self.db,dict(op='escrow',id='e1',custodian='dep1',bundle='b-arm64',at=46))
        source_delivery.run(self.db,dict(op='approve',id='ap2',artifact='art-arm64',
                                         methods=['written_offer'],recipients=['C'],valid_until=200))
        source_delivery.run(self.db,dict(op='distribute',id='d2',customer='C',node='n乙',
                                         artifact='art-arm64',at=50,method='written_offer'))
        offer=source_delivery.run(self.db,dict(op='offer',id='d2',offer='of1',escrow='e1',
                                               signature='sign-letter',valid_until=180,at=51))
        self.assertEqual(offer['decision'],'issued')
        # 客户申请 -> 托管人实际兑现, 取件凭据留存
        req=source_delivery.run(self.db,dict(op='request',id='r1',offer='of1',customer='C',
                                             at=60,credential='pickup-token-1'))
        self.assertEqual(req['decision'],'requested')
        # 重复申请不产生第二条请求
        dup=source_delivery.run(self.db,dict(op='request',id='r2',offer='of1',customer='C',
                                             at=61,credential='pickup-token-2'))
        self.assertEqual(dup['decision'],'reused')
        self.assertEqual(dup['credential'],'pickup-token-1')
        ful=source_delivery.run(self.db,dict(op='fulfill',id='r1',at=70))
        self.assertEqual(ful['decision'],'fulfilled')
        self.assertEqual(ful['bundle_digest'],
                         self.db.execute("SELECT bundle_digest FROM escrows WHERE id='e1'").fetchone()[0])
        # 兑现重试幂等
        self.assertEqual(source_delivery.run(self.db,dict(op='fulfill',id='r1',at=71))['decision'],'reused')
        receipt=self.db.execute("SELECT * FROM delivery_receipts WHERE distribution_id='d2' AND state='valid'").fetchone()
        self.assertEqual(receipt['method'],'written_offer')
        self.assertEqual(self.db.execute("SELECT state FROM delivery_obligations WHERE distribution_id='d2'").fetchone()[0],'fulfilled')

    # 6. 托管人失联: 挂起在途函件, 换独立托管重新托管, 或直接补发兜底
    def test_custodian_lost_suspends_offers_and_re_escrow_or_fallback_remedies(self):
        self._multiarch_fixture();self._archive('arc-B','revB','digB')
        self._certify('b-arm64','art-arm64','n乙')
        source_delivery.run(self.db,dict(op='custodian',id='dep1',name='co-1',independent=True))
        source_delivery.run(self.db,dict(op='custodian',id='dep2',name='co-2',independent=True))
        source_delivery.run(self.db,dict(op='escrow',id='e1',custodian='dep1',bundle='b-arm64',at=46))
        source_delivery.run(self.db,dict(op='approve',id='ap3',artifact='art-arm64',
                                         methods=['written_offer'],recipients=['C'],valid_until=200))
        source_delivery.run(self.db,dict(op='distribute',id='d3',customer='C',node='n乙',
                                         artifact='art-arm64',at=50,method='written_offer'))
        source_delivery.run(self.db,dict(op='offer',id='d3',offer='of3',escrow='e1',
                                         signature='s',valid_until=180,at=51))
        # 客户在失联前已提交源码申请并取得凭据
        source_delivery.run(self.db,dict(op='request',id='r3',offer='of3',customer='C',at=52,credential='tok-3'))
        lost=source_delivery.run(self.db,dict(op='custodian_lost',id='dep1',at=55))
        self.assertEqual(lost['escrows'],['e1'])
        self.assertEqual(self.db.execute("SELECT state FROM offer_letters WHERE id='of3'").fetchone()[0],'suspended')
        # 失联期间在途申请无法兑现
        self.assertEqual(source_delivery.run(self.db,dict(op='fulfill',id='r3',at=58))['reason'],'custodian_unreachable')
        # 重新托管, 函件恢复, 申请可兑现
        ree=source_delivery.run(self.db,dict(op='reescrow',id='e2',old_escrow='e1',custodian='dep2',at=59))
        self.assertEqual(ree['decision'],'re_escrowed')
        self.assertEqual(self.db.execute("SELECT state FROM offer_letters WHERE id='of3'").fetchone()[0],'issued')
        self.assertEqual(source_delivery.run(self.db,dict(op='fulfill',id='r3',at=60))['decision'],'fulfilled')
        # 第二个客户走兜底直发路径
        source_delivery.run(self.db,dict(op='approve',id='ap4',artifact='art-arm64',
                                         methods=['written_offer'],recipients=['D'],valid_until=200))
        source_delivery.run(self.db,dict(op='distribute',id='d4',customer='D',node='n乙',
                                         artifact='art-arm64',at=61,method='written_offer'))
        source_delivery.run(self.db,dict(op='offer',id='d4',offer='of4',escrow='e2',
                                         signature='s2',valid_until=180,at=62))
        source_delivery.run(self.db,dict(op='custodian_lost',id='dep2',at=63))
        fb=source_delivery.run(self.db,dict(op='fallback_direct',id='d4',bundle='b-arm64',at=64))
        self.assertEqual(fb['decision'],'received')
        self.assertEqual(self.db.execute("SELECT method FROM delivery_obligations WHERE distribution_id='d4'").fetchone()[0],
                         'direct_fallback')

    # 7. 后来发现漏入插件: 旧交付包不删除, 补发并标记客户
    def test_late_plugin_discovery_supersedes_rev_a_with_supplement_only(self):
        # 出货时节点只有空装载证明, 系统只知道主镜像修订甲
        self._node('n乙','arm64')
        self._build('art-arm64','arm64','digest-arm64')
        self._component('art-arm64','revA','digA')
        self._archive('arc-A','revA','digA')
        inventory.run(self.db,dict(op='runtime_load',id='n乙',generation=1,at=30,components=[]))
        self._certify('b-old','art-arm64','n乙')
        source_delivery.run(self.db,dict(op='approve',id='ap5',artifact='art-arm64',
                                         methods=['direct'],recipients=['C'],valid_until=200))
        source_delivery.run(self.db,dict(op='distribute',id='d5',customer='C',node='n乙',
                                         artifact='art-arm64',at=50,method='direct'))
        first=source_delivery.run(self.db,dict(op='deliver_direct',id='d5',bundle='b-old',at=51))
        self.assertEqual(first['decision'],'received')
        # 后来启动后加载的修订乙被证实 (新的装载证明), 旧清单被取代但行保留
        self._component('art-arm64','revB','digB',stage='runtime',layer='layer-digB',sig='sig-digB')
        self._attest('n乙',1,'revB','digB')
        self._archive('arc-B','revB','digB')
        newcert=self._certify('b-new','art-arm64','n乙',at=80)
        self.assertEqual(newcert['decision'],'certified')
        self.assertEqual(self.db.execute("SELECT state FROM source_bundles WHERE id='b-old'").fetchone()[0],'superseded')
        self.assertIsNotNone(self.db.execute("SELECT * FROM source_archives WHERE id='arc-A'").fetchone())
        # 同一分发的断电重试仍返回既有有效回执 (幂等, 不产生矛盾记录)
        self.assertEqual(source_delivery.run(self.db,dict(op='deliver_direct',id='d5',bundle='b-old',at=81))['decision'],'reused')
        # 旧包已被取代, 不能再支撑任何新分发的交付
        source_delivery.run(self.db,dict(op='distribute',id='d5b',customer='C',node='n乙',
                                         artifact='art-arm64',at=82,method='direct'))
        self.assertEqual(source_delivery.run(self.db,dict(
            op='deliver_direct',id='d5b',bundle='b-old',at=83))['reason'],'bundle_not_usable')
        sup=source_delivery.run(self.db,dict(op='supplement',id='d5',bundle='b-new',at=82,
                                             reason='runtime_plugin_discovered'))
        self.assertEqual(sup['decision'],'supplemented')
        self.assertTrue(sup['prior_retained'])
        rows=self.db.execute("SELECT bundle_id,state,superseded FROM delivery_receipts WHERE distribution_id='d5' ORDER BY received_at").fetchall()
        self.assertEqual([tuple(r) for r in rows],[('b-old','superseded',1),('b-new','valid',0)])
        flag=self.db.execute("SELECT * FROM customer_flags WHERE distribution_id='d5'").fetchone()
        self.assertEqual((flag['customer'],flag['reason'],flag['bundle_id']),('C','runtime_plugin_discovered','b-new'))
        # 补发重试幂等, 不产生矛盾记录
        again=source_delivery.run(self.db,dict(op='supplement',id='d5',bundle='b-new',at=83))
        self.assertEqual(again['decision'],'reused')
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM delivery_obligations WHERE distribution_id='d5'").fetchone()[0],1)

    # 8. 分发闸: 无运行时证明、流量入口不符、无预批准、内部备份均不构成客户收件
    def test_distribution_gates_and_internal_backup_is_not_receipt(self):
        self._multiarch_fixture();self._archive('arc-B','revB','digB')
        self._certify('b-arm64','art-arm64','n乙')
        # 没有运行时装载证明的节点不能分发
        self._node('n丙','arm64')
        no_attest=source_delivery.run(self.db,dict(op='distribute',id='dx',customer='X',node='n丙',
                                                   artifact='art-arm64',at=50,method='direct'))
        self.assertEqual(no_attest['reason'],'missing_runtime_attestation')
        # 架构不符
        wrong_arch=source_delivery.run(self.db,dict(op='distribute',id='dx',customer='X',node='n甲',
                                                    artifact='art-arm64',at=50,method='direct'))
        self.assertEqual(wrong_arch['reason'],'node_architecture_mismatch')
        # 客户流量入口与实际节点不符
        entry=source_delivery.run(self.db,dict(op='distribute',id='dx',customer='X',node='n乙',
                                               artifact='art-arm64',entry='n甲',at=50,method='direct'))
        self.assertEqual(entry['reason'],'traffic_entry_mismatch')
        # 法务未预批准
        no_approval=source_delivery.run(self.db,dict(op='distribute',id='dx',customer='X',node='n乙',
                                                     artifact='art-arm64',entry='n乙',at=50,method='direct'))
        self.assertEqual(no_approval['reason'],'no_valid_preapproval')
        source_delivery.run(self.db,dict(op='approve',id='apx',artifact='art-arm64',
                                         methods=['direct'],recipients=['X'],valid_until=200))
        source_delivery.run(self.db,dict(op='distribute',id='dx',customer='X',node='n乙',
                                         artifact='art-arm64',entry='n乙',at=50,method='direct'))
        # 仅内部备份归档: 义务保持 open, 无客户回执
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM delivery_receipts WHERE distribution_id='dx'").fetchone()[0],0)
        self.assertEqual(self.db.execute("SELECT state FROM delivery_obligations WHERE distribution_id='dx'").fetchone()[0],'open')
        # 批准期限届满后交付被拒
        source_delivery.run(self.db,dict(op='approve',id='apz',artifact='art-arm64',
                                         methods=['direct'],recipients=['Z'],valid_until=40))
        expired=source_delivery.run(self.db,dict(op='distribute',id='dz',customer='Z',node='n乙',
                                                 artifact='art-arm64',at=50,method='direct'))
        self.assertEqual(expired['reason'],'no_valid_preapproval')

    # 9. 升级波次把节点、探针与制品身份接在同一条 transition 上
    def test_wave_carries_artifact_identity_into_finish(self):
        self._node('n甲','amd64')
        self._build('art-amd64','amd64','digest-amd64');self._component('art-amd64','revA','digA')
        self._archive('arc-A','revA','digA')
        inventory.run(self.db,dict(op='runtime_load',id='n甲',generation=1,at=30,components=[]))
        wave.run(self.db,dict(op='plan',id='w',target='v2',max_unavailable=1))
        wave.run(self.db,dict(op='release',id='w',transition='t',node='n甲',artifact='art-amd64'))
        stored=self.db.execute("SELECT artifact_id FROM transitions WHERE id='t'").fetchone()[0]
        self.assertEqual(stored,'art-amd64')
        wave.run(self.db,dict(op='probe',id='w',transition='t',probe='p',generation=1,target='v2',at=31,healthy=True))
        # 探针只认代次与目标字符串, 但 finish 拒绝伪造的另一制品身份, 节点版本保持不变
        forged=wave.run(self.db,dict(op='finish',id='w',transition='t',artifact='art-arm64'))
        self.assertEqual(forged['reason'],'artifact_identity_conflict')
        self.assertEqual(self.db.execute("SELECT state FROM transitions WHERE id='t'").fetchone()[0],'applying')
        self.assertEqual(self.db.execute("SELECT version FROM nodes WHERE id='n甲'").fetchone()[0],'v1')
        # 与 release 固定的同一制品身份才可完成, finish 回带该身份
        clash=wave.run(self.db,dict(op='finish',id='w',transition='t',artifact='art-amd64'))
        self.assertEqual(clash['decision'],'complete')
        self.assertEqual(clash['artifact'],'art-amd64')
        self.assertEqual(self.db.execute("SELECT version FROM nodes WHERE id='n甲'").fetchone()[0],'v2')

    # 10. 全链路决定可从 evidence 重放, 新表状态逐表一致
    def test_evidence_replays_custody_and_delivery(self):
        self.test_direct_delivery_customer_receives_matching_sources()
        result=replay(str(Path(self.tmp.name)/'x.sqlite'),
                      {'inventory':inventory,'wave':wave,
                       'source_custody':source_custody,'source_delivery':source_delivery})
        self.assertTrue(result['verified'],result['divergences'])

    def test_revoked_bundle_blocks_and_reissue_keeps_history(self):
        self._multiarch_fixture();self._archive('arc-B','revB','digB')
        self._certify('b-arm64','art-arm64','n乙')
        source_delivery.run(self.db,dict(op='custodian',id='dep1',name='co',independent=True))
        source_delivery.run(self.db,dict(op='escrow',id='e1',custodian='dep1',bundle='b-arm64',at=46))
        source_custody.run(self.db,dict(op='revoke',id='b-arm64',reason='license_recheck'))
        self.assertEqual(source_delivery.run(self.db,dict(
            op='escrow',id='e2',custodian='dep1',bundle='b-arm64',at=47))['reason'],'no_active_bundle')
        # 撤销行保留, 重新归档新包后可再认证
        self.assertEqual(self.db.execute("SELECT state FROM source_bundles WHERE id='b-arm64'").fetchone()[0],'revoked')
        self._archive('arc-B2','revB','digB')
        recert=self._certify('b-fixed','art-arm64','n乙',at=90)
        self.assertEqual(recert['decision'],'certified')


assert Path(cloudlab.__file__).resolve().is_relative_to(Path(__file__).resolve().parents[1])
print('imported_module_file=',cloudlab.__file__)
if __name__=='__main__':unittest.main()
