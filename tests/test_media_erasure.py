import tempfile
import unittest
from pathlib import Path

import cloudlab
from cloudlab.store import connect, replay
from cloudlab import inventory, wave, migration, media_custody as mc
from cloudlab import erasure_proof as ep

CUSTOMER_A = 'customer-jia'
CUSTOMER_B = 'customer-yi'

OLD = {'replicas': 3, 'minAvailable': 2, 'selector': {'app': 'web'}}
GOOD = {'desiredReplicas': 3, 'availability': {'minimumReady': 2}, 'selector': {'app': 'web'}}


class MediaErasure(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = connect(str(Path(self.tmp.name) / 'm.sqlite'))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    # ---- 固定场景装配 -------------------------------------------------
    def base_cluster(self):
        """节点 n1 第30分钟已扫描为新代次, 波次完成; 旧卷 V 仍在存储商库房。"""
        inventory.run(self.db, dict(op='node', id='n1', architecture='amd64',
                                    features=['cgroup2'], generation=1,
                                    observed_at=10, version='1.29', zone='z1'))
        inventory.run(self.db, dict(op='verify', id='n1', now=12, max_age=10,
                                    architecture='amd64', features=['cgroup2'],
                                    deprecated_api='old/v1'))
        migration.run(self.db, dict(op='config', workload='web', version='cfg1'))
        wave.run(self.db, dict(op='plan', id='w1', target='1.30', max_unavailable=1))
        wave.run(self.db, dict(op='release', id='w1', transition='t1', node='n1', zone='z1'))
        wave.run(self.db, dict(op='probe', id='w1', transition='t1', probe='p1',
                               generation=1, target='1.30', at=13, healthy=True))
        wave.run(self.db, dict(op='finish', id='w1', transition='t1'))
        inventory.run(self.db, dict(op='node', id='n1', architecture='amd64',
                                    features=['cgroup2'], generation=2,
                                    observed_at=30, version='1.30', zone='z1'))

    def build_media(self, copies=3, shared=True):
        """卷 V + 两份离线副本, 统一密钥 K, 压缩共享块 B。"""
        all_media = [('V', 'vendor-vault-a'),
                     ('V-off1', 'vendor-vault-b'),
                     ('V-off2', 'vendor-vault-c')]
        media_set = all_media[:copies]
        for mid, loc in media_set:
            mc.run(self.db, dict(op='register_media', id=mid, kind='volume', node_id='n1',
                                 wave_id='w1', location=loc, vendor='storeco',
                                 state='retired', discovered_at=30))
        mc.run(self.db, dict(op='register_key', id='K', quorum=2,
                             shares=[{'share_id': 'K-1', 'location': 'safe-1'},
                                     {'share_id': 'K-2', 'location': 'safe-2'}]))
        mc.run(self.db, dict(op='register_object', id='A-diag', customer=CUSTOMER_A,
                             order_no=1, plaintext_hash='h-a-diag'))
        mc.run(self.db, dict(op='register_object', id='B-obj', customer=CUSTOMER_B,
                             order_no=2, plaintext_hash='h-b-obj'))
        block_ids = ['B'] if shared else ['Ba', 'Bb']
        for bid in block_ids:
            mc.run(self.db, dict(op='register_block', id=bid, key_id='K',
                                 compression='gzip', ciphertext_hash='c-' + bid))
            for mid, _ in media_set:
                mc.run(self.db, dict(op='place_block', block_id=bid, media_id=mid, offset_no=1))
        if shared:
            mc.run(self.db, dict(op='map_object_block', object_id='A-diag', block_id='B'))
            mc.run(self.db, dict(op='map_object_block', object_id='B-obj', block_id='B'))
        else:
            mc.run(self.db, dict(op='map_object_block', object_id='A-diag', block_id='Ba'))
            mc.run(self.db, dict(op='map_object_block', object_id='B-obj', block_id='Bb'))
        return block_ids

    def orders(self, case_id='case1', locations=None):
        if locations is None:
            locations = [r[0] for r in self.db.execute(
                'SELECT DISTINCT location FROM media ORDER BY location')]
        d = mc.run(self.db, dict(op='register_order', id='del-order', kind='delete',
                                 subject=CUSTOMER_A, scope=['A-diag'],
                                 effective_at=30, expires_at=1000,
                                 authority='jia-dpo', authority_kind='customer',
                                 locations=list(locations)))
        p = mc.run(self.db, dict(op='register_order', id='pres-order', kind='preserve',
                                 subject=CUSTOMER_B, scope=['B-obj'],
                                 effective_at=30, expires_at=10000,
                                 authority='court-7', authority_kind='court',
                                 locations=list(locations)))
        return d, p

    def open_case(self, mode, case_id='case1'):
        return mc.run(self.db, dict(op='open_case', id=case_id,
                                    delete_order='del-order',
                                    preserve_order='pres-order', mode=mode))

    # ---- 升阶完成不等于介质清空 ---------------------------------------
    def test_wave_complete_does_not_wipe_media_and_inventory_rejects_false_wipe_claim(self):
        self.base_cluster()
        mc.run(self.db, dict(op='register_media', id='V', kind='volume', node_id='n1',
                             wave_id='w1', location='vendor-vault-a', vendor='storeco',
                             state='retired', discovered_at=30))
        # 第二波次再次升阶同一节点 n1, finish 时必须带出该节点介质的处置状态。
        inventory.run(self.db, dict(op='verify', id='n1', now=31, max_age=10,
                                    architecture='amd64', features=['cgroup2'],
                                    deprecated_api='old/v1'))
        wave.run(self.db, dict(op='plan', id='w2', target='1.31', max_unavailable=1))
        wave.run(self.db, dict(op='release', id='w2', transition='t2', node='n1', zone='z1'))
        wave.run(self.db, dict(op='probe', id='w2', transition='t2', probe='p2',
                               generation=2, target='1.31', at=32, healthy=True))
        finish = wave.run(self.db, dict(op='finish', id='w2', transition='t2'))
        # 波次仍是 complete, 但介质处置显示未结清。
        self.assertEqual(finish['decision'], 'complete')
        self.assertEqual(finish['media_disposition'], {'settled': [], 'pending': ['V']})
        claim = inventory.run(self.db, dict(op='node', id='n1', architecture='amd64',
                                            features=['cgroup2'], generation=3,
                                            observed_at=40, version='1.31',
                                            media_wiped=True))
        self.assertEqual(claim['reason'], 'media_wiped_unproven')
        observe = inventory.run(self.db, dict(op='node', id='n1', architecture='amd64',
                                              features=['cgroup2'], generation=4,
                                              observed_at=41, version='1.31'))
        self.assertEqual(observe['decision'], 'observed')
        self.assertEqual(observe['retired_media_pending'], ['V'])

    # ---- 法令核对 -----------------------------------------------------
    def test_orders_must_check_subject_scope_time_authority_location(self):
        self.base_cluster()
        self.build_media()
        bad_time = mc.run(self.db, dict(op='register_order', id='bad-time', kind='delete',
                                        subject=CUSTOMER_A, scope=['A-diag'],
                                        effective_at=100, expires_at=10,
                                        authority='jia-dpo', authority_kind='customer'))
        self.assertEqual(bad_time['reason'], 'order_time_invalid')
        bad_scope = mc.run(self.db, dict(op='register_order', id='bad-scope', kind='delete',
                                         subject=CUSTOMER_A, scope=['ghost'],
                                         effective_at=30, expires_at=1000,
                                         authority='jia-dpo', authority_kind='customer'))
        self.assertEqual(bad_scope['reason'], 'order_scope_unknown')
        bad_loc = mc.run(self.db, dict(op='register_order', id='bad-loc', kind='delete',
                                       subject=CUSTOMER_A, scope=['A-diag'],
                                       effective_at=30, expires_at=1000,
                                       authority='jia-dpo', authority_kind='customer',
                                       locations=['mars-warehouse']))
        self.assertEqual(bad_loc['reason'], 'order_location_untracked')
        customer_preserve = mc.run(self.db, dict(op='register_order', id='cp', kind='preserve',
                                                 subject=CUSTOMER_B, scope=['B-obj'],
                                                 effective_at=30, expires_at=10000,
                                                 authority='vendor',
                                                 authority_kind='customer'))
        self.assertEqual(customer_preserve['reason'], 'order_bad_authority')
        court_delete = mc.run(self.db, dict(op='register_order', id='cd', kind='delete',
                                            subject=CUSTOMER_A, scope=['A-diag'],
                                            effective_at=30, expires_at=1000,
                                            authority='court-7', authority_kind='court'))
        self.assertEqual(court_delete['reason'], 'order_bad_authority')
        expired = mc.run(self.db, dict(op='register_order', id='exp', kind='delete',
                                       subject=CUSTOMER_A, scope=['A-diag'],
                                       effective_at=1, expires_at=2,
                                       authority='jia-dpo', authority_kind='customer',
                                       now=40))
        self.assertEqual(expired['reason'], 'order_expired')
        not_yet = mc.run(self.db, dict(op='register_order', id='fut', kind='delete',
                                       subject=CUSTOMER_A, scope=['A-diag'],
                                       effective_at=100, expires_at=200,
                                       authority='jia-dpo', authority_kind='customer',
                                       now=40))
        self.assertEqual(not_yet['reason'], 'order_not_effective')

    # ---- 常规按对象退役程序无法同时兑现两种权利 -----------------------
    def test_object_level_retirement_leaves_shared_block_recoverable(self):
        self.base_cluster()
        self.build_media()
        self.orders()
        self.open_case('reencrypt')
        # 目录项打删除/保全标志并按对象号向存储商发擦除, 回单对象与列表一致。
        for mid in ('V', 'V-off1', 'V-off2'):
            mc.run(self.db, dict(op='erase', case_id='case1', receipt_id='cmd-' + mid,
                                 kind='object', media_id=mid, scope='object',
                                 scope_refs=['A-diag'], now=31))
            mc.run(self.db, dict(op='receive_receipt', case_id='case1',
                                 receipt_id='cmd-' + mid, kind='object',
                                 issuer='storeco', media_id=mid, scope='object',
                                 scope_refs=['A-diag'], status='signed', signed_at=32))
        snapshot = self._snapshot('case1', now=40)
        verdict = ep.evaluate(snapshot)
        self.assertFalse(verdict['certifiable'])
        self.assertTrue(any(b.startswith('a_fragment_recoverable:B@')
                            for b in verdict['blockers']))
        self.assertEqual(verdict['object_only_receipts'], ['cmd-V', 'cmd-V-off1', 'cmd-V-off2'])
        # 应用层注销密钥同样不能替代物理证明。
        refused = mc.run(self.db, dict(op='certify', case_id='case1', now=40,
                                       certificate_id='fake-cert'))
        self.assertEqual(refused['reason'], 'erase_unproven')
        self.assertIn('old_decryption_path_alive:K', refused['blockers'])

    def _snapshot(self, case_id, now):
        case = self.db.execute('SELECT * FROM custody_cases WHERE id=?', (case_id,)).fetchone()
        return mc._build_snapshot(self.db, dict(case), now)

    # ---- 路径一: 重加密迁移后销毁旧卷与旧密钥 -------------------------
    def test_reencrypt_path_delivers_b_and_certifies_a(self):
        self.base_cluster()
        self.build_media()
        self.orders()
        self.open_case('reencrypt')
        # 迁出乙方对象到独立密钥卷 V-b。
        mc.run(self.db, dict(op='register_key', id='Kb', quorum=1,
                             shares=[{'share_id': 'Kb-1', 'location': 'b-safe'}]))
        mc.run(self.db, dict(op='register_media', id='V-b', kind='volume',
                             node_id='n1', location='b-vault', vendor='storeco',
                             state='active', case_id='case1', role='b_volume',
                             discovered_at=31))
        mc.run(self.db, dict(op='migrate', case_id='case1', id='mig1', object_id='B-obj',
                             new_key_id='Kb', new_block_id='Bb-new', dest_media='V-b'))
        # 迁移不得夹带甲方对象。
        cheat = mc.run(self.db, dict(op='migrate', case_id='case1', id='mig-cheat',
                                     object_id='A-diag', new_key_id='Kb',
                                     new_block_id='Ba-new', dest_media='V-b'))
        self.assertEqual(cheat['reason'], 'migration_scope_violation')
        bad = mc.run(self.db, dict(op='verify_migration', case_id='case1', id='mig1',
                                   new_block_id='Bb-new', dest_media='V-b',
                                   plaintext_hash='tampered', order_no=2))
        self.assertEqual(bad['reason'], 'migration_hash_mismatch')
        # 错误目标密钥的迁移登记被门限检查拦下。
        mc.run(self.db, dict(op='register_key', id='Kx', quorum=2,
                             shares=[{'share_id': 'Kx-1', 'location': 'x'}]))
        bad_key = mc.run(self.db, dict(op='migrate', case_id='case1', id='mig-badkey',
                                       object_id='B-obj', new_key_id='Kx',
                                       new_block_id='Bb-x', dest_media='V-b'))
        self.assertEqual(bad_key['reason'], 'key_quorum_lost')
        mc.run(self.db, dict(op='verify_migration', case_id='case1', id='mig1',
                             new_block_id='Bb-new', dest_media='V-b',
                             plaintext_hash='h-b-obj', order_no=2, offset_no=1))
        # 旧共享卷(含两份离线副本)逐块/整介质擦除并收签名回单。
        for mid in ('V', 'V-off1', 'V-off2'):
            mc.run(self.db, dict(op='erase', case_id='case1', receipt_id='era-' + mid,
                                 kind='media', media_id=mid, now=33))
            mc.run(self.db, dict(op='receive_receipt', case_id='case1',
                                 receipt_id='era-' + mid, kind='media',
                                 issuer='storeco', media_id=mid, status='signed',
                                 signed_at=34))
            self.assertEqual(
                self.db.execute('SELECT state FROM media WHERE id=?', (mid,)).fetchone()[0],
                'erased')
        # 旧密钥全部份额可交代后销毁, 甲方明文再无可用解密路径。
        mc.run(self.db, dict(op='receive_receipt', case_id='case1', receipt_id='kd-K',
                             kind='key_destruction', issuer='kms', key_id='K',
                             scope='share', scope_refs=['K-1', 'K-2'],
                             status='signed', signed_at=35))
        destroyed = mc.run(self.db, dict(op='destroy_key', case_id='case1', key_id='K'))
        self.assertEqual(destroyed['decision'], 'destroyed')
        # 法院只收乙方记录, 并核对哈希与顺序。
        delivery = mc.run(self.db, dict(op='deliver_court', case_id='case1',
                                        receipt_id='court-1', issuer='court-7',
                                        scope_refs=['B-obj'], signed_at=36, now=36,
                                        manifest=[{'object_id': 'B-obj', 'order_no': 2,
                                                   'plaintext_hash': 'h-b-obj'}]))
        self.assertEqual(delivery['decision'], 'delivered')
        cert = mc.run(self.db, dict(op='certify', case_id='case1', now=40,
                                    certificate_id='cert-a-1'))
        self.assertEqual(cert['decision'], 'certified')
        self.assertEqual(cert['version'], 1)
        self.assertIn('era-V', cert['basis']['receipts'])
        # 断电重试: 不重复出证。
        again = mc.run(self.db, dict(op='certify', case_id='case1', now=41,
                                     certificate_id='cert-a-1'))
        self.assertEqual(again['decision'], 'reused')
        # 同一编号不得用于"再次出具"。
        duplicate = mc.run(self.db, dict(op='certify', case_id='case1', now=42,
                                         certificate_id='cert-a-1'))
        self.assertEqual(duplicate['decision'], 'reused')
        status = mc.run(self.db, dict(op='case_status', case_id='case1', now=41))
        self.assertTrue(status['certifiable'])
        self.assertEqual(status['decision'], 'certified')

    # ---- 路径二: 原密文托管, 共享块无法分离必须停办 -------------------
    def test_sealed_path_halts_when_a_share_inside_shared_block(self):
        self.base_cluster()
        self.build_media(shared=True)
        self.orders()
        self.open_case('sealed')
        # 托管收件已具备, 但 B 同时承载甲乙内容, 无法在保持原密文字节时剔除甲片段。
        mc.run(self.db, dict(op='receive_receipt', case_id='case1', receipt_id='esc-V',
                             kind='escrow', issuer='independent-custodian',
                             media_id='V', status='signed', signed_at=33))
        seal = mc.run(self.db, dict(op='seal_media', case_id='case1', media_id='V', now=34))
        self.assertEqual(seal['reason'], 'shared_block_cannot_seal')
        self.assertEqual(seal['shared_blocks'], ['B'])
        self.assertEqual(
            self.db.execute("SELECT state FROM custody_cases WHERE id='case1'").fetchone()[0],
            'halted')
        # 停办状态禁止出具删除证。
        cert = mc.run(self.db, dict(op='certify', case_id='case1', now=40,
                                    certificate_id='fake'))
        self.assertEqual(cert['reason'], 'erase_unproven')

    def test_sealed_path_succeeds_when_a_fragments_are_excisable(self):
        self.base_cluster()
        self.build_media(shared=False)  # 甲块 Ba、乙块 Bb 独立
        self.orders()
        self.open_case('sealed')
        # 托管卷 V: 甲片段由托管方见证逐块剔除, 乙方原密文 Bb 原样封存。
        mc.run(self.db, dict(op='receive_receipt', case_id='case1', receipt_id='exc-V-Ba',
                             kind='excision', issuer='independent-custodian',
                             media_id='V', block_id='Ba', status='signed', signed_at=33))
        mc.run(self.db, dict(op='receive_receipt', case_id='case1', receipt_id='esc-V',
                             kind='escrow', issuer='independent-custodian',
                             media_id='V', status='signed', signed_at=34))
        seal = mc.run(self.db, dict(op='seal_media', case_id='case1', media_id='V', now=35))
        self.assertEqual(seal['decision'], 'sealed')
        # 两份离线副本上的甲块逐块销毁, 乙块随托管原件保全。
        for mid in ('V-off1', 'V-off2'):
            mc.run(self.db, dict(op='erase', case_id='case1', receipt_id='era-' + mid,
                                 kind='block', media_id=mid, block_id='Ba', now=36))
            mc.run(self.db, dict(op='receive_receipt', case_id='case1',
                                 receipt_id='era-' + mid, kind='block', issuer='storeco',
                                 media_id=mid, block_id='Ba', status='signed',
                                 signed_at=37))
        # 统一密钥 K 在原密文路径下保留于托管处(门限满足), 法院交付乙方原件。
        delivery = mc.run(self.db, dict(op='deliver_court', case_id='case1',
                                        receipt_id='court-1', issuer='court-7',
                                        scope_refs=['B-obj'], signed_at=38, now=38,
                                        manifest=[{'object_id': 'B-obj', 'order_no': 2,
                                                   'plaintext_hash': 'h-b-obj'}]))
        self.assertEqual(delivery['decision'], 'delivered')
        cert = mc.run(self.db, dict(op='certify', case_id='case1', now=40,
                                    certificate_id='cert-a-sealed'))
        self.assertEqual(cert['decision'], 'certified')
        # 托管卷受保护, 不能再被擦除。
        self.assertEqual(mc.run(self.db, dict(op='erase', case_id='case1',
                                              receipt_id='no', media_id='V', now=41))['reason'],
                         'sealed_media_protected')

    # ---- 晚到漏盘: 已发证书只能被更正, 不能重复出证 -------------------
    def test_late_offline_copy_supersedes_certificate_then_re_certifies(self):
        self.base_cluster()
        self.build_media(copies=2)  # 登记时只有 V 与 V-off1
        self.orders(locations=('vendor-vault-a', 'vendor-vault-b'))
        self.open_case('reencrypt')
        self._finish_reencrypt(copies=('V', 'V-off1'))
        first = mc.run(self.db, dict(op='certify', case_id='case1', now=40,
                                     certificate_id='cert-1'))
        self.assertEqual(first['decision'], 'certified')
        # 第二份离线副本晚到, 仍含甲方共享块 B。
        found = mc.run(self.db, dict(op='discover_copy', case_id='case1', id='V-off2',
                                     kind='offline_copy', node_id='n1',
                                     location='vendor-vault-c', vendor='storeco',
                                     discovered_at=50, parent_media_id='V',
                                     placements=[{'block_id': 'B', 'offset_no': 1}]))
        self.assertEqual(found['superseded_certificate'], 'cert-1')
        self.assertEqual(
            self.db.execute("SELECT state FROM deletion_certificates WHERE id='cert-1'").fetchone()[0],
            'superseded')
        retry = mc.run(self.db, dict(op='certify', case_id='case1', now=51,
                                     certificate_id='cert-3'))
        self.assertEqual(retry['reason'], 'erase_unproven')
        self.assertTrue(any('V-off2' in b for b in retry['blockers']))
        # 旧证书编号已占用, 换发不得复用。
        reuse = mc.run(self.db, dict(op='certify', case_id='case1', now=51,
                                     certificate_id='cert-1'))
        self.assertEqual(reuse['reason'], 'certificate_id_reused')
        # 补办擦除后换发 v2 更正证书。
        mc.run(self.db, dict(op='erase', case_id='case1', receipt_id='era-V-off2',
                             kind='media', media_id='V-off2', now=52))
        mc.run(self.db, dict(op='receive_receipt', case_id='case1',
                             receipt_id='era-V-off2', kind='media', issuer='storeco',
                             media_id='V-off2', status='signed', signed_at=53))
        second = mc.run(self.db, dict(op='certify', case_id='case1', now=54,
                                      certificate_id='cert-2'))
        self.assertEqual(second['decision'], 'certified')
        self.assertEqual(second['version'], 2)
        self.assertEqual(
            self.db.execute('SELECT superseded_by FROM deletion_certificates WHERE id=?',
                            ('cert-1',)).fetchone()[0], 'cert-2')

    def _finish_reencrypt(self, copies):
        mc.run(self.db, dict(op='register_key', id='Kb', quorum=1,
                             shares=[{'share_id': 'Kb-1', 'location': 'b-safe'}]))
        mc.run(self.db, dict(op='register_media', id='V-b', kind='volume',
                             node_id='n1', location='b-vault', vendor='storeco',
                             state='active', case_id='case1', role='b_volume',
                             discovered_at=31))
        mc.run(self.db, dict(op='migrate', case_id='case1', id='mig1', object_id='B-obj',
                             new_key_id='Kb', new_block_id='Bb-new', dest_media='V-b'))
        mc.run(self.db, dict(op='verify_migration', case_id='case1', id='mig1',
                             new_block_id='Bb-new', dest_media='V-b',
                             plaintext_hash='h-b-obj', order_no=2, offset_no=1))
        for mid in copies:
            mc.run(self.db, dict(op='erase', case_id='case1', receipt_id='era-' + mid,
                                 kind='media', media_id=mid, now=33))
            mc.run(self.db, dict(op='receive_receipt', case_id='case1',
                                 receipt_id='era-' + mid, kind='media',
                                 issuer='storeco', media_id=mid,
                                 status='signed', signed_at=34))
        mc.run(self.db, dict(op='receive_receipt', case_id='case1', receipt_id='kd-K',
                             kind='key_destruction', issuer='kms', key_id='K',
                             scope='share', scope_refs=['K-1', 'K-2'],
                             status='signed', signed_at=35))
        mc.run(self.db, dict(op='destroy_key', case_id='case1', key_id='K'))
        mc.run(self.db, dict(op='deliver_court', case_id='case1', receipt_id='court-1',
                             issuer='court-7', scope_refs=['B-obj'], signed_at=36, now=36,
                             manifest=[{'object_id': 'B-obj', 'order_no': 2,
                                        'plaintext_hash': 'h-b-obj'}]))

    # ---- 跨卷重复块: 每个物理副本都要证明 ----------------------------
    def test_declared_but_missing_copy_blocks_certificate_until_reconciled(self):
        self.base_cluster()
        self.build_media(copies=2)  # 台账只有 V 与 V-off1
        self.orders()
        self.open_case('reencrypt')
        # 存储商清单声明: 共享块 B 实际还有第三份离线副本 V-off2。
        mc.run(self.db, dict(op='register_media', id='V-off2', kind='offline_copy',
                             node_id='n1', location='vendor-vault-c', vendor='storeco',
                             state='retired', discovered_at=31))
        declared = mc.run(self.db, dict(
            op='declare_inventory', case_id='case1', declared_at=32,
            placements=[{'block_id': 'B', 'media_id': 'V-off2'}]))
        self.assertEqual(declared['missing_copies'], ['B@V-off2'])
        self._finish_reencrypt(copies=('V', 'V-off1'))
        cert = mc.run(self.db, dict(op='certify', case_id='case1', now=40,
                                    certificate_id='cert-gap'))
        self.assertEqual(cert['reason'], 'erase_unproven')
        self.assertTrue(any('placement_not_inventoried:B@V-off2' in b
                            for b in cert['blockers']))
        # 漏盘补办: 放置登记到位并完成擦除后阻断消除。
        mc.run(self.db, dict(op='place_block', block_id='B', media_id='V-off2', offset_no=1))
        mc.run(self.db, dict(op='erase', case_id='case1', receipt_id='era-V-off2',
                             kind='media', media_id='V-off2', now=42))
        mc.run(self.db, dict(op='receive_receipt', case_id='case1',
                             receipt_id='era-V-off2', kind='media', issuer='storeco',
                             media_id='V-off2', status='signed', signed_at=43))
        ok = mc.run(self.db, dict(op='certify', case_id='case1', now=44,
                                  certificate_id='cert-gap-2'))
        self.assertEqual(ok['decision'], 'certified')

    def test_cross_volume_duplicate_block_requires_every_copy_erased(self):
        self.base_cluster()
        self.build_media()
        self.orders()
        self.open_case('reencrypt')
        snapshot = self._snapshot('case1', now=40)
        copies = ep.physical_copies(snapshot, 'B')
        self.assertEqual(sorted(copies), ['V', 'V-off1', 'V-off2'])
        self.assertTrue(ep.is_shared_block(snapshot, 'B'))
        # 只擦主卷, 两份离线副本仍可凭 K 恢复甲方记录。
        mc.run(self.db, dict(op='register_key', id='Kb', quorum=1,
                             shares=[{'share_id': 'Kb-1', 'location': 'b-safe'}]))
        mc.run(self.db, dict(op='register_media', id='V-b', kind='volume',
                             node_id='n1', location='b-vault', vendor='storeco',
                             state='active', case_id='case1', role='b_volume',
                             discovered_at=31))
        mc.run(self.db, dict(op='migrate', case_id='case1', id='mig1', object_id='B-obj',
                             new_key_id='Kb', new_block_id='Bb-new', dest_media='V-b'))
        mc.run(self.db, dict(op='verify_migration', case_id='case1', id='mig1',
                             new_block_id='Bb-new', dest_media='V-b',
                             plaintext_hash='h-b-obj', order_no=2))
        mc.run(self.db, dict(op='erase', case_id='case1', receipt_id='era-V',
                             kind='media', media_id='V', now=33))
        mc.run(self.db, dict(op='receive_receipt', case_id='case1', receipt_id='era-V',
                             kind='media', issuer='storeco', media_id='V',
                             status='signed', signed_at=34))
        mc.run(self.db, dict(op='receive_receipt', case_id='case1', receipt_id='kd-K',
                             kind='key_destruction', issuer='kms', key_id='K',
                             scope='share', scope_refs=['K-1', 'K-2'],
                             status='signed', signed_at=35))
        # 密钥未销毁成功(份额状态未随 K 全毁前不应销毁)——先看阻断项。
        verdict = ep.evaluate(self._snapshot('case1', now=40))
        self.assertIn('a_fragment_recoverable:B@V-off1', verdict['blockers'])
        self.assertIn('a_fragment_recoverable:B@V-off2', verdict['blockers'])

    def test_block_erasure_does_not_mark_whole_media_erased(self):
        # 同一介质上还有案外块时, 逐块擦除回单不得把整盘标成 erased。
        self.base_cluster()
        self.build_media(copies=1, shared=False)
        mc.run(self.db, dict(op='register_object', id='C-other', customer='customer-bing',
                             order_no=3, plaintext_hash='h-c'))
        mc.run(self.db, dict(op='register_block', id='Bc', key_id='K',
                             compression='gzip', ciphertext_hash='c-Bc'))
        mc.run(self.db, dict(op='map_object_block', object_id='C-other', block_id='Bc'))
        mc.run(self.db, dict(op='place_block', block_id='Bc', media_id='V', offset_no=9))
        self.orders()
        self.open_case('sealed')
        mc.run(self.db, dict(op='erase', case_id='case1', receipt_id='era-Ba',
                             kind='block', media_id='V', block_id='Ba', now=36))
        mc.run(self.db, dict(op='receive_receipt', case_id='case1', receipt_id='era-Ba',
                             kind='block', issuer='storeco', media_id='V', block_id='Ba',
                             status='signed', signed_at=37))
        # 介质仍是 retired: Bc 物理字节还在, 不能宣称整盘清空。
        self.assertEqual(
            self.db.execute("SELECT state FROM media WHERE id='V'").fetchone()[0], 'retired')
        # 整介质擦除回单才允许置 erased。
        mc.run(self.db, dict(op='erase', case_id='case1', receipt_id='era-V',
                             kind='media', media_id='V', now=38))
        mc.run(self.db, dict(op='receive_receipt', case_id='case1', receipt_id='era-V',
                             kind='media', issuer='storeco', media_id='V',
                             status='signed', signed_at=39))
        self.assertEqual(
            self.db.execute("SELECT state FROM media WHERE id='V'").fetchone()[0], 'erased')

    # ---- 密钥份额丢失 -------------------------------------------------
    def test_lost_key_share_blocks_migration_and_sealed_delivery(self):
        self.base_cluster()
        self.build_media()
        self.orders()
        self.open_case('reencrypt')
        mc.run(self.db, dict(op='lose_share', case_id='case1', key_id='K', share_id='K-2'))
        mc.run(self.db, dict(op='register_key', id='Kb', quorum=1,
                             shares=[{'share_id': 'Kb-1', 'location': 'b-safe'}]))
        mc.run(self.db, dict(op='register_media', id='V-b', kind='volume',
                             node_id='n1', location='b-vault', vendor='storeco',
                             state='active', case_id='case1', role='b_volume',
                             discovered_at=31))
        blocked = mc.run(self.db, dict(op='migrate', case_id='case1', id='mig1',
                                       object_id='B-obj', new_key_id='Kb',
                                       new_block_id='Bb-new', dest_media='V-b'))
        self.assertEqual(blocked['reason'], 'key_quorum_lost')
        # sealed 路径下托管卷封存后, 若新密钥份额丢失, 法院交付同样被阻断。
        case2 = self._sealed_separable_case()
        mc.run(self.db, dict(op='lose_share', case_id=case2, key_id='K', share_id='K-2'))
        delivery = mc.run(self.db, dict(op='deliver_court', case_id=case2,
                                        receipt_id='court-x', issuer='court-7',
                                        scope_refs=['B-obj'], signed_at=38, now=38))
        self.assertEqual(delivery['reason'], 'b_key_quorum_lost')

    def _sealed_separable_case(self):
        cid = 'case2'
        mc.run(self.db, dict(op='register_order', id='del-order-2', kind='delete',
                             subject=CUSTOMER_A, scope=['A-diag'],
                             effective_at=30, expires_at=1000,
                             authority='jia-dpo', authority_kind='customer'))
        mc.run(self.db, dict(op='register_order', id='pres-order-2', kind='preserve',
                             subject=CUSTOMER_B, scope=['B-obj'],
                             effective_at=30, expires_at=10000,
                             authority='court-7', authority_kind='court'))
        mc.run(self.db, dict(op='open_case', id=cid, delete_order='del-order-2',
                             preserve_order='pres-order-2', mode='sealed'))
        return cid

    # ---- 存储商拒绝擦除 ----------------------------------------------
    def test_vendor_refusal_blocks_certificate_until_resolved(self):
        self.base_cluster()
        self.build_media(copies=1)
        self.orders(locations=('vendor-vault-a',))
        self.open_case('reencrypt')
        mc.run(self.db, dict(op='erase', case_id='case1', receipt_id='era-V',
                             kind='media', media_id='V', now=33))
        refused = mc.run(self.db, dict(op='receive_receipt', case_id='case1',
                                       receipt_id='era-V', kind='media',
                                       issuer='storeco', media_id='V',
                                       status='refused', signed_at=34))
        self.assertEqual(refused['decision'], 'refused')
        self.assertEqual(
            self.db.execute("SELECT state FROM custody_cases WHERE id='case1'").fetchone()[0],
            'blocked')
        cert = mc.run(self.db, dict(op='certify', case_id='case1', now=40,
                                    certificate_id='no'))
        self.assertTrue(any('vendor_refused_erasure' in b for b in cert['blockers']))
        # 换存储商补签后阻断解除(其余条件由状态查询体现)。
        mc.run(self.db, dict(op='receive_receipt', case_id='case1', receipt_id='era-V',
                             kind='media', issuer='storeco-2', media_id='V',
                             status='signed', signed_at=41))
        verdict = ep.evaluate(self._snapshot('case1', now=42))
        self.assertFalse(any('vendor_refused' in b for b in verdict['blockers']))

    # ---- 法院改变保全原件要求: sealed -> reencrypt --------------------
    def test_court_amendment_switches_preservation_mode(self):
        self.base_cluster()
        self.build_media(shared=True)
        self.orders()
        self.open_case('sealed')
        mc.run(self.db, dict(op='receive_receipt', case_id='case1', receipt_id='esc-V',
                             kind='escrow', issuer='independent-custodian',
                             media_id='V', status='signed', signed_at=33))
        # 第一次修订漏报 authority_kind, 属签发权不合规, 修订被拒绝。
        bad_amend = mc.run(self.db, dict(op='amend_order', id='pres-order', new_id='pres-order-x',
                                         subject=CUSTOMER_B, scope=['B-obj'],
                                         effective_at=30, expires_at=10000,
                                         authority='court-7'))
        self.assertEqual(bad_amend['reason'], 'order_bad_authority')
        # 已建立托管后不得直接改模式。
        bad = mc.run(self.db, dict(op='amend_order', id='pres-order', new_id='pres-order-2',
                                   subject=CUSTOMER_B, scope=['B-obj'],
                                   effective_at=30, expires_at=10000,
                                   authority='court-7', authority_kind='court',
                                   locations=['vendor-vault-a'],
                                   mode='reencrypt'))
        self.assertEqual(bad['reason'], 'escrow_already_established')
        # 另开未托管案件, 法院裁定准许重加密, 模式随之切换。
        mc.run(self.db, dict(op='register_order', id='pres2', kind='preserve',
                             subject=CUSTOMER_B, scope=['B-obj'],
                             effective_at=30, expires_at=10000,
                             authority='court-7', authority_kind='court'))
        mc.run(self.db, dict(op='open_case', id='case-rx', delete_order='del-order',
                             preserve_order='pres2', mode='sealed'))
        amend = mc.run(self.db, dict(op='amend_order', id='pres2', new_id='pres2b',
                                     subject=CUSTOMER_B, scope=['B-obj'],
                                     effective_at=30, expires_at=10000,
                                     authority='court-7', authority_kind='court',
                                     locations=['vendor-vault-a', 'vendor-vault-b',
                                                'vendor-vault-c'],
                                     mode='reencrypt'))
        self.assertEqual(amend['decision'], 'amended')
        self.assertEqual(
            self.db.execute("SELECT state FROM legal_orders WHERE id='pres2'").fetchone()[0],
            'superseded')
        self.assertEqual(
            self.db.execute("SELECT mode FROM custody_cases WHERE id='case-rx'").fetchone()[0],
            'reencrypt')

    # ---- 纯函数: 清单顺序与哈希 ---------------------------------------
    def test_manifest_detects_missing_altered_and_disorder(self):
        snapshot = {
            'objects': [
                {'object_id': 'o1', 'customer': CUSTOMER_B, 'order_no': 1,
                 'plaintext_hash': 'h1', 'block_ids': []},
                {'object_id': 'o2', 'customer': CUSTOMER_B, 'order_no': 2,
                 'plaintext_hash': 'h2', 'block_ids': []}],
            'preserve_scope': ['o1', 'o2'],
            'delivered_manifest': [
                {'object_id': 'o1', 'order_no': 2, 'plaintext_hash': 'h1'},
                {'object_id': 'o2', 'order_no': 1, 'plaintext_hash': 'XX'}]}
        result = ep.verify_b_manifest(snapshot, CUSTOMER_B)
        self.assertFalse(result['ok'])
        self.assertEqual(result['altered'], ['o2'])
        self.assertEqual(result['disorder'], ['o1'])

    # ---- 事件重放: 新子系统同样可重建且逐表一致 -----------------------
    def test_evidence_replays_custody_decisions(self):
        self.base_cluster()
        self.build_media()
        self.orders()
        self.open_case('reencrypt')
        self._finish_reencrypt(copies=('V', 'V-off1', 'V-off2'))
        mc.run(self.db, dict(op='certify', case_id='case1', now=40,
                             certificate_id='cert-1'))
        path = str(Path(self.tmp.name) / 'm.sqlite')
        result = replay(path, {'inventory': inventory, 'wave': wave,
                               'migration': migration, 'media_custody': mc})
        self.assertTrue(result['verified'], result['divergences'])


assert Path(cloudlab.__file__).resolve().is_relative_to(Path(__file__).resolve().parents[1])
print('imported_module_file=', cloudlab.__file__)
if __name__ == '__main__':
    unittest.main()
