"""退役介质客户数据保管的纯判定逻辑。

所有函数只处理入参的普通 dict/list, 不触碰数据库, 便于直接单测和重放。
判定的核心事实:

- 目录项删除、资产表退役标记、应用层密钥注销都不是物理不可恢复证明;
- 块级去重/压缩/统一密钥使逻辑对象与物理字节不是一对一, 必须按块核算;
- 重加密路径要求乙方原文与顺序可核验不变且旧密钥/旧卷全部销毁;
- 原密文托管路径要求甲方片段从全部物理副本(含托管卷)中被见证剔除。
"""

OBJECT = 'object'      # 仅按对象号的擦除回单: 物理字节可能仍在
MEDIA = 'media'        # 整介质擦除回单
BLOCK = 'block'        # 逐块擦除/重排回单
EXCISION = 'excision'  # 见证剔除(封闭托管处对托管卷的块级操作)
ESCROW = 'escrow'      # 托管收件
COURT = 'court'       # 法院收件


def blocks_for_object(snapshot, object_id):
    return [b['block_id'] for b in snapshot.get('placements', [])
            if object_id in b.get('object_ids', [])]


def block_customers(snapshot, block_id):
    """引用某物理块的全部客户。去重使一个块可同时服务多家客户。"""
    customers = set()
    for obj in snapshot.get('objects', []):
        if block_id in obj.get('block_ids', []):
            customers.add(obj['customer'])
    return customers


def is_shared_block(snapshot, block_id):
    return len(block_customers(snapshot, block_id)) > 1


def a_blocks(snapshot, customer_a):
    """承载甲方明文(含与乙方共享)的块集合。"""
    out = set()
    for obj in snapshot.get('objects', []):
        if obj['customer'] == customer_a:
            out.update(obj.get('block_ids', []))
    return out


def physical_copies(snapshot, block_id):
    return [p['media_id'] for p in snapshot.get('placements', []) if p['block_id'] == block_id]


def _signed_ok(receipt):
    return receipt.get('status') == 'signed' and receipt.get('signed_at') is not None


def block_erasure_receipts(snapshot, block_id, media_id):
    """该 (块, 介质) 上构成物理不可恢复证明的回单。

    整介质擦除/逐块擦除/逐块重排算数; 仅按对象号签发的回单不算数,
    因为去重块的物理字节不随目录项删除而消失。
    """
    out = []
    for r in snapshot.get('receipts', []):
        if not _signed_ok(r):
            continue
        if r['kind'] == OBJECT:
            continue
        if r.get('media_id') != media_id:
            continue
        if r['kind'] in (MEDIA,):
            out.append(r)
        elif r['kind'] in (BLOCK, EXCISION) and r.get('block_id') == block_id:
            out.append(r)
    return out


def any_refused(snapshot, media_id, block_id=None):
    for r in snapshot.get('receipts', []):
        if r.get('media_id') != media_id:
            continue
        if block_id is not None and r.get('block_id') not in (block_id, None):
            continue
        if r.get('status') == 'refused':
            return True
    return False


def verify_b_manifest(snapshot, customer_b):
    """乙方交付内容必须与保全令范围、原文哈希、对象顺序一致。"""
    missing, altered, disorder = [], [], []
    scope = snapshot.get('preserve_scope') or []
    by_id = {o.get('id', o.get('object_id')): o for o in snapshot.get('objects', [])
             if o['customer'] == customer_b}
    if sorted(scope) != sorted(by_id):
        missing = sorted(set(scope) ^ set(by_id))
    expected = sorted(
        ((o['order_no'], o.get('id', o.get('object_id')), o['plaintext_hash'])
         for o in by_id.values()),
        key=lambda t: t[0])
    delivered = snapshot.get('delivered_manifest')
    if delivered is not None:
        actual = sorted(
            ((d['order_no'], d.get('object_id', d.get('id')), d['plaintext_hash'])
             for d in delivered),
            key=lambda t: t[0])
        actual_by_id = {d[1]: d for d in actual}
        for order_no, oid, ph in expected:
            got = actual_by_id.get(oid)
            if got is None:
                missing.append(oid)
            elif got[2] != ph:
                altered.append(oid)
            elif got[0] != order_no:
                disorder.append(oid)
        extra = sorted(set(actual_by_id) - {oid for _, oid, _ in expected})
        missing.extend(extra)
    return {'ok': not (missing or altered or disorder),
            'missing': sorted(set(missing)), 'altered': altered, 'disorder': disorder}


def _orders_valid(snapshot):
    blockers = []
    for o in snapshot.get('orders', []):
        if o.get('state') != 'active':
            blockers.append('order_not_active:' + o['id'])
            continue
        if not o.get('authority') or o.get('authority_kind') not in ('customer', 'court'):
            blockers.append('order_bad_authority:' + o['id'])
        now = snapshot.get('now', 0)
        if now < o.get('effective_at', 0):
            blockers.append('order_not_effective:' + o['id'])
        if o.get('expires_at') is not None and now > o['expires_at']:
            blockers.append('order_expired:' + o['id'])
        if not o.get('scope'):
            blockers.append('order_empty_scope:' + o['id'])
        # 法令点名的库房必须在介质台账内; 实际位置在登记时已强校验,
        # 这里只核验位置仍可追踪, 不要求介质停在退役态(擦除/托管后位置仍存在)。
        locations = set(o.get('locations') or [])
        if locations:
            actual = {m['location'] for m in snapshot.get('media', [])}
            if not locations <= actual:
                blockers.append('order_location_untracked:' + o['id'])
    return blockers


def _receipt_covers(snapshot, block_id, media_id, allow_excision):
    kinds = (MEDIA, BLOCK) + ((EXCISION,) if allow_excision else ())
    for r in block_erasure_receipts(snapshot, block_id, media_id):
        if r['kind'] in kinds:
            return True
    return False


def evaluate(snapshot):
    """对一个保管案件做删除/保全可交割性总判定。

 返回 blockers 为空时, 甲方删除证与乙方保全交付才允许同时出具。
    """
    blockers = []
    case = snapshot['case']
    mode = case['mode']
    customer_a = snapshot['delete_subject']
    customer_b = snapshot['preserve_subject']
    blockers.extend(_orders_valid(snapshot))

    a_block_set = a_blocks(snapshot, customer_a)
    media_by_id = {m['id']: m for m in snapshot.get('media', [])}

    # 1. 甲方明文的每个物理副本都必须有不可恢复证明, 晚到漏盘使集合不完整。
    tracked = {(p['block_id'], p['media_id']) for p in snapshot.get('placements', [])}
    declared = set()
    for p in snapshot.get('declared_placements', []):
        declared.add((p['block_id'], p['media_id']))
    for block_id, media_id in sorted(declared - tracked):
        if block_id in a_block_set:
            blockers.append('placement_not_inventoried:%s@%s' % (block_id, media_id))
    for block_id in sorted(a_block_set):
        for media_id in physical_copies(snapshot, block_id):
            media = media_by_id.get(media_id)
            if not media or media['state'] not in ('retired', 'erased', 'sealed', 'migrated'):
                blockers.append('media_not_retired:%s' % media_id)
                continue
            allow_excision = mode == 'sealed' and media['state'] == 'sealed'
            if any_refused(snapshot, media_id, block_id):
                blockers.append('vendor_refused_erasure:%s@%s' % (block_id, media_id))
            elif not _receipt_covers(snapshot, block_id, media_id, allow_excision):
                blockers.append('a_fragment_recoverable:%s@%s' % (block_id, media_id))

    # 2. 原密文托管路径: 托管卷内不得存在任何甲方可恢复片段。
    if mode == 'sealed':
        shared = sorted(b for b in a_block_set if is_shared_block(snapshot, b))
        sealed_media = [m['id'] for m in snapshot.get('media', []) if m['state'] == 'sealed']
        for block_id in shared:
            if any(m in sealed_media for m in physical_copies(snapshot, block_id)):
                blockers.append('shared_block_inside_escrow:%s' % block_id)
        for media_id in sealed_media:
            escrow = [r for r in snapshot.get('receipts', [])
                      if r['kind'] == ESCROW and r.get('media_id') == media_id and _signed_ok(r)]
            if not escrow:
                blockers.append('escrow_receipt_missing:%s' % media_id)

    # 3. 重加密路径: 迁移必须覆盖乙方全部对象, 哈希/顺序核验, 旧密钥与旧卷销毁。
    if mode == 'reencrypt':
        migrations = snapshot.get('migrations', [])
        b_objects = [o for o in snapshot.get('objects', []) if o['customer'] == customer_b]
        covered = {m['object_id'] for m in migrations if m.get('state') == 'verified'}
        for obj in b_objects:
            if obj['id'] not in covered:
                blockers.append('b_object_not_migrated:' + obj['id'])
        for m in migrations:
            if m.get('state') != 'verified':
                blockers.append('migration_unverified:' + m['id'])
            if m.get('plaintext_hash') != m.get('verified_hash'):
                blockers.append('b_plaintext_altered:' + m['id'])
        old_key = snapshot.get('old_key') or {}
        if old_key.get('state') != 'destroyed':
            blockers.append('old_decryption_path_alive:' + str(old_key.get('id', 'K')))
        for media in snapshot.get('media', []):
            if media.get('role') == 'shared_source' and media['state'] != 'erased':
                blockers.append('shared_volume_not_destroyed:' + media['id'])

    # 4. 乙方证据必须完整可读: 密钥份额满足门限, 内容哈希与顺序未改。
    for key in snapshot.get('keys', []):
        if key.get('state') == 'destroyed':
            continue
        usable = [s for s in key.get('shares', []) if s.get('state') == 'held']
        if len(usable) < key.get('quorum', 1):
            blockers.append('b_key_quorum_lost:' + key['id'])
    manifest = verify_b_manifest(snapshot, customer_b)
    if not manifest['ok']:
        blockers.append('b_evidence_manifest_mismatch')

    # 5. 法院只收保全令指定记录, 交付必须有法院收件回单且不得夹带甲方对象。
    court_receipts = [r for r in snapshot.get('receipts', [])
                      if r['kind'] == COURT and _signed_ok(r)]
    if not court_receipts:
        blockers.append('court_receipt_missing')
    else:
        scope = set(snapshot.get('preserve_scope') or [])
        delivered = set()
        for r in court_receipts:
            delivered.update(r.get('scope_refs') or [])
        if delivered != scope:
            blockers.append('court_delivery_scope_mismatch')
        if delivered & {o['id'] for o in snapshot.get('objects', [])
                        if o['customer'] == customer_a}:
            blockers.append('customer_a_records_disclosed')

    # 对象级回单永远不能作为物理删除依据(去重块 B 仍可凭 K 恢复甲方)。
    object_only = [r['id'] for r in snapshot.get('receipts', [])
                   if r['kind'] == OBJECT and r.get('status') == 'signed']
    return {
        'certifiable': not blockers,
        'blockers': sorted(set(blockers)),
        'object_only_receipts': object_only,
        'manifest': manifest,
        'a_blocks': sorted(a_block_set),
        'shared_blocks': sorted(b for b in a_block_set if is_shared_block(snapshot, b)),
    }
