"""退役介质的客户数据保管交割。

节点升阶完成只说明节点版本与波次状态, 不说明旧介质上哪家客户的数据仍可恢复。
本模块在 inventory/wave 之外建立独立的介质-对象-块-密钥-法令事实链, 支持两种
真实交割:

- reencrypt (准许重加密乙方内容): 乙方对象迁入独立密钥卷并核验原文/顺序,
  旧共享卷与统一密钥 K 全部销毁后, 方可出具甲方删除证并向法院交付乙方;
- sealed (法院要求原密文字节): 原卷送入独立监管封闭托管, 甲方片段必须从
  全部物理副本(含托管卷)见证剔除; 若共享块无法分离甲片段, 案件停在未完成,
  只能请法院改变保全方式, 不得出具假删除证。

外部事实(存储商擦除回单、托管收件、法院收件、客户删除证)均以带签名时间的
回单/证书行登记; 断电重试走幂等返回, 不重复出具完成证书。
"""
import json

from .store import transaction, record, audit_run
from . import erasure_proof as ep


def _loads(value, default):
    if value is None:
        return default
    return json.loads(value)


def _blocked(reason, **extra):
    out = {'decision': 'blocked', 'reason': reason}
    out.update(extra)
    return out


def _get(db, table, key, key_id='id'):
    return db.execute('SELECT * FROM %s WHERE %s=?' % (table, key_id), (key,)).fetchone()


def _validate_order(db, x):
    """删除令/保全令必须核对主体、数据范围、生效到期、签发权、实际介质位置。"""
    if x['kind'] not in ('delete', 'preserve'):
        return 'order_wrong_kind'
    if not x.get('subject') or not x.get('scope'):
        return 'order_bad_subject'
    if x['effective_at'] > x['expires_at']:
        return 'order_time_invalid'
    authority_kind = x.get('authority_kind')
    if authority_kind == 'court' and x['kind'] != 'preserve':
        return 'order_bad_authority'
    if authority_kind == 'customer' and x['kind'] != 'delete':
        return 'order_bad_authority'
    if authority_kind not in ('customer', 'court') or not x.get('authority'):
        return 'order_bad_authority'
    for object_id in x['scope']:
        if not _get(db, 'logical_objects', object_id):
            return 'order_scope_unknown'
    locations = set(x.get('locations') or [])
    if locations:
        actual = {r[0] for r in db.execute('SELECT DISTINCT location FROM media')}
        # 法令指定的实际介质位置必须可追踪; 尚未登记的库房不能凭空宣称覆盖。
        unknown = locations - actual
        if unknown:
            return 'order_location_untracked'
        named = {r[0] for r in db.execute(
            'SELECT DISTINCT location FROM media WHERE state IN (?,?,?,?)',
            ('retired', 'discovered', 'erased', 'sealed'))}
        if not (locations & named):
            return 'order_location_untracked'
    if x.get('now') is not None and x['now'] > x['expires_at']:
        return 'order_expired'
    if x.get('now') is not None and x['now'] < x['effective_at']:
        return 'order_not_effective'
    return None


def _scoped_blocks(db, object_ids):
    out = set()
    for oid in object_ids:
        for row in db.execute('SELECT block_id FROM object_blocks WHERE object_id=?', (oid,)):
            out.add(row[0])
    return out


def _case_media_ids(db, case_id):
    return [r[0] for r in db.execute(
        'SELECT media_id FROM case_media WHERE case_id=?', (case_id,))]


def _build_snapshot(db, case, now):
    delete_order = _get(db, 'legal_orders', case['delete_order'])
    preserve_order = _get(db, 'legal_orders', case['preserve_order'])
    scope = sorted(set(_loads(delete_order['scope'], [])) | set(_loads(preserve_order['scope'], [])))
    preserve_scope = _loads(preserve_order['scope'], [])
    objects = [dict(o) for o in db.execute(
        'SELECT * FROM logical_objects WHERE id IN (%s)' % ','.join('?' * len(scope)), scope)] \
        if scope else []
    block_ids = _scoped_blocks(db, scope)
    blocks = [dict(b) for b in db.execute(
        'SELECT * FROM physical_blocks WHERE id IN (%s)' % ','.join('?' * len(block_ids)),
        tuple(block_ids))] if block_ids else []
    for b in blocks:
        b['object_ids'] = [r[0] for r in db.execute(
            'SELECT object_id FROM object_blocks WHERE block_id=?', (b['id'],))]
    media_ids = set(_case_media_ids(db, case['id']))
    if block_ids:
        media_ids.update(r[0] for r in db.execute(
            'SELECT DISTINCT media_id FROM block_placement WHERE block_id IN (%s)'
            % ','.join('?' * len(block_ids)), tuple(block_ids)))
    # 法令点名的库房即便其块已全部擦除, 仍须出现在快照中以支持位置追踪核验。
    for order_row in (delete_order, preserve_order):
        for loc in _loads(order_row['locations'], []):
            for r in db.execute('SELECT id FROM media WHERE location=?', (loc,)):
                media_ids.add(r[0])
    media = []
    for mid in sorted(media_ids):
        row = _get(db, 'media', mid)
        if row:
            role = db.execute(
                'SELECT role FROM case_media WHERE case_id=? AND media_id=?',
                (case['id'], mid)).fetchone()
            item = dict(row)
            item['role'] = role[0] if role else 'copy'
            media.append(item)
    placements = []
    for b in blocks:
        for row in db.execute('SELECT * FROM block_placement WHERE block_id=?', (b['id'],)):
            placements.append({'block_id': row['block_id'], 'media_id': row['media_id']})
    receipts = [dict(r) for r in db.execute(
        'SELECT * FROM receipts WHERE case_id=? ORDER BY id', (case['id'],))]
    for r in receipts:
        r['scope_refs'] = _loads(r['scope_refs'], [])
    key_ids = {b['key_id'] for b in blocks if b['key_id']}
    key_ids.update(r[0] for r in db.execute(
        'SELECT DISTINCT new_key_id FROM media_migrations WHERE case_id=?', (case['id'],)))
    keys = []
    for kid in sorted(key_ids):
        ring = _get(db, 'key_rings', kid)
        if not ring:
            continue
        item = dict(ring)
        item['shares'] = [dict(s) for s in db.execute(
            'SELECT * FROM key_shares WHERE key_id=?', (kid,))]
        keys.append(item)
    migrations = []
    for row in db.execute('SELECT * FROM media_migrations WHERE case_id=? ORDER BY id', (case['id'],)):
        migrations.append(dict(row))
    # 旧统一密钥只来自迁移记录的 old_key_id 与未迁出的旧块;
    # 已迁入新卷的块(Bb-new)持有的是新密钥, 不能混入旧密钥集合。
    migrated_new = {m['new_block_id'] for m in migrations}
    old_key_ids = {b['key_id'] for b in blocks
                   if b['key_id'] and b['id'] not in migrated_new}
    for mig in migrations:
        raw = mig['old_key_id']
        if raw:
            old_key_ids.update(k for k in raw.split(',') if k)
    old_key = None
    if len(old_key_ids) == 1:
        ring = _get(db, 'key_rings', next(iter(old_key_ids)))
        old_key = dict(ring) if ring else None
    delivered_manifest = []
    for r in receipts:
        if r['kind'] == ep.COURT and r['status'] == 'signed':
            for oid in r['scope_refs']:
                obj = _get(db, 'logical_objects', oid)
                if obj:
                    delivered_manifest.append(
                        {'id': oid, 'object_id': oid, 'order_no': obj['order_no'],
                         'plaintext_hash': obj['plaintext_hash']})
    for obj in objects:
        obj['block_ids'] = [r[0] for r in db.execute(
            'SELECT block_id FROM object_blocks WHERE object_id=?', (obj['id'],))]
    return {
        'now': now,
        'case': {'id': case['id'], 'mode': case['mode']},
        'orders': [
            {**dict(delete_order),
             'scope': _loads(delete_order['scope'], []),
             'locations': _loads(delete_order['locations'], [])},
            {**dict(preserve_order),
             'scope': _loads(preserve_order['scope'], []),
             'locations': _loads(preserve_order['locations'], [])}],
        'delete_subject': delete_order['subject'],
        'preserve_subject': preserve_order['subject'],
        'preserve_scope': preserve_scope,
        'objects': objects,
        'blocks': blocks,
        'placements': placements,
        'media': media,
        'receipts': receipts,
        'keys': keys,
        'old_key': old_key,
        'migrations': migrations,
        'delivered_manifest': delivered_manifest,
        'declared_placements': [
            {'block_id': r['block_id'], 'media_id': r['media_id']}
            for r in db.execute(
                'SELECT block_id,media_id FROM declared_placements WHERE case_id=?',
                (case['id'],))],
    }


@audit_run('media_custody')
def run(db, x):
    with transaction(db):
        op = x['op']

        if op == 'register_media':
            old = _get(db, 'media', x['id'])
            if old:
                return {'decision': 'reused', 'state': old['state']}
            db.execute('INSERT INTO media VALUES(?,?,?,?,?,?,?,?,?)',
                       (x['id'], x['kind'], x.get('node_id'), x.get('wave_id'),
                        x['location'], x['vendor'], x.get('state', 'retired'),
                        x.get('parent_media_id'), x['discovered_at']))
            if x.get('case_id'):
                db.execute('INSERT OR IGNORE INTO case_media VALUES(?,?,?,?)',
                           (x['case_id'], x['id'], x.get('role', 'copy'),
                            x.get('state', 'retired')))
            record(db, 'media_custody', x['id'], 'register_media', 1, x)
            return {'decision': 'registered', 'media': x['id']}

        if op == 'retire_media':
            media = _get(db, 'media', x['id'])
            if not media:
                return _blocked('unknown_media')
            if media['state'] == 'sealed':
                return _blocked('sealed_media_protected')
            db.execute("UPDATE media SET state='retired' WHERE id=?", (x['id'],))
            record(db, 'media_custody', x['id'], 'retire_media', 1, x)
            return {'decision': 'retired'}

        if op == 'register_object':
            if _get(db, 'logical_objects', x['id']):
                return {'decision': 'reused'}
            db.execute('INSERT INTO logical_objects VALUES(?,?,?,?)',
                       (x['id'], x['customer'], x['order_no'], x['plaintext_hash']))
            record(db, 'media_custody', x['id'], 'register_object', 1, x)
            return {'decision': 'registered'}

        if op == 'register_block':
            if _get(db, 'physical_blocks', x['id']):
                return {'decision': 'reused'}
            db.execute('INSERT INTO physical_blocks VALUES(?,?,?,?)',
                       (x['id'], x.get('key_id'), x.get('compression', 'none'),
                        x['ciphertext_hash']))
            record(db, 'media_custody', x['id'], 'register_block', 1, x)
            return {'decision': 'registered'}

        if op == 'map_object_block':
            obj = _get(db, 'logical_objects', x['object_id'])
            block = _get(db, 'physical_blocks', x['block_id'])
            if not obj or not block:
                return _blocked('unknown_object_or_block')
            db.execute('INSERT OR IGNORE INTO object_blocks VALUES(?,?)',
                       (x['object_id'], x['block_id']))
            record(db, 'media_custody', x['object_id'], 'map_object_block', 1, x)
            return {'decision': 'mapped'}

        if op == 'place_block':
            if not _get(db, 'physical_blocks', x['block_id']) or \
                    not _get(db, 'media', x['media_id']):
                return _blocked('unknown_block_or_media')
            db.execute('INSERT OR IGNORE INTO block_placement VALUES(?,?,?)',
                       (x['block_id'], x['media_id'], x['offset_no']))
            record(db, 'media_custody', x['block_id'], 'place_block', 1, x)
            return {'decision': 'placed'}

        if op == 'declare_inventory':
            # 保管人据存储商清单声明某案件应存在的全部物理副本。
            # 已声明但块放置台账缺失的副本, 在出证判定中算"漏盘", 不能跳过。
            case_row = _get(db, 'custody_cases', x['case_id'])
            if not case_row:
                return _blocked('unknown_case')
            missing = []
            for item in x['placements']:
                if not _get(db, 'physical_blocks', item['block_id']):
                    return _blocked('unknown_block_or_media')
                db.execute('INSERT OR IGNORE INTO declared_placements VALUES(?,?,?,?,?)',
                           (x['case_id'], item['block_id'], item['media_id'],
                            x['declared_at'], 0))
                present = db.execute(
                    'SELECT 1 FROM block_placement WHERE block_id=? AND media_id=?',
                    (item['block_id'], item['media_id'])).fetchone()
                if not present:
                    missing.append('%s@%s' % (item['block_id'], item['media_id']))
            record(db, 'media_custody', x['case_id'], 'declare_inventory', 1, x)
            return {'decision': 'declared', 'missing_copies': sorted(missing)}

        if op == 'register_order':
            if _get(db, 'legal_orders', x['id']):
                return {'decision': 'reused'}
            reason = _validate_order(db, x)
            if reason:
                return _blocked(reason)
            db.execute('INSERT INTO legal_orders VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                       (x['id'], x['kind'], x['subject'], json.dumps(x['scope']),
                        x['effective_at'], x['expires_at'], x['authority'],
                        x['authority_kind'], json.dumps(x.get('locations') or []),
                        'active', None))
            record(db, 'media_custody', x['id'], 'register_order', 1, x)
            return {'decision': 'registered'}

        if op == 'amend_order':
            old_order = _get(db, 'legal_orders', x['id'])
            if not old_order:
                return _blocked('unknown_order')
            if old_order['authority_kind'] != 'court':
                return _blocked('amendment_requires_court')
            case_row = db.execute(
                'SELECT * FROM custody_cases WHERE preserve_order=?', (x['id'],)).fetchone()
            if case_row and db.execute(
                    "SELECT 1 FROM receipts WHERE case_id=? AND kind='court' AND status='signed'",
                    (case_row['id'],)).fetchone():
                return _blocked('court_delivery_already_made')
            payload = dict(x, kind=old_order['kind'])
            reason = _validate_order(db, payload)
            if reason:
                return _blocked(reason)
            new_id = x['new_id']
            db.execute("UPDATE legal_orders SET state='superseded' WHERE id=?", (x['id'],))
            db.execute('INSERT INTO legal_orders VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                       (new_id, old_order['kind'], x['subject'], json.dumps(x['scope']),
                        x['effective_at'], x['expires_at'], x['authority'],
                        old_order['authority_kind'], json.dumps(x.get('locations') or []),
                        'active', x['id']))
            if case_row:
                db.execute('UPDATE custody_cases SET preserve_order=? WHERE id=?',
                           (new_id, case_row['id']))
                if x.get('mode') in ('reencrypt', 'sealed'):
                    if x['mode'] != case_row['mode'] and db.execute(
                            "SELECT 1 FROM receipts WHERE case_id=? AND kind='escrow' AND status='signed'",
                            (case_row['id'],)).fetchone():
                        return _blocked('escrow_already_established')
                    db.execute('UPDATE custody_cases SET mode=? WHERE id=?',
                               (x['mode'], case_row['id']))
            record(db, 'media_custody', new_id, 'amend_order', 2, x)
            return {'decision': 'amended', 'order': new_id,
                    'mode': x.get('mode')}

        if op == 'register_key':
            if _get(db, 'key_rings', x['id']):
                return {'decision': 'reused'}
            db.execute('INSERT INTO key_rings VALUES(?,?,?,?)',
                       (x['id'], x['quorum'], 'active', None))
            for share in x['shares']:
                db.execute('INSERT OR IGNORE INTO key_shares VALUES(?,?,?,?)',
                           (x['id'], share['share_id'], 'held', share['location']))
            record(db, 'media_custody', x['id'], 'register_key', 1, x)
            return {'decision': 'registered'}

        if op == 'lose_share':
            row = db.execute('SELECT * FROM key_shares WHERE key_id=? AND share_id=?',
                             (x['key_id'], x['share_id'])).fetchone()
            if not row:
                return _blocked('unknown_share')
            db.execute("UPDATE key_shares SET state='lost' WHERE key_id=? AND share_id=?",
                       (x['key_id'], x['share_id']))
            record(db, 'media_custody', x['key_id'], 'lose_share', 1, x)
            return {'decision': 'lost'}

        if op == 'open_case':
            if _get(db, 'custody_cases', x['id']):
                return {'decision': 'reused'}
            d = _get(db, 'legal_orders', x['delete_order'])
            p = _get(db, 'legal_orders', x['preserve_order'])
            if not d or not p:
                return _blocked('case_orders_missing')
            if d['kind'] != 'delete' or p['kind'] != 'preserve':
                return _blocked('case_orders_mismatch')
            if d['state'] != 'active' or p['state'] != 'active':
                return _blocked('order_not_active')
            if x['mode'] not in ('reencrypt', 'sealed'):
                return _blocked('case_mode_invalid')
            db.execute('INSERT INTO custody_cases VALUES(?,?,?,?,?)',
                       (x['id'], x['delete_order'], x['preserve_order'],
                        x['mode'], 'open'))
            scope = set(_loads(d['scope'], [])) | set(_loads(p['scope'], []))
            block_ids = _scoped_blocks(db, scope)
            media_ids = {r[0] for r in db.execute(
                'SELECT DISTINCT media_id FROM block_placement WHERE block_id IN (%s)'
                % ','.join('?' * len(block_ids)), tuple(block_ids))} if block_ids else set()
            for mid in sorted(media_ids):
                db.execute('INSERT OR IGNORE INTO case_media VALUES(?,?,?,?)',
                           (x['id'], mid, 'shared_source', 'retired'))
            record(db, 'media_custody', x['id'], 'open_case', 1, x)
            return {'decision': 'opened', 'mode': x['mode'],
                    'media': sorted(media_ids)}

        case = _get(db, 'custody_cases', x.get('case_id')) if x.get('case_id') else None
        if op != 'case_status' and not case:
            return _blocked('unknown_case')

        if op == 'migrate':
            if case['mode'] != 'reencrypt':
                return _blocked('migration_requires_reencrypt_mode')
            if _get(db, 'media_migrations', x['id']):
                return {'decision': 'reused'}
            obj = _get(db, 'logical_objects', x['object_id'])
            preserve_order = _get(db, 'legal_orders', case['preserve_order'])
            if not obj or obj['id'] not in _loads(preserve_order['scope'], []):
                return _blocked('migration_scope_violation')
            old_blocks = [r[0] for r in db.execute(
                'SELECT block_id FROM object_blocks WHERE object_id=?', (x['object_id'],))]
            old_key_ids = {r[0] for r in db.execute(
                'SELECT DISTINCT key_id FROM physical_blocks WHERE id IN (%s)'
                % ','.join('?' * len(old_blocks)), tuple(old_blocks))} if old_blocks else set()
            ring = _get(db, 'key_rings', next(iter(old_key_ids))) if len(old_key_ids) == 1 else None
            if ring:
                held = db.execute(
                    "SELECT COUNT(*) FROM key_shares WHERE key_id=? AND state='held'",
                    (ring['id'],)).fetchone()[0]
                if held < ring['quorum']:
                    return _blocked('key_quorum_lost')
            new_ring = _get(db, 'key_rings', x['new_key_id'])
            if not new_ring:
                return _blocked('migration_wrong_key')
            if new_ring['id'] in old_key_ids:
                return _blocked('migration_wrong_key')
            held_new = db.execute(
                "SELECT COUNT(*) FROM key_shares WHERE key_id=? AND state='held'",
                (new_ring['id'],)).fetchone()[0]
            if held_new < new_ring['quorum']:
                return _blocked('key_quorum_lost')
            if not _get(db, 'media', x['dest_media']):
                return _blocked('unknown_media')
            db.execute('INSERT INTO media_migrations VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                       (x['id'], case['id'], x['object_id'], ','.join(old_blocks),
                        x['new_block_id'], ','.join(sorted(old_key_ids)), x['new_key_id'],
                        obj['plaintext_hash'], obj['order_no'], 'pending', None))
            record(db, 'media_custody', x['id'], 'migrate', 1, x)
            return {'decision': 'migration_pending'}

        if op == 'verify_migration':
            mig = _get(db, 'media_migrations', x['id'])
            if not mig or mig['case_id'] != case['id']:
                return _blocked('unknown_migration')
            if mig['state'] == 'verified':
                return {'decision': 'reused'}
            block = _get(db, 'physical_blocks', x['new_block_id'])
            if block and block['key_id'] != mig['new_key_id']:
                return _blocked('migration_wrong_key')
            # 哈希与顺序先核验, 不通过则不得落块、不得标记 verified。
            if x['plaintext_hash'] != mig['plaintext_hash'] or x['order_no'] != mig['order_no']:
                return _blocked('migration_hash_mismatch')
            db.execute("UPDATE media_migrations SET state='verified',verified_hash=? WHERE id=?",
                       (x['plaintext_hash'], x['id']))
            db.execute('INSERT OR IGNORE INTO physical_blocks VALUES(?,?,?,?)',
                       (x['new_block_id'], mig['new_key_id'], 'none',
                        x.get('ciphertext_hash', x['new_block_id'])))
            db.execute('INSERT OR IGNORE INTO object_blocks VALUES(?,?)',
                       (mig['object_id'], x['new_block_id']))
            db.execute('INSERT OR IGNORE INTO block_placement VALUES(?,?,?)',
                       (x['new_block_id'], x['dest_media'], x.get('offset_no', 0)))
            db.execute("UPDATE custody_cases SET state='in_progress' WHERE id=?", (case['id'],))
            record(db, 'media_custody', x['id'], 'verify_migration', 2, x)
            return {'decision': 'verified'}

        if op == 'seal_media':
            if case['mode'] != 'sealed':
                return _blocked('seal_requires_sealed_mode')
            media = _get(db, 'media', x['media_id'])
            if not media:
                return _blocked('unknown_media')
            snapshot = _build_snapshot(db, case, x['now'])
            a_set = ep.a_blocks(snapshot, snapshot['delete_subject'])
            on_media = {p['block_id'] for p in snapshot['placements']
                        if p['media_id'] == x['media_id']}
            shared_here = sorted(b for b in a_set
                                 if b in on_media and ep.is_shared_block(snapshot, b))
            if shared_here:
                db.execute("UPDATE custody_cases SET state='halted' WHERE id=?", (case['id'],))
                record(db, 'media_custody', case['id'], 'seal_blocked', 2,
                       {**x, 'shared_blocks': shared_here})
                return _blocked('shared_block_cannot_seal', shared_blocks=shared_here)
            for block_id in sorted(a_set & on_media):
                excised = db.execute(
                    """SELECT 1 FROM receipts WHERE case_id=? AND media_id=? AND block_id=?
                       AND kind='excision' AND status='signed' LIMIT 1""",
                    (case['id'], x['media_id'], block_id)).fetchone()
                if not excised:
                    return _blocked('a_fragment_not_excised', block=block_id)
            escrow = db.execute(
                "SELECT 1 FROM receipts WHERE case_id=? AND media_id=? AND kind='escrow' AND status='signed'",
                (case['id'], x['media_id'])).fetchone()
            if not escrow:
                return _blocked('escrow_receipt_missing')
            db.execute("UPDATE media SET state='sealed' WHERE id=?", (x['media_id'],))
            db.execute(
                "UPDATE case_media SET role='escrow_volume',state='sealed' WHERE case_id=? AND media_id=?",
                (case['id'], x['media_id']))
            db.execute("UPDATE custody_cases SET state='in_progress' WHERE id=?", (case['id'],))
            record(db, 'media_custody', x['media_id'], 'seal_media', 2, x)
            return {'decision': 'sealed'}

        if op == 'erase':
            media = _get(db, 'media', x['media_id'])
            if not media:
                return _blocked('unknown_media')
            if media['state'] == 'sealed':
                return _blocked('sealed_media_protected')
            if _get(db, 'receipts', x['receipt_id']):
                return {'decision': 'reused'}
            db.execute('INSERT INTO receipts VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                       (x['receipt_id'], case['id'], x.get('kind', ep.MEDIA), x.get('vendor', media['vendor']),
                        x['media_id'], x.get('block_id'), x.get('scope', 'media'),
                        json.dumps(x.get('scope_refs') or []), 'commanded', x['now'],
                        json.dumps(x, sort_keys=True)))
            record(db, 'media_custody', x['receipt_id'], 'erase_command', 1, x)
            return {'decision': 'commanded'}

        if op == 'receive_receipt':
            row = _get(db, 'receipts', x['receipt_id'])
            if not row:
                if x['kind'] not in (ep.EXCISION, ep.ESCROW, ep.COURT, 'key_destruction'):
                    return _blocked('unknown_receipt')
                db.execute('INSERT INTO receipts VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                           (x['receipt_id'], case['id'], x['kind'], x['issuer'],
                            x.get('media_id'), x.get('block_id'), x.get('scope'),
                            json.dumps(x.get('scope_refs') or []), x['status'],
                            x['signed_at'], json.dumps(x, sort_keys=True)))
                row = _get(db, 'receipts', x['receipt_id'])
            elif row['status'] == 'signed':
                return {'decision': 'reused', 'status': 'signed'}
            else:
                db.execute('UPDATE receipts SET status=?,signed_at=?,issuer=?,detail=? WHERE id=?',
                           (x['status'], x['signed_at'], x['issuer'],
                            json.dumps(x, sort_keys=True), x['receipt_id']))
            if x['status'] == 'refused':
                db.execute("UPDATE custody_cases SET state='blocked' WHERE id=?", (case['id'],))
                record(db, 'media_custody', x['receipt_id'], 'receipt_refused', 2, x)
                return {'decision': 'refused'}
            if x['kind'] == 'key_destruction':
                for share_id in x.get('scope_refs') or []:
                    db.execute(
                        "UPDATE key_shares SET state='destroyed' WHERE key_id=? AND share_id=?",
                        (x['key_id'], share_id))
            if x['kind'] == ep.MEDIA and x.get('media_id'):
                # 整介质擦除回单才能把介质整体置为 erased; 逐块擦除只证明对应块,
                # 介质上其余客户的片段仍在, 不得冒充整盘清空。
                db.execute("UPDATE media SET state='erased' WHERE id=?", (x['media_id'],))
            record(db, 'media_custody', x['receipt_id'], 'receive_receipt', 2, x)
            return {'decision': 'received', 'kind': x['kind']}

        if op == 'destroy_key':
            ring = _get(db, 'key_rings', x['key_id'])
            if not ring:
                return _blocked('unknown_key')
            if ring['state'] == 'destroyed':
                return {'decision': 'reused'}
            shares = db.execute('SELECT * FROM key_shares WHERE key_id=?', (x['key_id'],)).fetchall()
            for share in shares:
                if share['state'] != 'destroyed':
                    return _blocked('key_share_unaccounted', share=share['share_id'])
            db.execute("UPDATE key_rings SET state='destroyed' WHERE id=?", (x['key_id'],))
            record(db, 'media_custody', x['key_id'], 'destroy_key', 2, x)
            return {'decision': 'destroyed'}

        if op == 'deliver_court':
            preserve_order = _get(db, 'legal_orders', case['preserve_order'])
            scope = _loads(preserve_order['scope'], [])
            if sorted(x['scope_refs']) != sorted(scope):
                return _blocked('court_delivery_scope_mismatch')
            delete_order = _get(db, 'legal_orders', case['delete_order'])
            if set(x['scope_refs']) & set(_loads(delete_order['scope'], [])):
                return _blocked('customer_a_records_disclosed')
            snapshot = _build_snapshot(db, case, x['now'])
            # 先核对密钥可用性: 证据存在但门限丢失时应报不可读原因。
            for key in snapshot['keys']:
                if key['state'] == 'destroyed':
                    continue
                held = [s for s in key['shares'] if s['state'] == 'held']
                if len(held) < key['quorum']:
                    return _blocked('b_key_quorum_lost', key=key['id'])
            base_manifest = ep.verify_b_manifest(
                {**snapshot, 'delivered_manifest': None}, snapshot['preserve_subject'])
            if not base_manifest['ok']:
                return _blocked('b_evidence_not_readable', manifest=base_manifest)
            # 交付清单须逐对象核对原文哈希与顺序, 法院只收保全令指定记录。
            if x.get('manifest'):
                checked = ep.verify_b_manifest(
                    {**snapshot, 'delivered_manifest': x['manifest']},
                    snapshot['preserve_subject'])
                if not checked['ok']:
                    return _blocked('b_evidence_manifest_mismatch', manifest=checked)
            if _get(db, 'receipts', x['receipt_id']):
                return {'decision': 'reused'}
            db.execute('INSERT INTO receipts VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                       (x['receipt_id'], case['id'], ep.COURT, x['issuer'], None, None,
                        'object', json.dumps(x['scope_refs']), 'signed', x['signed_at'],
                        json.dumps(x, sort_keys=True)))
            record(db, 'media_custody', x['receipt_id'], 'deliver_court', 2, x)
            return {'decision': 'delivered'}

        if op == 'discover_copy':
            media = _get(db, 'media', x['id'])
            if media:
                return {'decision': 'reused', 'state': media['state']}
            db.execute('INSERT INTO media VALUES(?,?,?,?,?,?,?,?,?)',
                       (x['id'], 'offline_copy', x.get('node_id'), x.get('wave_id'),
                        x['location'], x['vendor'], 'discovered', x.get('parent_media_id'),
                        x['discovered_at']))
            for placement in x.get('placements', []):
                if _get(db, 'physical_blocks', placement['block_id']):
                    db.execute('INSERT OR IGNORE INTO block_placement VALUES(?,?,?)',
                               (placement['block_id'], x['id'], placement['offset_no']))
            db.execute('INSERT OR IGNORE INTO case_media VALUES(?,?,?,?)',
                       (case['id'], x['id'], 'offline_copy', 'discovered'))
            prior = db.execute(
                "SELECT id FROM deletion_certificates WHERE case_id=? AND state='issued' ORDER BY version DESC",
                (case['id'],)).fetchone()
            superseded = None
            if prior:
                superseded = prior[0]
                db.execute("UPDATE deletion_certificates SET state='superseded' WHERE id=?",
                           (superseded,))
            db.execute("UPDATE custody_cases SET state='in_progress' WHERE id=?", (case['id'],))
            record(db, 'media_custody', x['id'], 'discover_copy', 2,
                    {**x, 'superseded_certificate': superseded})
            return {'decision': 'discovered', 'superseded_certificate': superseded}

        if op == 'certify':
            snapshot = _build_snapshot(db, case, x['now'])
            verdict = ep.evaluate(snapshot)
            existing = db.execute(
                "SELECT * FROM deletion_certificates WHERE case_id=? AND state='issued' ORDER BY version DESC LIMIT 1",
                (case['id'],)).fetchone()
            if existing and verdict['certifiable']:
                # 断电重试只能取回原证书; 用旧编号索取"新证书"是重复出具, 必须拒绝。
                if x['certificate_id'] != existing['id']:
                    prior_same = _get(db, 'deletion_certificates', x['certificate_id'])
                    if prior_same:
                        return _blocked('certificate_id_reused')
                return {'decision': 'reused', 'certificate': existing['id'],
                        'version': existing['version']}
            if _get(db, 'deletion_certificates', x['certificate_id']):
                # 该编号已被(含已更正的)证书占用, 换发必须使用新编号。
                return _blocked('certificate_id_reused')
            if not verdict['certifiable']:
                if case['state'] not in ('halted',):
                    db.execute("UPDATE custody_cases SET state='blocked' WHERE id=?", (case['id'],))
                record(db, 'media_custody', case['id'], 'certify_refused', 2,
                        {'blockers': verdict['blockers']})
                return _blocked('erase_unproven', blockers=verdict['blockers'],
                                object_only_receipts=verdict['object_only_receipts'])
            version = (db.execute(
                'SELECT COALESCE(MAX(version),0)+1 FROM deletion_certificates WHERE case_id=?',
                (case['id'],)).fetchone()[0])
            basis = {
                'receipts': sorted(r['id'] for r in snapshot['receipts']
                                   if r['status'] == 'signed'),
                'a_blocks': verdict['a_blocks'],
                'shared_blocks': verdict['shared_blocks'],
                'migrations': sorted(m['id'] for m in snapshot['migrations']),
                'court_scope': snapshot['preserve_scope'],
            }
            cert_id = x['certificate_id']
            db.execute('INSERT INTO deletion_certificates VALUES(?,?,?,?,?,?,?)',
                       (cert_id, case['id'], snapshot['delete_subject'], version,
                        'issued', json.dumps(basis, sort_keys=True), None))
            if version > 1:
                db.execute(
                    'UPDATE deletion_certificates SET superseded_by=? WHERE case_id=? AND state=?',
                    (cert_id, case['id'], 'superseded'))
            db.execute("UPDATE custody_cases SET state='certified' WHERE id=?", (case['id'],))
            record(db, 'media_custody', cert_id, 'certify', version, basis)
            return {'decision': 'certified', 'certificate': cert_id, 'version': version,
                    'basis': basis}

        if op == 'case_status':
            row = _get(db, 'custody_cases', x['case_id'])
            if not row:
                return _blocked('unknown_case')
            snapshot = _build_snapshot(db, row, x['now'])
            verdict = ep.evaluate(snapshot)
            certs = [dict(c) for c in db.execute(
                'SELECT * FROM deletion_certificates WHERE case_id=? ORDER BY version',
                (x['case_id'],))]
            return {'decision': row['state'], 'mode': row['mode'],
                    'certifiable': verdict['certifiable'], 'blockers': verdict['blockers'],
                    'certificates': certs}

        raise ValueError(op)
