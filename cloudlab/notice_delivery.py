"""Exact originals, delivery events and receipts for incident notices."""
import json

from . import incident_scope as scope_mod
from .store import audit_run, transaction
from .incident_scope import (
    as_bytes,
    canonical_json,
    pick,
    sha256_hex,
)


CUSTOMER_FACING_KINDS = {'customer_private', 'service_advisory'}


def _json_loads(value, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _row_dict(row):
    return dict(row) if row is not None else None


def _normalize_kind(value, op=None):
    text = str(value or '').strip().lower().replace('-', '_')
    aliases = {
        'private': 'customer_private',
        'customer': 'customer_private',
        'customer_notice': 'customer_private',
        'precise': 'customer_private',
        'precise_letter': 'customer_private',
        'private_notice': 'customer_private',
        'private_letter': 'customer_private',
        'customer_private': 'customer_private',
        'advisory': 'service_advisory',
        'general': 'service_advisory',
        'general_notice': 'service_advisory',
        'service': 'service_advisory',
        'service_notice': 'service_advisory',
        'service_advisory': 'service_advisory',
        'preliminary_notice': 'service_advisory',
        'regulator': 'regulator_supplement',
        'regulatory': 'regulator_supplement',
        'regulator_report': 'regulator_supplement',
        'regulatory_report': 'regulator_supplement',
        'supplement': 'regulator_supplement',
        'supplemental_report': 'regulator_supplement',
        'regulator_supplement': 'regulator_supplement',
        'correction': 'correction',
        'correct': 'correction',
        'correct_notice': 'correction',
        'send_correction': 'correction',
        'correction_letter': 'correction',
    }
    if not text and op in ('send_advisory', 'advisory'):
        return 'service_advisory'
    if not text and op in ('send_private', 'private_notice'):
        return 'customer_private'
    if not text and op in ('file_regulator', 'regulator_supplement'):
        return 'regulator_supplement'
    if not text and op in ('correct', 'correction', 'correct_notice', 'send_correction'):
        return 'correction'
    return aliases.get(text, text or 'customer_private')


def _classification_item(scope, client_id):
    for classification in ('confirmed', 'possible', 'excluded', 'unknown'):
        for item in scope.get(classification, []):
            if item.get('client_id') == client_id:
                return item
    return None


_CLASSIFICATION_ZH = {
    'confirmed': '确证',
    'possible': '可能',
    'excluded': '已排除',
    'unknown': '未知',
}


def _redact_other_identities(text, scope, recipient_id):
    """Redact scope-known other client IDs from generated private prose."""
    if not text:
        return text
    for key in ('confirmed_client_ids', 'possible_client_ids',
                'excluded_client_ids', 'unknown_client_ids'):
        for client_id in scope.get(key, []):
            if client_id != recipient_id and client_id is not None:
                text = text.replace(str(client_id), '另一主体')
    return text


def _identity_leaks(body, scope, recipient_id=None):
    try:
        text = bytes(body or b'').decode('utf-8', errors='ignore')
    except Exception:
        text = ''
    leaks = []
    for key in ('confirmed_client_ids', 'possible_client_ids',
                'excluded_client_ids', 'unknown_client_ids'):
        for client_id in scope.get(key, []):
            if client_id is None or client_id == recipient_id:
                continue
            if str(client_id) in text:
                leaks.append(client_id)
    return sorted(set(leaks), key=str)


def _counts(scope):
    return {key: len(scope.get(key + '_client_ids', scope.get(key, [])))
            for key in ('confirmed', 'possible', 'excluded', 'unknown')}


def render_private_notice(scope, recipient_id, correction_of=None,
                          claimed_classification=None, reason=None):
    item = _classification_item(scope, recipient_id) or {'classification': 'unknown', 'trace_ids': []}
    classification = item['classification']
    classification_zh = _CLASSIFICATION_ZH.get(classification, classification)
    counts = _counts(scope)
    lines = [
        '升级事故客户通知 / Upgrade incident private notice',
        f"事故编号: {scope.get('incident_id')}",
        f"故障版本: {scope.get('fault_version')}",
        f"客户编号: {recipient_id}",
        f"您本人的核查状态: 【{classification_zh} / {classification}】",
    ]
    if correction_of:
        lines.insert(0, '更正信 / Correction notice')
        lines.append(f'本函更正原通知: {correction_of}')
        if claimed_classification:
            claimed_zh = _CLASSIFICATION_ZH.get(claimed_classification, claimed_classification)
            lines.append(f'原通知记载的状态: 【{claimed_zh} / {claimed_classification}】；该记载现予更正。')
        safe_reason = _redact_other_identities(
            reason or '真实客户端签认或令牌反转后，主体识别发生变化', scope, recipient_id)
        lines.append(f"更正原因: {safe_reason}")
    traces = item.get('trace_ids') or item.get('confirmed_trace_ids') or []
    if traces:
        lines.append(f"与您相关的物理追踪号: {', '.join(traces)}")
    if item.get('signed_at') is not None:
        lines.append(f"客户端最终签收分钟: {item['signed_at']}")
    lines.extend([
        '范围分类计数（不包含任何其他客户或租户身份）: '
        f"确证 {counts['confirmed']}；可能 {counts['possible']}；"
        f"已排除 {counts['excluded']}；未知 {counts['unknown']}。",
        '本函仅披露您本人的状态；不得据此推断任何其他主体的身份。',
        '节点健康状态不能单独证明或排除单份客户响应外泄。',
    ])
    return '\n'.join(lines).encode('utf-8')


def render_advisory(scope):
    counts = _counts(scope)
    lines = [
        '升级事故服务级预告 / Identity-free service advisory',
        f"事故编号: {scope.get('incident_id')}",
        f"故障版本: {scope.get('fault_version')}",
        '本预告不含租户、客户、代理地址背后主体或签收令牌指向的身份。',
        '当前范围分类计数: '
        f"确证 {counts['confirmed']}；可能 {counts['possible']}；"
        f"已排除 {counts['excluded']}；未知 {counts['unknown']}。",
        '共享代理、NAT 复用、代理重试或跨区回源的同一物理响应只按追踪号计一次。',
        '网关成功码不是终端签收；本预告不证明任何特定客户已经逐客户签收。',
        '保密托管人完成身份解封后，仅真实受损客户会收到精确私函。',
    ]
    return '\n'.join(lines).encode('utf-8')


def render_regulator(scope, incident=None, supplement_reason=None):
    payload = {
        'notice_type': 'regulator_supplement',
        'supplement_reason': supplement_reason or 'incident_scope_and_delivery_ledger',
        'incident': {
            'incident_id': scope.get('incident_id'),
            'fault_version': scope.get('fault_version'),
            'wave_id': scope.get('wave_id'),
            'node_id': scope.get('node_id'),
            'legal_clock_started_at': scope.get('legal_clock_started_at'),
            'first_notice_deadline_at': scope.get('first_notice_deadline_at'),
            'earliest_fault_at': scope.get('earliest_fault_at'),
        },
        'classification_counts': _counts(scope),
        # Regulator copy is allowed to contain the full accountable scope.
        'scope': scope,
    }
    return canonical_json(payload).encode('utf-8')


def render_correction(scope, recipient_id, old_notice=None, x=None):
    x = x or {}
    old_id = pick(x, 'corrects_notice_id', 'corrects', 'old_notice_id') or \
        (old_notice or {}).get('notice_id')
    claimed = pick(x, 'claimed_classification', 'prior_classification', 'old_classification')
    reason = pick(x, 'correction_reason', 'reason')
    if pick(x, 'body', 'raw', 'body_raw', 'original_bytes') is not None:
        return as_bytes(pick(x, 'body', 'raw', 'body_raw', 'original_bytes'))
    if pick(x, 'correction_text'):
        return as_bytes(x['correction_text'])
    return render_private_notice(scope, recipient_id, correction_of=old_id,
                                 claimed_classification=claimed, reason=reason)


def _status_from_rows(doc, recipients, events):
    recipient_values = []
    counts = {
        'recipient_count': len(recipients),
        'external_recipient_count': len(recipients),
        'queued_count': 0,
        'sent_count': 0,
        'gateway_accepted_count': 0,
        'unconfirmed_count': 0,
        'delivered_count': 0,
        'bounced_count': 0,
        'signed_count': 0,
        'final_receipt_count': 0,
    }
    for row in recipients:
        item = _row_dict(row)
        item.pop('detail_json', None)
        recipient_values.append(item)
        state = item['state']
        count_key = state + '_count'
        if count_key in counts:
            counts[count_key] += 1
        if state in ('sent', 'queued', 'gateway_accepted'):
            counts['unconfirmed_count'] += 1
        if state == 'signed':
            counts['final_receipt_count'] += 1
    event_values = []
    for event in events:
        item = _row_dict(event)
        item.pop('receipt_bytes', None)
        event_values.append(item)
    signed_minutes = [r['signed_at'] for r in recipient_values if r.get('signed_at') is not None]
    final_signed_at = max(signed_minutes) if signed_minutes else doc['final_signed_at']
    body_raw = bytes(doc['body_raw']) if doc['body_raw'] is not None else None
    return {
        'decision': 'status',
        'notice_id': doc['notice_id'],
        'incident_id': doc['incident_id'],
        'kind': doc['kind'],
        'notice_role': doc['notice_role'],
        'execution_mode': doc['execution_mode'],
        'state': doc['state'],
        'status': doc['state'],
        'late': bool(doc['late']),
        'authorizer': doc['authorizer'],
        'authorized_by': doc['authorizer'],
        'approval_id': doc['approval_id'],
        'corrects_notice_id': doc['corrects_notice_id'],
        'scope_hash': doc['scope_hash'],
        'body_hash': doc['body_hash'],
        'body_raw': body_raw,
        'raw_bytes': body_raw,
        'original_bytes': body_raw,
        'body_length': len(body_raw or b''),
        'body_format': doc['body_format'],
        'created_at': doc['created_at'],
        'first_sent_at': doc['first_sent_at'],
        'sent_at': doc['first_sent_at'],
        'signed_at': final_signed_at,
        'signed_minute': final_signed_at,
        'final_receipt_at': final_signed_at,
        'final_signed_at': final_signed_at,
        'recipients': recipient_values,
        'events': event_values,
        **counts,
        'actual_external_recipient_count': len(recipients),
        'client_receipt_proven': counts['signed_count'] > 0,
        'terminal_delivery_proven': counts['signed_count'] > 0 or counts['delivered_count'] > 0,
    }


def notice_status(db, notice_id):
    doc = db.execute('SELECT * FROM notice_documents WHERE notice_id=?', (notice_id,)).fetchone()
    if not doc:
        return None
    recipients = db.execute('SELECT * FROM notice_recipients WHERE notice_id=? ORDER BY rowid',
                            (notice_id,)).fetchall()
    events = db.execute('SELECT * FROM notice_events WHERE notice_id=? ORDER BY id',
                        (notice_id,)).fetchall()
    return _status_from_rows(doc, recipients, events)


def get_notice_bytes(db, notice_id):
    row = db.execute('SELECT body_raw FROM notice_documents WHERE notice_id=?', (notice_id,)).fetchone()
    return bytes(row['body_raw']) if row and row['body_raw'] is not None else None


def _first_customer_notice(db, incident_id):
    row = db.execute("""
        SELECT * FROM notice_documents
        WHERE incident_id=? AND kind IN ('customer_private','service_advisory')
        ORDER BY COALESCE(first_sent_at, created_at) ASC, rowid ASC
        LIMIT 1
    """, (incident_id,)).fetchone()
    return _row_dict(row)


def _normalize_recipients(db, x, kind, case):
    raw = pick(x, 'recipients', 'recipient_ids', 'recipient_list', 'client_ids',
               'customer_ids', 'subscriber_ids', 'to')
    result = []
    if raw is not None:
        if isinstance(raw, str):
            raw = [raw]
        for value in raw:
            if isinstance(value, dict):
                rid = pick(value, 'recipient_id', 'client_id', 'customer_id', 'id')
                address = pick(value, 'address', 'endpoint', 'email', 'channel_address')
                rkind = pick(value, 'recipient_kind', 'kind', default='customer')
            else:
                rid, address, rkind = value, None, 'customer'
            if rid:
                result.append((str(rid), address, rkind))
    single = pick(x, 'recipient_id', 'client_id', 'customer_id', 'recipient')
    if single and not any(r[0] == str(single) for r in result):
        address = pick(x, 'address', 'endpoint', 'email', 'recipient_address')
        rkind = pick(x, 'recipient_kind', default='regulator' if kind == 'regulator_supplement' else 'customer')
        result.append((str(single), address, rkind))
    if not result and kind == 'regulator_supplement':
        rid = pick(x, 'regulator_id', 'authority_id', default='regulator')
        result.append((rid, pick(x, 'regulator_address', 'address'), 'regulator'))
    if not result and kind == 'service_advisory':
        ids = _json_loads(case['known_clients_json'], []) if case else []
        addresses = pick(x, 'addresses', 'address_map', default={}) or {}
        for rid in ids:
            result.append((str(rid), addresses.get(str(rid)) if isinstance(addresses, dict) else None, 'subscriber'))
    if not result and kind in ('customer_private', 'correction'):
        # Correction of a broadcast advisory without an explicit list goes to
        # every original recipient; private corrections normally name one.
        old_id = pick(x, 'corrects_notice_id', 'corrects', 'old_notice_id')
        if old_id:
            for row in db_global_recipients(db, old_id):
                result.append((row['recipient_id'], row['address'], row['recipient_kind']))
    return result


def db_global_recipients(db, notice_id):
    if db is None:
        return []
    return db.execute('SELECT * FROM notice_recipients WHERE notice_id=? ORDER BY rowid',
                      (notice_id,)).fetchall()


def add_event(db, notice_id, recipient_id, event_type, at=None, code=None,
              detail=None, receipt_bytes=None, event_id=None, signer=None):
    if event_id is None:
        event_id = f'{notice_id}:{recipient_id or "all"}:{event_type}:{at}:{code or ""}:{sha256_hex(canonical_json(detail or {}))[:10]}'
    old = db.execute('SELECT * FROM notice_events WHERE event_id=?', (event_id,)).fetchone()
    if old:
        return _row_dict(old), True
    receipt_data = as_bytes(receipt_bytes) if receipt_bytes is not None else None
    receipt_hash = sha256_hex(receipt_data) if receipt_data else None
    db.execute('INSERT INTO notice_events(event_id,notice_id,recipient_id,event_type,at,code,detail_json,receipt_bytes,receipt_hash) VALUES(?,?,?,?,?,?,?,?,?)',
               (event_id, notice_id, recipient_id, event_type, at,
                None if code is None else str(code), canonical_json(detail or {}),
                receipt_data, receipt_hash))
    if recipient_id:
        recipient = db.execute('SELECT * FROM notice_recipients WHERE notice_id=? AND recipient_id=?',
                               (notice_id, recipient_id)).fetchone()
        if recipient:
            state = event_type
            updates = {'state': event_type}
            if event_type == 'send_attempt':
                db.execute('UPDATE notice_recipients SET attempts=attempts+1,sent_at=COALESCE(sent_at,?),state=? WHERE notice_id=? AND recipient_id=?',
                           (at, 'sent', notice_id, recipient_id))
            elif event_type == 'gateway_accepted':
                db.execute('UPDATE notice_recipients SET state=?,accepted_at=?,gateway_code=? WHERE notice_id=? AND recipient_id=?',
                           ('gateway_accepted', at, None if code is None else str(code), notice_id, recipient_id))
            elif event_type == 'bounced':
                reason = pick(detail or {}, 'reason', 'bounce_reason') if isinstance(detail, dict) else None
                db.execute('UPDATE notice_recipients SET state=?,bounced_at=?,bounce_code=?,bounce_reason=? WHERE notice_id=? AND recipient_id=?',
                           ('bounced', at, None if code is None else str(code), reason, notice_id, recipient_id))
            elif event_type == 'delivered':
                db.execute('UPDATE notice_recipients SET state=?,delivered_at=? WHERE notice_id=? AND recipient_id=?',
                           ('delivered', at, notice_id, recipient_id))
            elif event_type == 'signed':
                db.execute('UPDATE notice_recipients SET state=?,signed_at=?,signer=COALESCE(?,signer),receipt_hash=? WHERE notice_id=? AND recipient_id=?',
                           ('signed', at, signer, receipt_hash, notice_id, recipient_id))
            else:
                db.execute('UPDATE notice_recipients SET state=? WHERE notice_id=? AND recipient_id=?',
                           (state, notice_id, recipient_id))
    return _row_dict(db.execute('SELECT * FROM notice_events WHERE event_id=?', (event_id,)).fetchone()), False


def _apply_inline_outcomes(db, notice_id, recipient_ids, x, at):
    for rid in recipient_ids:
        gateway_code = pick(x, 'gateway_code', 'provider_code', 'status_code')
        if gateway_code is not None or pick(x, 'gateway_accepted', 'provider_accepted', default=False):
            add_event(db, notice_id, rid, 'gateway_accepted',
                      pick(x, 'gateway_at', 'accepted_at', default=at),
                      code=gateway_code or '200', detail={'gateway_success_code_only': True})
        if pick(x, 'bounced', 'bounce', default=False):
            add_event(db, notice_id, rid, 'bounced',
                      pick(x, 'bounced_at', 'bounce_at', default=at),
                      code=pick(x, 'bounce_code', default='550'),
                      detail={'reason': pick(x, 'bounce_reason', 'reason', default='bounced')})
        if pick(x, 'delivered', 'actual_delivered', default=False):
            add_event(db, notice_id, rid, 'delivered',
                      pick(x, 'delivered_at', default=at), detail={'carrier_confirmation': True})
        signed_at = pick(x, 'signed_at', 'receipt_at', 'ack_at')
        receipt = pick(x, 'receipt', 'signature', 'receipt_bytes', 'signed_receipt')
        if pick(x, 'signed', 'client_signed', 'final_receipt', default=False) or signed_at is not None or receipt is not None:
            add_event(db, notice_id, rid, 'signed',
                      signed_at if signed_at is not None else at,
                      detail={'terminal_client_confirmation': True},
                      receipt_bytes=receipt if receipt is not None else canonical_json({'signed': True, 'at': at}),
                      signer=pick(x, 'signer', 'client_signer'))


def issue_notice(db, x, op=None):
    candidate_id = pick(x, 'id')
    incident_id = pick(x, 'incident_id', 'incident', 'case_id', 'case')
    if not incident_id:
        wave_ref = pick(x, 'wave_id', 'wave')
        if wave_ref:
            incident_id = f'incident-{wave_ref}'
    if not incident_id and candidate_id and scope_mod._incident(db, candidate_id):
        incident_id = candidate_id
    case = scope_mod._incident(db, incident_id) if incident_id else None
    if not case:
        return {'decision': 'blocked', 'reason': 'unknown_incident'}

    explicit_notice_id = pick(x, 'notice_id', 'notification_id', 'letter_id', 'notice', 'letter')
    idem_key = pick(x, 'idempotency_key', 'request_id', 'client_request_id')
    notice_id = explicit_notice_id
    if not notice_id and candidate_id and candidate_id != incident_id:
        notice_id = candidate_id
    if not notice_id:
        notice_id = idem_key
    if not notice_id:
        return {'decision': 'blocked', 'reason': 'missing_notice_id_or_request_id'}
    if not idem_key:
        idem_key = notice_id

    existing = db.execute('SELECT * FROM notice_documents WHERE notice_id=? OR idempotency_key=?',
                          (notice_id, idem_key)).fetchone()
    if existing:
        status = notice_status(db, existing['notice_id'])
        status.update({'decision': 'reused', 'idempotent': True,
                       'same_notice': existing['notice_id'] == notice_id})
        return status

    kind = _normalize_kind(pick(x, 'kind', 'notice_type', 'letter_type'), op)
    corrects_id = pick(x, 'corrects_notice_id', 'corrects', 'old_notice_id')
    old_notice = None
    if kind == 'correction':
        if not corrects_id:
            return {'decision': 'blocked', 'reason': 'correction_requires_original_notice'}
        old_notice = db.execute('SELECT * FROM notice_documents WHERE notice_id=?', (corrects_id,)).fetchone()
        if not old_notice:
            return {'decision': 'blocked', 'reason': 'unknown_original_notice'}
        old_notice = _row_dict(old_notice)

    authorizer = pick(x, 'authorizer', 'authorized_by', 'legal_authorizer', 'approver') or \
        case['authorizer'] or case['contract_owner']
    if not authorizer:
        return {'decision': 'blocked', 'reason': 'missing_authorizer'}

    mode = scope_mod._normalize_mode(pick(x, 'execution_mode', 'route', 'plan', 'approved_route'))
    prior = _first_customer_notice(db, incident_id)
    if not mode:
        mode = 'advisory_first' if kind == 'service_advisory' or prior else 'escrow_precise'
    approved_modes = _json_loads(case['approved_modes_json'], [])
    approval_rows = db.execute('SELECT mode FROM incident_approvals WHERE incident_id=?', (incident_id,)).fetchall()
    approved_modes = sorted(set(approved_modes + [r['mode'] for r in approval_rows]))
    if approved_modes and mode not in approved_modes and not pick(x, 'force_unapproved_route', default=False):
        return {'decision': 'blocked', 'reason': 'execution_route_not_preapproved',
                'execution_mode': mode, 'approved_modes': approved_modes}

    scope = scope_mod.build_scope(db, incident_id, at=pick(x, 'at', 'minute'))
    if scope.get('decision') == 'blocked':
        return scope

    # Resolve recipients before rendering because a private body is bound to
    # exactly one authorized recipient.
    recipient_tuples = _normalize_recipients(db, x, kind, case)
    recipient_ids = [r[0] for r in recipient_tuples]
    if kind == 'customer_private' and len(set(recipient_ids)) > 1:
        return {'decision': 'blocked', 'reason': 'private_notice_requires_single_recipient'}

    raw_override = pick(x, 'body_raw', 'raw', 'original_bytes', 'raw_bytes')
    body_override = pick(x, 'body', 'content', 'text')
    if raw_override is not None:
        body = as_bytes(raw_override)
        body_format = pick(x, 'body_format', default='raw')
    elif body_override is not None:
        body = as_bytes(body_override)
        body_format = pick(x, 'body_format', default='utf-8')
    else:
        if kind == 'service_advisory':
            body = render_advisory(scope)
        elif kind == 'regulator_supplement':
            body = render_regulator(scope, case, pick(x, 'supplement_reason', 'reason'))
        elif kind == 'correction':
            if not recipient_ids:
                # Broadcast correction: same identity-free corrected advisory.
                body = render_advisory(scope)
            else:
                body = render_correction(scope, recipient_ids[0], old_notice, x)
        else:
            if not recipient_ids:
                return {'decision': 'blocked', 'reason': 'missing_private_recipient'}
            rid = recipient_ids[0]
            item = _classification_item(scope, rid)
            classification = item['classification'] if item else 'unknown'
            if classification != 'confirmed' and not pick(x, 'force_unconfirmed', 'allow_unconfirmed', default=False):
                return {'decision': 'blocked', 'reason': 'recipient_not_confirmed',
                        'recipient_id': rid, 'classification': classification}
            body = render_private_notice(scope, rid)
        body_format = pick(x, 'body_format', default='utf-8' if kind != 'regulator_supplement' else 'json')

    if kind == 'customer_private' and not pick(x, 'force_unconfirmed', 'allow_unconfirmed', default=False):
        rid = recipient_ids[0] if recipient_ids else pick(x, 'recipient_id')
        item = _classification_item(scope, rid)
        if not item or item['classification'] != 'confirmed':
            return {'decision': 'blocked', 'reason': 'recipient_not_confirmed',
                    'recipient_id': rid,
                    'classification': item['classification'] if item else 'unknown'}

    if not recipient_tuples:
        return {'decision': 'blocked', 'reason': 'missing_recipients'}

    if kind != 'regulator_supplement':
        privacy_recipient = recipient_ids[0] if len(recipient_ids) == 1 and kind in ('customer_private', 'correction') else None
        leaks = _identity_leaks(body, scope, privacy_recipient)
        if leaks:
            return {'decision': 'blocked', 'reason': 'cross_customer_identity_in_notice_body',
                    'leaked_identity_count': len(leaks)}

    body_hash = sha256_hex(body)
    sent_at = pick(x, 'sent_at', 'sent_minute', 'issued_at', 'issue_minute', 'at', 'minute')
    created_at = pick(x, 'created_at', default=sent_at)
    late = 0
    deadline = case['deadline_at']
    is_first = prior is None and kind in CUSTOMER_FACING_KINDS
    if is_first and sent_at is not None and deadline is not None and int(sent_at) > int(deadline):
        breach_approver = pick(x, 'breach_authorized_by', 'late_filing_authorized_by')
        if not pick(x, 'accept_breach', 'late_filing', default=False) or not breach_approver:
            return {'decision': 'blocked', 'reason': 'first_notice_deadline_exceeded',
                    'sent_at': sent_at, 'deadline_at': deadline}
        late = 1

    request_core = {
        'incident_id': incident_id, 'kind': kind, 'notice_id': notice_id,
        'idempotency_key': idem_key, 'recipients': recipient_ids,
        'execution_mode': mode, 'corrects': corrects_id, 'body_hash': body_hash,
    }
    request_hash = sha256_hex(canonical_json(request_core))
    conflicting = db.execute('SELECT notice_id,request_hash FROM notice_documents WHERE idempotency_key=?',
                             (idem_key,)).fetchone()
    if conflicting and conflicting['request_hash'] != request_hash:
        return {'decision': 'blocked', 'reason': 'idempotency_conflict',
                'existing_notice_id': conflicting['notice_id']}

    authorization = pick(x, 'authorization', default={})
    if not isinstance(authorization, dict):
        authorization = {'statement': str(authorization)}
    authorization = dict(authorization)
    authorization.update({
        'authorizer': authorizer,
        'approval_id': pick(x, 'approval_id'),
        'contract_owner': case['contract_owner'],
        'security_officer': case['security_officer'],
        'force_unconfirmed': bool(pick(x, 'force_unconfirmed', 'allow_unconfirmed', default=False)),
    })
    notice_role = pick(x, 'notice_role') or ('first' if is_first else ('correction' if kind == 'correction' else 'followup'))
    audience_type = pick(x, 'audience_type', 'audience') or (
        'regulator' if kind == 'regulator_supplement' else
        'subscribers' if kind == 'service_advisory' else 'customer')
    initial_state = 'issued' if sent_at is None else 'sent'
    db.execute('INSERT INTO notice_documents VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
               (notice_id, idem_key, request_hash, incident_id, kind, notice_role, mode,
                audience_type,
                recipient_ids[0] if len(recipient_ids) == 1 and kind != 'service_advisory' else pick(x, 'recipient_id'),
                authorizer, canonical_json(authorization), pick(x, 'approval_id'), corrects_id,
                pick(x, 'scope_id'), scope['scope_hash'], body_format, body, body_hash,
                initial_state, late, created_at, sent_at, None, canonical_json(x)))

    addresses = pick(x, 'addresses', 'address_map', default={}) or {}
    for rid, address, rkind in recipient_tuples:
        if address is None and isinstance(addresses, dict):
            address = addresses.get(rid)
        if address is None:
            address = pick(x, 'address', 'endpoint', 'email') if len(recipient_tuples) == 1 else None
        if address is None:
            address = f'{pick(x,"channel","secure-channel")}:{rid}'
        db.execute('INSERT INTO notice_recipients VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                   (notice_id, rid, str(address), rkind, 'queued', 0, None, None, None,
                    None, None, None, None, None, None, None, canonical_json({})))
        if sent_at is not None:
            add_event(db, notice_id, rid, 'send_attempt', sent_at,
                      code=pick(x, 'submission_code', default='queued'),
                      detail={'channel': pick(x, 'channel', default='secure-channel')},
                      event_id=f'{notice_id}:{rid}:initial_send:{sent_at}')

    if sent_at is not None:
        _apply_inline_outcomes(db, notice_id, recipient_ids, x, sent_at)
        states = [r['state'] for r in db.execute('SELECT state FROM notice_recipients WHERE notice_id=?', (notice_id,))]
        if states and all(s == 'signed' for s in states):
            db.execute("UPDATE notice_documents SET state='signed',final_signed_at=? WHERE notice_id=?",
                       (pick(x, 'signed_at', default=sent_at), notice_id))
        elif any(s == 'bounced' for s in states):
            db.execute("UPDATE notice_documents SET state='bounced' WHERE notice_id=?", (notice_id,))
        elif any(s in ('delivered', 'signed') for s in states):
            db.execute("UPDATE notice_documents SET state='partially_delivered' WHERE notice_id=?", (notice_id,))
        elif any(s == 'gateway_accepted' for s in states):
            db.execute("UPDATE notice_documents SET state='gateway_accepted' WHERE notice_id=?", (notice_id,))
        else:
            db.execute("UPDATE notice_documents SET state='sent' WHERE notice_id=?", (notice_id,))

    if old_notice:
        db.execute("UPDATE notice_documents SET detail_json=? WHERE notice_id=?",
                   (canonical_json({**_json_loads(db.execute('SELECT detail_json FROM notice_documents WHERE notice_id=?', (corrects_id,)).fetchone()['detail_json'], {}),
                                    'corrected_by': notice_id}), corrects_id))
    status = notice_status(db, notice_id)
    status.update({
        'decision': 'issued' if not late else 'issued_late_breach_recorded',
        'issued': True,
        'sent': sent_at is not None,
        'idempotent': False,
        'first_notice': is_first,
        'first_notice_id': notice_id if is_first else (_first_customer_notice(db, incident_id) or {}).get('notice_id'),
        'deadline_met': not late and (deadline is None or sent_at is None or int(sent_at) <= int(deadline)),
        'body_hash': body_hash,
        'scope_hash': scope['scope_hash'],
        'classification_counts': _counts(scope),
    })
    return status


def _refresh_document_state(db, notice_id):
    rows = db.execute('SELECT state,signed_at FROM notice_recipients WHERE notice_id=?', (notice_id,)).fetchall()
    if not rows:
        return
    states = [r['state'] for r in rows]
    signed_at = [r['signed_at'] for r in rows if r['signed_at'] is not None]
    if all(s == 'signed' for s in states):
        state = 'signed'
    elif 'bounced' in states:
        state = 'bounced'
    elif all(s in ('delivered', 'signed') for s in states):
        state = 'delivered'
    elif any(s in ('delivered', 'signed') for s in states):
        state = 'partially_delivered'
    elif any(s == 'gateway_accepted' for s in states):
        state = 'gateway_accepted'
    elif any(s == 'sent' for s in states):
        state = 'sent'
    else:
        state = 'issued'
    db.execute('UPDATE notice_documents SET state=?,final_signed_at=? WHERE notice_id=?',
               (state, max(signed_at) if signed_at else None, notice_id))


def delivery_action(db, x, event_type):
    notice_id = pick(x, 'notice_id', 'notification_id', 'letter_id', 'notice', 'letter')
    if not notice_id:
        candidate_id = pick(x, 'id')
        if candidate_id and db.execute('SELECT 1 FROM notice_documents WHERE notice_id=?', (candidate_id,)).fetchone():
            notice_id = candidate_id
        else:
            notice_id = candidate_id
    rid = pick(x, 'recipient_id', 'client_id', 'customer_id', 'recipient')
    at = pick(x, 'at', 'minute', event_type + '_at')
    if not notice_id:
        return {'decision': 'blocked', 'reason': 'missing_notice_id'}
    if not db.execute('SELECT 1 FROM notice_documents WHERE notice_id=?', (notice_id,)).fetchone():
        return {'decision': 'blocked', 'reason': 'unknown_notice'}
    if not rid:
        recipients = db.execute('SELECT recipient_id FROM notice_recipients WHERE notice_id=?', (notice_id,)).fetchall()
        if len(recipients) == 1:
            rid = recipients[0]['recipient_id']
        else:
            return {'decision': 'blocked', 'reason': 'missing_recipient_id'}
    if not db.execute('SELECT 1 FROM notice_recipients WHERE notice_id=? AND recipient_id=?',
                      (notice_id, rid)).fetchone():
        return {'decision': 'blocked', 'reason': 'unknown_notice_recipient'}

    event_id = pick(x, 'event_id')
    code = pick(x, 'code', 'gateway_code', 'status_code', 'bounce_code')
    detail = pick(x, 'detail') if isinstance(pick(x, 'detail'), dict) else dict(x)
    receipt = pick(x, 'receipt', 'signature', 'receipt_bytes', 'signed_receipt', 'raw_receipt')
    signer = pick(x, 'signer', 'client_signer')
    mapped_type = {
        'gateway': 'gateway_accepted',
        'gateway_ack': 'gateway_accepted',
        'gateway_acceptance': 'gateway_accepted',
        'gateway_success': 'gateway_accepted',
        'accept': 'gateway_accepted',
        'bounce': 'bounced',
        'record_bounce': 'bounced',
        'retry': 'send_attempt',
        'redeliver': 'send_attempt',
        'retry_delivery': 'send_attempt',
        'deliver': 'delivered',
        'mark_delivered': 'delivered',
        'sign': 'signed',
        'confirm': 'signed',
        'confirm_receipt': 'signed',
        'final_receipt': 'signed',
    }.get(event_type, event_type)
    at = pick(x, 'at', 'minute', f'{mapped_type}_at', f'{mapped_type}_minute',
              f'{event_type}_at', f'{event_type}_minute',
              'bounced_at' if mapped_type == 'bounced' else None,
              'signed_at' if mapped_type == 'signed' else None,
              'delivered_at' if mapped_type == 'delivered' else None)
    event, reused = add_event(db, notice_id, rid, mapped_type, at=at, code=code,
                              detail=detail, receipt_bytes=receipt,
                              event_id=event_id, signer=signer)
    if mapped_type == 'send_attempt' and not reused:
        # Retry may carry an immediate gateway result.
        gateway_code = pick(x, 'gateway_code', 'provider_code')
        if gateway_code is not None or pick(x, 'gateway_accepted', default=False):
            add_event(db, notice_id, rid, 'gateway_accepted',
                      pick(x, 'gateway_at', default=at), code=gateway_code or '200',
                      detail={'gateway_success_code_only': True})
    _refresh_document_state(db, notice_id)
    status = notice_status(db, notice_id)
    status['decision'] = 'reused' if reused else 'recorded'
    status['event_type'] = mapped_type
    return status


def verify_copy(db, x):
    notice_id = pick(x, 'notice_id', 'notification_id', 'letter_id', 'notice', 'letter', 'id')
    rid = pick(x, 'recipient_id', 'client_id', 'customer_id')
    body = pick(x, 'body', 'raw', 'body_raw', 'original_bytes')
    expected_hash = pick(x, 'body_hash', 'expected_body_hash')
    doc = db.execute('SELECT * FROM notice_documents WHERE notice_id=?', (notice_id,)).fetchone() if notice_id else None
    if not doc:
        return {'decision': 'blocked', 'reason': 'unknown_notice'}
    actual_hash = doc['body_hash']
    body_ok = True
    if body is not None:
        body_ok = sha256_hex(as_bytes(body)) == actual_hash
    if expected_hash is not None:
        body_ok = body_ok and expected_hash == actual_hash
    recipient = None
    if rid:
        row = db.execute('SELECT * FROM notice_recipients WHERE notice_id=? AND recipient_id=?',
                         (notice_id, rid)).fetchone()
        recipient = _row_dict(row)
        if not recipient:
            return {'decision': 'blocked', 'reason': 'recipient_not_on_notice'}
    verification_code = sha256_hex(
        f'{notice_id}:{rid or "regulator"}:{actual_hash}'.encode('utf-8')
    )[:24]
    return {
        'decision': 'verified' if body_ok else 'hash_mismatch',
        'authentic': body_ok,
        'verification_code': verification_code,
        'notice_id': notice_id,
        'recipient_id': rid,
        'kind': doc['kind'],
        'body_hash': actual_hash,
        'scope_hash': doc['scope_hash'],
        'recipient_state': recipient['state'] if recipient else None,
        'signed_at': recipient['signed_at'] if recipient else None,
        'receipt_hash': recipient['receipt_hash'] if recipient else None,
        'actually_delivered': bool(recipient and recipient['state'] in ('delivered', 'signed')),
        'final_signed': bool(recipient and recipient['state'] == 'signed'),
    }


def delivery_history(db, incident_id):
    case = scope_mod._incident(db, incident_id)
    if not case:
        return {'decision': 'blocked', 'reason': 'unknown_incident'}
    docs = db.execute('SELECT notice_id FROM notice_documents WHERE incident_id=? ORDER BY COALESCE(first_sent_at,created_at),rowid',
                      (incident_id,)).fetchall()
    notices = [notice_status(db, row['notice_id']) for row in docs]
    first = _first_customer_notice(db, incident_id)
    first_status = notice_status(db, first['notice_id']) if first else None
    first_body = get_notice_bytes(db, first['notice_id']) if first else None
    all_recipient_ids = set()
    delivery_records = 0
    private_signed_count = 0
    for notice in notices:
        for recipient in notice['recipients']:
            all_recipient_ids.add(recipient['recipient_id'])
            delivery_records += 1
            if notice['kind'] == 'customer_private' and recipient['state'] == 'signed':
                private_signed_count += 1
    deadline_met = bool(first and first['first_sent_at'] is not None and
                        (case['deadline_at'] is None or first['first_sent_at'] <= case['deadline_at']))
    return {
        'decision': 'history',
        'incident_id': incident_id,
        'first_notice_id': first['notice_id'] if first else None,
        'first_kind': first['kind'] if first else None,
        'first_body_hash': first['body_hash'] if first else None,
        'first_body_raw': first_body,
        'first_body': first_body,
        'first_sent_at': first['first_sent_at'] if first else None,
        'first_signed_minute': first_status['signed_minute'] if first_status else None,
        'first_notice_recipient_count': first_status['recipient_count'] if first_status else 0,
        'first_external_recipient_count': first_status['external_recipient_count'] if first_status else 0,
        'first_signed_count': first_status['signed_count'] if first_status else 0,
        'first_notice_deadline_met': deadline_met,
        'general_notification_satisfied': deadline_met and first['kind'] == 'service_advisory' if first else False,
        'per_customer_signed_count': private_signed_count,
        'execution_route': first['execution_mode'] if first else None,
        'notice_count': len(notices),
        'total_delivery_records': delivery_records,
        'unique_recipient_ids': sorted(all_recipient_ids),
        'unique_recipient_count': len(all_recipient_ids),
        'notices': notices,
    }


def actual_recipients(db, notice_id=None, incident_id=None):
    if notice_id:
        status = notice_status(db, notice_id)
        if not status:
            return None
        return status['recipients']
    if incident_id:
        history = delivery_history(db, incident_id)
        if history.get('decision') == 'blocked':
            return []
        return [
            {'notice_id': n['notice_id'], 'kind': n['kind'],
             'body_hash': n['body_hash'], 'recipients': n['recipients']}
            for n in history['notices']
        ]
    return []


def who_received_which_version(db, incident_id):
    return delivery_history(db, incident_id)


def recipient_ledger(db, recipient_id):
    rows = db.execute("""
        SELECT d.notice_id FROM notice_documents d
        JOIN notice_recipients r ON r.notice_id=d.notice_id
        WHERE r.recipient_id=?
        ORDER BY COALESCE(d.first_sent_at,d.created_at),d.rowid
    """, (recipient_id,)).fetchall()
    items = []
    for row in rows:
        status = notice_status(db, row['notice_id'])
        raw = get_notice_bytes(db, row['notice_id'])
        status['body_raw'] = raw
        status['raw_bytes'] = raw
        status['original_bytes'] = raw
        # A recipient may verify only their own delivery row/events.  Aggregate
        # counts contain no identities, but event recipient IDs must be filtered.
        own = [r for r in status['recipients'] if r['recipient_id'] == recipient_id]
        status['recipients'] = own
        status['recipient_count'] = len(own)
        status['external_recipient_count'] = len(own)
        status['events'] = [
            e for e in status.get('events', [])
            if e.get('recipient_id') in (recipient_id, None)
        ]
        for event in status['events']:
            # Event metadata can retain operator payloads in the regulator copy;
            # customer ledger gets only timeline/type/time/code/hash facts.
            event.pop('detail_json', None)
        items.append(status)
    return {'decision': 'recipient_ledger', 'recipient_id': recipient_id, 'notices': items}


@audit_run('notice_delivery')
def run(db, x):
    with transaction(db):
        op = (x.get('op') or 'issue').replace('-', '_')
        if op in ('send', 'issue', 'issue_notice', 'send_notice', 'send_private',
                  'send_advisory', 'file_regulator', 'regulator_supplement',
                  'regulator_report', 'correct', 'correction', 'correct_notice',
                  'send_correction', 'record_sent_notice', 'ingest_external_notice'):
            return issue_notice(db, x, op=op)
        if op in ('gateway_ack', 'gateway_success', 'gateway_acceptance', 'accept_gateway'):
            return delivery_action(db, x, 'gateway_acceptance')
        if op in ('bounce', 'record_bounce'):
            return delivery_action(db, x, 'bounce')
        if op in ('retry', 'redeliver', 'retry_delivery'):
            return delivery_action(db, x, 'retry')
        if op in ('deliver', 'mark_delivered', 'delivery_confirmation'):
            return delivery_action(db, x, 'deliver')
        if op in ('sign', 'confirm', 'confirm_receipt', 'final_receipt', 'record_signature'):
            return delivery_action(db, x, 'sign')
        if op in ('status', 'get_notice', 'notice_status'):
            nid = pick(x, 'notice_id', 'notification_id', 'letter_id', 'notice', 'letter', 'id')
            result = notice_status(db, nid)
            return result or {'decision': 'blocked', 'reason': 'unknown_notice'}
        if op in ('bytes', 'get_bytes', 'original_bytes'):
            nid = pick(x, 'notice_id', 'notification_id', 'letter_id', 'notice', 'letter', 'id')
            data = get_notice_bytes(db, nid)
            return {'decision': 'bytes', 'notice_id': nid, 'body_raw': data,
                    'body_hash': sha256_hex(data or b'')}
        if op in ('verify', 'verify_copy', 'verify_receipt'):
            return verify_copy(db, x)
        if op in ('history', 'delivery_history', 'ledger'):
            return delivery_history(db, pick(x, 'incident_id', 'incident', 'case_id', 'id'))
        if op in ('recipient_ledger', 'customer_ledger'):
            return recipient_ledger(db, pick(x, 'recipient_id', 'client_id', 'customer_id'))
        if op in ('delete', 'remove', 'erase', 'delete_notice', 'withdraw'):
            return {'decision': 'blocked',
                    'reason': 'sent_notice_cannot_be_deleted_issue_correction'}
        raise ValueError(x['op'])


class DeliveryLedger:
    def __init__(self, db):
        self.db = db

    def run(self, payload):
        return run(self.db, payload)

    def issue(self, **payload):
        payload['op'] = 'issue'
        return run(self.db, payload)

    def status(self, notice_id):
        return notice_status(self.db, notice_id)

    def history(self, incident_id):
        return delivery_history(self.db, incident_id)

    def bytes(self, notice_id):
        return get_notice_bytes(self.db, notice_id)

    def verify(self, **payload):
        return verify_copy(self.db, payload)

    def send(self, **payload):
        payload['op'] = 'send'
        return run(self.db, payload)

    def bounce(self, **payload):
        payload['op'] = 'bounce'
        return run(self.db, payload)

    def retry(self, **payload):
        payload['op'] = 'redeliver'
        return run(self.db, payload)

    def sign(self, **payload):
        payload['op'] = 'sign'
        return run(self.db, payload)

    def correct(self, **payload):
        payload['op'] = 'correct'
        return run(self.db, payload)

    def regulator(self, **payload):
        payload['op'] = 'file_regulator'
        return run(self.db, payload)


NoticeDelivery = DeliveryLedger
NoticeLedger = DeliveryLedger
NoticeDeliveryLedger = DeliveryLedger
DeliveryService = DeliveryLedger
NoticeService = DeliveryLedger
Ledger = DeliveryLedger


def send_notice(db, payload=None, **kwargs):
    data = dict(payload or {})
    data.update(kwargs)
    data.setdefault('op', 'send')
    return run(db, data)


def send_service_advisory(db, payload=None, **kwargs):
    data = dict(payload or {})
    data.update(kwargs)
    data['op'] = 'send_advisory'
    return run(db, data)


def send_private_notice(db, payload=None, **kwargs):
    data = dict(payload or {})
    data.update(kwargs)
    data['op'] = 'send_private'
    return run(db, data)


def record_bounce(db, payload=None, **kwargs):
    data = dict(payload or {})
    data.update(kwargs)
    data['op'] = 'bounce'
    return run(db, data)


def retry_delivery(db, payload=None, **kwargs):
    data = dict(payload or {})
    data.update(kwargs)
    data['op'] = 'redeliver'
    return run(db, data)


def sign_notice(db, payload=None, **kwargs):
    data = dict(payload or {})
    data.update(kwargs)
    data['op'] = 'sign'
    return run(db, data)


def file_regulator_report(db, payload=None, **kwargs):
    data = dict(payload or {})
    data.update(kwargs)
    data['op'] = 'file_regulator'
    return run(db, data)


def send_correction(db, payload=None, **kwargs):
    data = dict(payload or {})
    data.update(kwargs)
    data['op'] = 'correct'
    return run(db, data)


def verify_delivery(db, payload=None, **kwargs):
    data = dict(payload or {})
    data.update(kwargs)
    data['op'] = 'verify'
    return run(db, data)


def delete_notice(db, payload=None, **kwargs):
    data = dict(payload or {})
    data.update(kwargs)
    data['op'] = 'delete'
    return run(db, data)
