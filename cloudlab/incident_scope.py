"""Evidence-bound scope for upgrade-caused tenant diagnostic disclosure.

The scope is deliberately built from physical responses and terminal client
receipts, not from node health or a proxy page's earliest customer label.
"""
import base64
import hashlib
import json

from .store import audit_run, transaction


def pick(x, *keys, default=None):
    if not isinstance(x, dict):
        return default
    for key in keys:
        value = x.get(key)
        if value is not None:
            return value
    return default


def as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [v.strip() for v in value.split(',') if v.strip()]
    return [value]


def as_bytes(value):
    if value is None:
        return b''
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode('utf-8')
    return canonical_json(value).encode('utf-8')


def canonical_json(value):
    def _default(obj):
        if isinstance(obj, (bytes, bytearray)):
            return {'__bytes_b64__': base64.b64encode(bytes(obj)).decode('ascii')}
        return str(obj)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), default=_default)


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def token_digest(token=None, token_hash=None):
    if token_hash:
        return token_hash
    if token is None:
        return None
    return sha256_hex(str(token).encode('utf-8'))


def _json_loads(value, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _row_dict(row):
    return dict(row) if row is not None else None


def _incident(db, incident_id):
    return _row_dict(db.execute('SELECT * FROM incident_cases WHERE id=?', (incident_id,)).fetchone())


def _normalize_mode(mode):
    if not mode:
        return None
    text = str(mode).strip().lower()
    aliases = {
        'precise': 'escrow_precise',
        'private': 'escrow_precise',
        'private_only': 'escrow_precise',
        'escrow': 'escrow_precise',
        'escrow_precise': 'escrow_precise',
        'escrow_private': 'escrow_precise',
        'advisory': 'advisory_first',
        'general_notice': 'advisory_first',
        'service_advisory': 'advisory_first',
        'advisory_first': 'advisory_first',
        'advisory_then_private': 'advisory_first',
        'generic_first': 'advisory_first',
    }
    return aliases.get(text, text)


def _approved_modes(x):
    raw = pick(x, 'approved_modes', 'approved_executions', 'execution_modes',
               'allowed_routes', 'preapproved_modes', 'approved_routes')
    if raw is None and pick(x, 'preapproved', 'both_routes_preapproved', default=False):
        raw = ['escrow_precise', 'advisory_first']
    if raw in ('both', '*', True):
        raw = ['escrow_precise', 'advisory_first']
    modes = [_normalize_mode(m) for m in as_list(raw)]
    return sorted(set(m for m in modes if m))


def open_incident(db, x):
    wave_id_for_default = pick(x, 'wave_id', 'wave')
    incident_id = pick(x, 'incident_id', 'id', 'case_id')
    if not incident_id and wave_id_for_default:
        incident_id = f'incident-{wave_id_for_default}'
    if not incident_id:
        return {'decision': 'blocked', 'reason': 'missing_incident_id'}
    old = _incident(db, incident_id)
    if old:
        return {'decision': 'reused', 'incident_id': incident_id,
                'legal_clock_started_at': old['legal_clock_started_at'],
                'first_notice_deadline_at': old['deadline_at'],
                'status': old['status']}

    evidence_at = pick(x, 'evidence_at', 'evidence_minute', 'credible_evidence_at',
                       'credible_evidence_minute', 'secured_at', 'secured_minute',
                       'security_officer_evidence_at', 'clock_started_at',
                       'clock_started_minute', 'legal_clock_started_at',
                       'legal_clock_start_minute', 'legal_clock_start', 'clock_start',
                       'obtained_at', 'obtained_minute', 'evidence_obtained_at',
                       'acquired_at', 'at', 'minute')
    if evidence_at is None:
        return {'decision': 'blocked', 'reason': 'missing_credible_evidence_time'}
    deadline_at = pick(x, 'deadline_at', 'deadline_minute', 'first_notice_deadline_at',
                       'first_notice_deadline_minute', 'legal_deadline_at',
                       'contract_deadline_at', 'contract_deadline_minute',
                       'contract_deadline', 'deadline')
    deadline_minutes = pick(x, 'deadline_minutes', 'contract_minutes',
                            'first_notice_minutes')
    if deadline_at is None and deadline_minutes is not None:
        deadline_at = int(evidence_at) + int(deadline_minutes)

    wave_id = pick(x, 'wave_id', 'wave')
    node_id = pick(x, 'node_id', 'node')
    fault_version = pick(x, 'fault_version', 'faulty_version', 'bad_version',
                         'affected_version', 'version', 'target_version')
    if wave_id:
        wave = db.execute('SELECT * FROM waves WHERE id=?', (wave_id,)).fetchone()
        if wave and not fault_version:
            fault_version = wave['target']

    known_clients = as_list(pick(x, 'known_clients', 'subscribers', 'subscriber_ids',
                                 'customers', 'customer_ids', 'clients', 'client_ids',
                                 'known_customer_ids', 'audience'))
    modes = _approved_modes(x)
    authorizer = pick(x, 'authorizer', 'authorized_by', 'legal_authorizer')
    contract_owner = pick(x, 'contract_owner', 'contract_approver', 'owner')
    if contract_owner and not modes and pick(x, 'contract_owner_preapproves_both', default=True):
        # The fixed artifact package is approved for either execution path.
        # Explicit approved_modes=[] can still intentionally leave it closed.
        if 'approved_modes' not in x and 'approved_executions' not in x:
            modes = ['escrow_precise', 'advisory_first']

    db.execute(
        'INSERT INTO incident_cases VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
        (incident_id, fault_version, wave_id, node_id,
         pick(x, 'node_generation', 'generation'), int(evidence_at), int(evidence_at),
         deadline_at, pick(x, 'earliest_fault_at'),
         pick(x, 'security_officer', 'officer', 'evidence_officer'),
         authorizer, contract_owner, canonical_json(known_clients),
         canonical_json(modes), 'open', pick(x, 'created_at', default=evidence_at),
         canonical_json(x)))
    return {'decision': 'opened', 'incident_id': incident_id,
            'fault_version': fault_version,
            'evidence_at': int(evidence_at),
            'legal_clock_started_at': int(evidence_at),
            'legal_clock_start': int(evidence_at),
            'clock_started_at': int(evidence_at),
            'deadline_at': deadline_at,
            'first_notice_deadline_at': deadline_at,
            'first_notice_deadline': deadline_at,
            'approved_modes': modes, 'known_clients': known_clients}


def approve_route(db, x):
    incident_id = pick(x, 'incident_id', 'incident', 'case_id', 'id')
    row = _incident(db, incident_id) if incident_id else None
    if not row:
        return {'decision': 'blocked', 'reason': 'unknown_incident'}
    mode = _normalize_mode(pick(x, 'mode', 'route', 'execution_mode'))
    if not mode:
        return {'decision': 'blocked', 'reason': 'missing_execution_mode'}
    approved_by = pick(x, 'approved_by', 'contract_owner', 'authorizer')
    if not approved_by:
        return {'decision': 'blocked', 'reason': 'missing_contract_owner_approval'}
    approval_id = pick(x, 'approval_id', 'id') or f'approval:{incident_id}:{mode}'
    at = pick(x, 'approved_at', 'at', 'minute')
    old = db.execute('SELECT * FROM incident_approvals WHERE approval_id=?', (approval_id,)).fetchone()
    if old:
        return {'decision': 'reused', 'approval_id': approval_id, 'mode': old['mode']}
    db.execute('INSERT INTO incident_approvals VALUES(?,?,?,?,?,?)',
               (approval_id, incident_id, mode, approved_by, at, canonical_json(x)))
    modes = sorted(set(_json_loads(row['approved_modes_json'], []) + [mode]))
    db.execute('UPDATE incident_cases SET approved_modes_json=?,contract_owner=COALESCE(?,contract_owner) WHERE id=?',
               (canonical_json(modes), approved_by, incident_id))
    return {'decision': 'approved', 'approval_id': approval_id, 'mode': mode,
            'approved_at': at, 'approved_modes': modes}


def add_fault_sample(db, x):
    incident_id = pick(x, 'incident_id', 'incident', 'case_id', 'id')
    row = _incident(db, incident_id) if incident_id else None
    if not row:
        return {'decision': 'blocked', 'reason': 'unknown_incident'}
    sample_id = pick(x, 'sample_id') or f"sample:{incident_id}:{pick(x,'kind','sample')}:{pick(x,'observed_at','at','minute')}"
    old = db.execute('SELECT 1 FROM incident_fault_samples WHERE sample_id=?', (sample_id,)).fetchone()
    if old:
        return {'decision': 'reused', 'sample_id': sample_id,
                'legal_clock_started_at': row['legal_clock_started_at']}
    observed_at = pick(x, 'observed_at', 'sample_at', 'fault_at', 'at', 'minute')
    recorded_at = pick(x, 'recorded_at', 'received_at', 'ingested_at', 'secured_at',
                       default=observed_at)
    healthy = pick(x, 'healthy', 'health', default=None)
    response_count = pick(x, 'response_count', 'egress_response_count')
    data_returned = pick(x, 'data_returned', 'returned_data', 'has_data')
    if data_returned is None and response_count == 0:
        data_returned = False
    db.execute('INSERT INTO incident_fault_samples VALUES(?,?,?,?,?,?,?,?,?)',
               (sample_id, incident_id, pick(x, 'kind', default='fault_sample'),
                observed_at, recorded_at,
                None if healthy is None else int(bool(healthy)),
                None if data_returned is None else int(bool(data_returned)),
                int(bool(pick(x, 'trusted', 'credible', default=False))),
                canonical_json(x)))
    earliest = row['earliest_fault_at']
    if observed_at is not None:
        earliest = observed_at if earliest is None else min(earliest, int(observed_at))
        db.execute('UPDATE incident_cases SET earliest_fault_at=? WHERE id=?',
                   (earliest, incident_id))
    # Crucially, legal_clock_started_at is never rewritten here.
    return {'decision': 'recorded', 'sample_id': sample_id,
            'earliest_fault_at': earliest,
            'legal_clock_started_at': row['legal_clock_started_at'],
            'clock_moved': False,
            'first_notice_deadline_at': row['deadline_at']}


def record_request(db, x):
    incident_id = pick(x, 'incident_id', 'incident', 'case_id', 'id')
    if not _incident(db, incident_id):
        return {'decision': 'blocked', 'reason': 'unknown_incident'}
    request_id = pick(x, 'request_id', 'customer_request_id', 'request')
    if not request_id:
        return {'decision': 'blocked', 'reason': 'missing_request_id'}
    old = db.execute('SELECT 1 FROM incident_requests WHERE request_id=?', (request_id,)).fetchone()
    if old:
        return {'decision': 'reused', 'request_id': request_id}
    at = pick(x, 'at', 'request_at', 'minute')
    db.execute('INSERT INTO incident_requests VALUES(?,?,?,?,?)',
               (request_id, incident_id, at,
                pick(x, 'client_hint', 'claimed_client', 'customer_hint'), canonical_json(x)))
    return {'decision': 'recorded', 'request_id': request_id}


def record_forward(db, x):
    incident_id = pick(x, 'incident_id', 'incident', 'case_id', 'id')
    if not _incident(db, incident_id):
        return {'decision': 'blocked', 'reason': 'unknown_incident'}
    request_id = pick(x, 'request_id', 'customer_request_id', 'request')
    trace_id = pick(x, 'trace_id', 'physical_trace_id', 'response_trace_id')
    at = pick(x, 'at', 'forwarded_at', 'minute')
    attempt_no = pick(x, 'attempt', 'attempt_no', 'retry_no', default=1)
    attempt_id = pick(x, 'attempt_id', 'forward_id') or \
        f'forward:{request_id or "unknown"}:{trace_id or "notrace"}:{attempt_no}:{at}'
    old = db.execute('SELECT * FROM incident_forward_attempts WHERE attempt_id=?', (attempt_id,)).fetchone()
    if old:
        return {'decision': 'reused', 'attempt_id': attempt_id, 'trace_id': old['trace_id']}
    proxy = x.get('proxy') if isinstance(x.get('proxy'), dict) else {}
    db.execute('INSERT INTO incident_forward_attempts VALUES(?,?,?,?,?,?,?,?,?,?)',
               (attempt_id, incident_id, request_id,
                pick(x, 'proxy_id', 'proxy') or pick(proxy, 'id', 'proxy_id'),
                pick(x, 'nat_address', 'proxy_address', 'address') or pick(proxy, 'nat_address', 'address'),
                trace_id, attempt_no, at, pick(x, 'outcome', default='forwarded'),
                canonical_json(x)))
    return {'decision': 'recorded', 'attempt_id': attempt_id,
            'trace_id': trace_id, 'counted_as': 'forward_attempt_not_physical_response'}


def record_response(db, x):
    incident_id = pick(x, 'incident_id', 'incident', 'case_id', 'id')
    case = _incident(db, incident_id) if incident_id else None
    if not case:
        return {'decision': 'blocked', 'reason': 'unknown_incident'}
    gateway = x.get('gateway_response') if isinstance(x.get('gateway_response'), dict) else {}
    trace_id = pick(x, 'trace_id', 'physical_trace_id', 'response_trace_id',
                    'tracking_number', 'trace_no') or pick(gateway, 'trace_id', 'physical_trace_id')
    if not trace_id:
        return {'decision': 'blocked', 'reason': 'missing_physical_trace_id'}

    raw = pick(x, 'raw', 'raw_bytes', 'original_bytes', 'response_bytes', 'raw_response')
    if raw is None and gateway:
        raw = pick(gateway, 'raw', 'raw_bytes', 'body', 'original_bytes')
    raw_bytes = as_bytes(raw)
    raw_hash = sha256_hex(raw_bytes) if raw_bytes else pick(x, 'raw_hash', 'body_hash')

    old = _row_dict(db.execute('SELECT * FROM incident_responses WHERE trace_id=?', (trace_id,)).fetchone())
    if old:
        if old['incident_id'] != incident_id:
            return {'decision': 'blocked', 'reason': 'trace_incident_conflict'}
        if raw_hash and old['raw_hash'] and raw_hash != old['raw_hash']:
            return {'decision': 'blocked', 'reason': 'trace_original_bytes_conflict'}
        # NAT candidate facts can arrive separately; merge rather than invent
        # a second physical response.
        new_candidates = as_list(pick(x, 'candidate_clients', 'candidate_customers',
                                      'candidates', 'nat_clients'))
        if new_candidates:
            merged = sorted(set(_json_loads(old['candidate_clients_json'], []) + new_candidates))
            db.execute('UPDATE incident_responses SET candidate_clients_json=? WHERE trace_id=?',
                       (canonical_json(merged), trace_id))
        new_egress = pick(x, 'independent_egress_count', 'egress_count', 'outlet_count')
        if old['independent_egress_count'] is None and new_egress is not None:
            db.execute('UPDATE incident_responses SET independent_egress_count=? WHERE trace_id=?',
                       (int(new_egress), trace_id))
        if not old['page_hint']:
            page_hint = pick(x, 'page_hint', 'page_client', 'proxy_page_customer',
                             'earliest_marked_client', 'suspect_client')
            if page_hint:
                db.execute('UPDATE incident_responses SET page_hint=? WHERE trace_id=?',
                           (page_hint, trace_id))
        return {'decision': 'reused', 'trace_id': trace_id,
                'counted_once': True, 'deduplicated_response_count': 1,
                'reason': 'physical_trace_id_dedup'}

    proxy = x.get('proxy') if isinstance(x.get('proxy'), dict) else {}
    candidates = as_list(pick(x, 'candidate_clients', 'candidate_customers',
                              'candidates', 'nat_clients', 'possible_customers'))
    diagnostic_fields = as_list(pick(x, 'diagnostic_fields', 'foreign_fields',
                                     'leaked_fields', default=[]))
    leak = pick(x, 'foreign_tenant_leak', 'contains_other_tenant',
                'cross_tenant_leak', 'leaked_other_tenant_data',
                'other_tenant_data', 'cross_tenant_diagnostic_data',
                'has_other_tenant_diagnostics', default=None)
    if leak is None:
        leak = bool(diagnostic_fields or pick(x, 'other_tenant_diagnostics', default=False))
    returned_data = pick(x, 'returned_data', 'data_returned', 'has_data', default=None)
    if returned_data is None:
        returned_data = bool(raw_bytes or diagnostic_fields or leak)
    egress_count = pick(x, 'independent_egress_count', 'egress_count', 'outlet_count')
    at = pick(x, 'at', 'response_at', 'minute', 'observed_at')
    request_id = pick(x, 'request_id', 'customer_request_id', 'request')
    proxy_id = pick(x, 'proxy_id', 'proxy') or pick(proxy, 'id', 'proxy_id')
    nat_address = pick(x, 'nat_address', 'proxy_address', 'shared_address', 'address') or \
        pick(proxy, 'nat_address', 'address')

    db.execute('INSERT INTO incident_responses VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
               (trace_id, incident_id, request_id, proxy_id, nat_address, at,
                pick(x, 'fault_version', 'version') or case['fault_version'],
                int(bool(returned_data)), int(bool(leak)),
                canonical_json(diagnostic_fields), canonical_json(candidates),
                pick(x, 'page_hint', 'page_client', 'proxy_page_customer',
                     'earliest_marked_client', 'suspect_client'),
                None if egress_count is None else int(egress_count),
                raw_bytes or None, raw_hash, canonical_json(x)))
    if egress_count is not None:
        obs_id = f'egress:{trace_id}:declared'
        db.execute('INSERT OR IGNORE INTO incident_egress_observations VALUES(?,?,?,?,?,?,?)',
                   (obs_id, incident_id, trace_id,
                    pick(x, 'egress_observer', 'observer', default='independent_egress_meter'),
                    int(egress_count), at, canonical_json({'declared_with_response': True})))
    return {'decision': 'recorded', 'trace_id': trace_id,
            'counted_once': True, 'physical_response_count': 1,
            'raw_hash': raw_hash, 'foreign_tenant_leak': bool(leak)}


def record_egress(db, x):
    incident_id = pick(x, 'incident_id', 'incident', 'case_id', 'id')
    if not _incident(db, incident_id):
        return {'decision': 'blocked', 'reason': 'unknown_incident'}
    trace_id = pick(x, 'trace_id', 'physical_trace_id')
    count = pick(x, 'count', 'egress_count', 'independent_count')
    if not trace_id or count is None:
        return {'decision': 'blocked', 'reason': 'missing_trace_or_count'}
    observation_id = pick(x, 'observation_id', 'egress_id', 'id') or \
        f"egress:{trace_id}:{pick(x,'observer','meter',default='meter')}"
    old = db.execute('SELECT * FROM incident_egress_observations WHERE observation_id=?',
                     (observation_id,)).fetchone()
    if old:
        if old['count'] != int(count):
            return {'decision': 'blocked', 'reason': 'egress_count_conflict'}
        return {'decision': 'reused', 'observation_id': observation_id, 'count': old['count']}
    at = pick(x, 'at', 'observed_at', 'minute')
    db.execute('INSERT INTO incident_egress_observations VALUES(?,?,?,?,?,?,?)',
               (observation_id, incident_id, trace_id,
                pick(x, 'observer', 'source', default='independent_egress_meter'),
                int(count), at, canonical_json(x)))
    response = db.execute('SELECT independent_egress_count FROM incident_responses WHERE trace_id=?',
                          (trace_id,)).fetchone()
    if response and response['independent_egress_count'] is None:
        db.execute('UPDATE incident_responses SET independent_egress_count=? WHERE trace_id=?',
                   (int(count), trace_id))
    return {'decision': 'recorded', 'observation_id': observation_id,
            'trace_id': trace_id, 'independent_egress_count': int(count)}


def record_receipt(db, x):
    incident_id = pick(x, 'incident_id', 'incident', 'case_id', 'id')
    if not _incident(db, incident_id):
        return {'decision': 'blocked', 'reason': 'unknown_incident'}
    trace_id = pick(x, 'trace_id', 'physical_trace_id')
    if not trace_id:
        return {'decision': 'blocked', 'reason': 'missing_trace_id'}
    token = pick(x, 'token', 'receipt_token', 'sign_token', 'ack_token', 'token_value')
    digest = token_digest(token, pick(x, 'token_hash'))
    receipt_id = pick(x, 'receipt_id', 'ack_id', 'id') or f'receipt:{trace_id}:{(digest or "none")[:16]}'

    signature = pick(x, 'signature', 'signature_bytes', 'receipt_bytes',
                     'raw_receipt', 'signed_receipt')
    signature_bytes = as_bytes(signature)
    receipt_hash = pick(x, 'receipt_hash', 'signature_hash') or \
        (sha256_hex(signature_bytes) if signature_bytes else None)
    signed_at = pick(x, 'signed_at', 'received_at', 'ack_at', 'at', 'minute')
    terminal = pick(x, 'terminal', 'terminal_confirmation', 'client_confirmed',
                    'client_receipt', 'confirmed', 'acknowledged',
                    'terminal_ack', default=None)
    if terminal is None:
        terminal = bool(signature_bytes or signed_at is not None and pick(x, 'signer'))
    terminal = bool(terminal)

    old = _row_dict(db.execute('SELECT * FROM incident_receipts WHERE receipt_id=?',
                               (receipt_id,)).fetchone())
    if old:
        return {'decision': 'reused', 'receipt_id': receipt_id,
                'terminal': bool(old['terminal']), 'subject_resolved': _binding_for_token(db, old['token_hash']) is not None}
    if digest:
        old_token = db.execute('SELECT * FROM incident_receipts WHERE trace_id=? AND token_hash=?',
                               (trace_id, digest)).fetchone()
        if old_token:
            return {'decision': 'reused', 'receipt_id': old_token['receipt_id'],
                    'terminal': bool(old_token['terminal']), 'deduped': True}
    db.execute('INSERT INTO incident_receipts VALUES(?,?,?,?,?,?,?,?,?,?,?)',
               (receipt_id, incident_id, trace_id, digest,
                pick(x, 'signer', 'client_signer'), signed_at, int(terminal),
                str(pick(x, 'gateway_code', 'code')) if pick(x, 'gateway_code', 'code') is not None else None,
                signature_bytes or None, receipt_hash, canonical_json(x)))
    binding = _binding_for_token(db, digest)
    return {'decision': 'recorded', 'receipt_id': receipt_id,
            'terminal': terminal, 'token_hash': digest,
            'subject_resolved': binding is not None,
            'client_id': binding['client_id'] if binding else None,
            'warning': None if terminal else 'gateway_or_incomplete_ack_is_not_client_receipt'}


def _binding_for_token(db, digest):
    if not digest:
        return None
    return _row_dict(db.execute(
        "SELECT * FROM incident_token_bindings WHERE token_hash=? AND state='active' ORDER BY unsealed_at DESC LIMIT 1",
        (digest,)).fetchone())


def unseal_token(db, x):
    incident_id = pick(x, 'incident_id', 'incident', 'case_id', 'id')
    if not _incident(db, incident_id):
        return {'decision': 'blocked', 'reason': 'unknown_incident'}
    mappings = x.get('mappings') if isinstance(x.get('mappings'), list) else None
    if mappings is None:
        mappings = [x]
    results = []
    for mapping in mappings:
        token = pick(mapping, 'token', 'receipt_token', 'sign_token')
        digest = token_digest(token, pick(mapping, 'token_hash'))
        client_id = pick(mapping, 'client_id', 'customer_id', 'client', 'customer')
        if not digest or not client_id:
            results.append({'decision': 'blocked', 'reason': 'missing_token_or_client'})
            continue
        custodian = pick(mapping, 'custodian', 'escrow_agent', 'escrow_officer',
                         'trustee', 'unsealed_by') or \
            pick(x, 'custodian', 'escrow_agent', 'escrow_officer', 'trustee', 'unsealed_by')
        authorizer = pick(mapping, 'authorizer', 'authorization', 'court_order') or \
            pick(x, 'authorizer', 'authorization', 'court_order')
        if not custodian and not authorizer and pick(x, 'require_custodian', default=True):
            results.append({'decision': 'blocked', 'reason': 'missing_custodian_authorization',
                            'token_hash': digest})
            continue
        at = pick(mapping, 'at', 'unsealed_at', 'minute') or pick(x, 'at', 'unsealed_at')
        reverse = bool(pick(mapping, 'reverse', 'reversed', 'replace_existing', default=False) or
                       x.get('op') in ('reverse_token', 'reverse_token_binding', 'token_reversal', 'reverse_receipt_token'))
        active = _binding_for_token(db, digest)
        if active and active['client_id'] == client_id:
            results.append({'decision': 'reused', 'binding_id': active['binding_id'],
                            'token_hash': digest, 'client_id': client_id})
            continue
        replaces = None
        if active:
            if not reverse:
                results.append({'decision': 'blocked', 'reason': 'token_binding_conflict',
                                'token_hash': digest, 'active_client_id': active['client_id']})
                continue
            replaces = active['binding_id']
            db.execute("UPDATE incident_token_bindings SET state='reversed',reversed_at=? WHERE binding_id=?",
                       (at, active['binding_id']))
        binding_id = pick(mapping, 'binding_id') or \
            f"binding:{digest[:16]}:{client_id}:{at if at is not None else 'na'}"
        db.execute('INSERT INTO incident_token_bindings VALUES(?,?,?,?,?,?,?,?,?,?)',
                   (binding_id, digest, client_id, 'active', custodian,
                    str(authorizer) if authorizer is not None else None, at, None,
                    replaces, canonical_json(mapping)))
        traces = [r['trace_id'] for r in db.execute(
            'SELECT trace_id FROM incident_receipts WHERE token_hash=? AND terminal=1', (digest,))]
        results.append({'decision': 'unsealed', 'binding_id': binding_id,
                        'token_hash': digest, 'client_id': client_id,
                        'terminal_receipt_traces': traces,
                        'reversed_binding_id': replaces})
    if len(results) == 1:
        return results[0]
    return {'decision': 'unsealed_batch', 'results': results}


def resolve_token(db, token=None, token_hash=None, **_aliases):
    digest = token_digest(token, token_hash)
    binding = _binding_for_token(db, digest)
    if not binding:
        return None
    return {'token_hash': digest, 'client_id': binding['client_id'],
            'binding_id': binding['binding_id'], 'state': binding['state'],
            'custodian': binding['custodian'], 'unsealed_at': binding['unsealed_at']}


# Readable aliases for callers and tests that prefer function calls over run().
def reverse_token_binding(db, x):
    payload = dict(x)
    payload['op'] = 'reverse_token_binding'
    payload['reverse'] = True
    return unseal_token(db, payload)


reverse_receipt_token = reverse_token_binding


def _add_client(clients, client_id, classification, trace_id, reason, at=None, **extra):
    if not client_id:
        return
    item = clients.setdefault(client_id, {
        'client_id': client_id,
        'classification': classification,
        'confirmed_trace_ids': [],
        'possible_trace_ids': [],
        'excluded_trace_ids': [],
        'trace_ids': [],
        'reasons': [],
        'signed_at': None,
    })
    rank = {'excluded': 0, 'unknown': 1, 'possible': 2, 'confirmed': 3}
    if rank[classification] > rank[item['classification']]:
        item['classification'] = classification
    if trace_id and trace_id not in item['trace_ids']:
        item['trace_ids'].append(trace_id)
    bucket = f'{classification}_trace_ids'
    if trace_id and bucket in item and trace_id not in item[bucket]:
        item[bucket].append(trace_id)
    reason_text = f'{trace_id}:{reason}' if trace_id else reason
    if reason_text not in item['reasons']:
        item['reasons'].append(reason_text)
    if at is not None and classification == 'confirmed':
        item['signed_at'] = at if item['signed_at'] is None else min(item['signed_at'], at)
    for key, value in extra.items():
        if value is not None and key not in item:
            item[key] = value


def build_scope(db, incident_id, at=None, known_clients=None):
    case = _incident(db, incident_id)
    if not case:
        return {'decision': 'blocked', 'reason': 'unknown_incident'}
    known = as_list(known_clients) or _json_loads(case['known_clients_json'], [])
    clients = {}
    response_rows = db.execute('SELECT * FROM incident_responses WHERE incident_id=? ORDER BY at,rowid',
                               (incident_id,)).fetchall()
    leaking_count = 0
    unresolved_responses = []

    for row in response_rows:
        response = _row_dict(row)
        trace_id = response['trace_id']
        candidates = _json_loads(response['candidate_clients_json'], [])
        if response['page_hint'] and response['page_hint'] not in candidates:
            # A proxy page label is evidence of a hint, never a confirmation.
            candidates.append(response['page_hint'])
        receipts = db.execute("""
            SELECT r.*, b.client_id AS resolved_client_id
            FROM incident_receipts r
            LEFT JOIN incident_token_bindings b
              ON b.token_hash=r.token_hash AND b.state='active'
            WHERE r.trace_id=?
            ORDER BY r.signed_at
        """, (trace_id,)).fetchall()
        confirmed = []
        for receipt in receipts:
            receipt = _row_dict(receipt)
            if receipt['terminal'] and receipt['resolved_client_id']:
                cid = receipt['resolved_client_id']
                confirmed.append(cid)
                _add_client(clients, cid, 'confirmed', trace_id,
                            'terminal_client_receipt_and_custodian_token_reversal',
                            at=receipt['signed_at'], receipt_hash=receipt['receipt_hash'])
        unique_one = response['independent_egress_count'] == 1
        leaking = bool(response['foreign_tenant_leak']) and bool(response['returned_data'])
        if leaking:
            leaking_count += 1
        if not leaking:
            for cid in candidates:
                _add_client(clients, cid, 'excluded', trace_id,
                            'no_foreign_tenant_data_returned')
            if not candidates and not confirmed:
                unresolved_responses.append({'trace_id': trace_id, 'status': 'no_data_or_leak_evidence'})
            continue

        if confirmed:
            confirmed_set = set(confirmed)
            for cid in candidates:
                if cid in confirmed_set:
                    continue
                if unique_one:
                    _add_client(clients, cid, 'excluded', trace_id,
                                'single_independent_egress_response_and_other_client_receipt')
                else:
                    _add_client(clients, cid, 'possible', trace_id,
                                'shared_proxy_nat_candidate_without_unique_egress_proof')
            if not candidates and len(confirmed_set) == 1:
                # Identity came directly from the receipt/token path.
                pass
        else:
            for cid in candidates:
                _add_client(clients, cid, 'possible', trace_id,
                            'shared_proxy_nat_identity_unresolved')
            if not candidates:
                unresolved_responses.append({'trace_id': trace_id, 'status': 'physical_response_without_subject'})

    for cid in known:
        if cid not in clients:
            _add_client(clients, cid, 'unknown', None, 'subscriber_without_response_or_receipt_evidence')

    # Ensure every named candidate has a classification even if no aggregate yet.
    ordered = sorted(clients.values(), key=lambda item: str(item['client_id']))
    groups = {name: [] for name in ('confirmed', 'possible', 'excluded', 'unknown')}
    for item in ordered:
        groups[item['classification']].append(item)

    health_samples = [_row_dict(r) for r in db.execute(
        'SELECT sample_id,kind,observed_at,healthy,data_returned,trusted FROM incident_fault_samples WHERE incident_id=? ORDER BY observed_at,rowid',
        (incident_id,)).fetchall()]
    scope = {
        'decision': 'scoped',
        'incident_id': incident_id,
        'fault_version': case['fault_version'],
        'wave_id': case['wave_id'],
        'node_id': case['node_id'],
        'node_generation': case['node_generation'],
        'legal_clock_started_at': case['legal_clock_started_at'],
        'legal_clock_start': case['legal_clock_started_at'],
        'clock_started_at': case['legal_clock_started_at'],
        'first_notice_deadline_at': case['deadline_at'],
        'first_notice_deadline': case['deadline_at'],
        'deadline_at': case['deadline_at'],
        'earliest_fault_at': case['earliest_fault_at'],
        'physical_response_count': len(response_rows),
        'leaking_response_count': leaking_count,
        'deduplicated_response_count': len(response_rows),
        'unique_trace_ids': [r['trace_id'] for r in response_rows],
        'confirmed': groups['confirmed'],
        'possible': groups['possible'],
        'excluded': groups['excluded'],
        'unknown': groups['unknown'],
        # Convenience ID lists for assertions and notice rendering.
        'confirmed_client_ids': [x['client_id'] for x in groups['confirmed']],
        'possible_client_ids': [x['client_id'] for x in groups['possible']],
        'excluded_client_ids': [x['client_id'] for x in groups['excluded']],
        'unknown_client_ids': [x['client_id'] for x in groups['unknown']],
        'unresolved_responses': unresolved_responses,
        'health_samples': health_samples,
        'health_warning': 'node_health_is_neither_customer_disclosure_nor_absence_of_single_response_leak',
        'as_of': at,
    }
    stable = {k: v for k, v in scope.items() if k not in ('decision', 'as_of')}
    scope['scope_hash'] = sha256_hex(canonical_json(stable))
    return scope


def commit_scope(db, x):
    incident_id = pick(x, 'incident_id', 'incident', 'case_id', 'id')
    at = pick(x, 'at', 'committed_at', 'minute')
    extra_clients = pick(x, 'known_clients', 'clients', 'subscribers', 'customer_ids')
    scope = build_scope(db, incident_id, at=at, known_clients=extra_clients)
    if scope.get('decision') == 'blocked':
        return scope
    version = int(db.execute('SELECT COALESCE(MAX(version),0)+1 FROM incident_scope_versions WHERE incident_id=?',
                             (incident_id,)).fetchone()[0])
    scope_id = pick(x, 'scope_id') or f'{incident_id}:scope-v{version}'
    old = db.execute('SELECT * FROM incident_scope_versions WHERE scope_id=?', (scope_id,)).fetchone()
    if old:
        return {'decision': 'reused', 'scope_id': scope_id, 'scope_hash': old['scope_hash']}
    db.execute('INSERT INTO incident_scope_versions VALUES(?,?,?,?,?,?,?,?)',
               (scope_id, incident_id, version, scope['scope_hash'],
                canonical_json(scope), at, pick(x, 'authorizer', 'authorized_by'),
                pick(x, 'reason', default='assessment')))
    scope.update({'decision': 'scoped', 'scope_id': scope_id, 'scope_version': version})
    return scope


def record_artifact(db, x):
    """Preserve a certificate, gateway export, list export, or other original."""
    explicit_incident = pick(x, 'incident_id', 'incident', 'case_id')
    incident_id = explicit_incident or pick(x, 'id')
    if not _incident(db, incident_id):
        return {'decision': 'blocked', 'reason': 'unknown_incident'}
    kind = pick(x, 'kind', 'artifact_type')
    if kind is None:
        kind = 'certificate' if x.get('op') in ('certificate', 'record_certificate') else 'artifact'
    artifact_id = pick(x, 'artifact_id', 'uuid')
    candidate_id = pick(x, 'id')
    if not artifact_id:
        artifact_id = candidate_id if candidate_id and candidate_id != incident_id else \
            f'artifact:{incident_id}:{kind}:{pick(x, "name", default="unnamed")}:{pick(x, "at", default="na")}'
    raw = pick(x, 'raw', 'raw_bytes', 'original_bytes', 'contents', 'certificate', 'pem')
    raw_bytes = as_bytes(raw)
    raw_hash = pick(x, 'raw_hash', 'sha256') or (sha256_hex(raw_bytes) if raw_bytes else None)
    old = db.execute('SELECT * FROM incident_artifacts WHERE artifact_id=?', (artifact_id,)).fetchone()
    if old:
        if raw_hash and old['raw_hash'] and raw_hash != old['raw_hash']:
            return {'decision': 'blocked', 'reason': 'artifact_conflict'}
        return {'decision': 'reused', 'artifact_id': artifact_id, 'raw_hash': old['raw_hash']}
    at = pick(x, 'at', 'recorded_at', 'minute')
    name = pick(x, 'name', 'filename')
    db.execute('INSERT INTO incident_artifacts VALUES(?,?,?,?,?,?,?,?)',
               (artifact_id, incident_id, kind, name, at,
                raw_bytes or None, raw_hash, canonical_json(x)))
    return {'decision': 'recorded', 'artifact_id': artifact_id,
            'kind': kind, 'raw_hash': raw_hash}


@audit_run('incident_scope')
def run(db, x):
    with transaction(db):
        op = (x.get('op') or '').replace('-', '_')
        if op in ('open', 'open_incident', 'register_incident', 'create_incident',
                  'secure_evidence', 'evidence', 'record_evidence', 'credible_evidence',
                  'register_evidence', 'start_clock'):
            return open_incident(db, x)
        if op in ('approve_route', 'approve_execution', 'approve',
                  'preapprove_route', 'preapprove', 'approve_notice_route'):
            return approve_route(db, x)
        if op in ('fault_sample', 'add_fault_sample', 'record_fault_sample',
                  'health_failure', 'record_health', 'health_sample', 'record_health_sample'):
            return add_fault_sample(db, x)
        if op in ('request', 'record_request', 'customer_request', 'proxy_request'):
            return record_request(db, x)
        if op in ('forward', 'record_forward', 'proxy_forward', 'proxy_retry',
                  'retry_forward', 'record_proxy_retry'):
            return record_forward(db, x)
        if op in ('response', 'record_response', 'add_response',
                  'gateway_response', 'record_gateway_response', 'physical_response'):
            return record_response(db, x)
        if op in ('egress', 'egress_count', 'record_egress', 'independent_egress'):
            return record_egress(db, x)
        if op in ('artifact', 'record_artifact', 'add_artifact', 'certificate',
                  'record_certificate', 'evidence_artifact'):
            return record_artifact(db, x)
        if op in ('receipt', 'record_receipt', 'add_receipt', 'client_receipt',
                  'ack', 'acknowledgement', 'acceptance', 'client_acceptance',
                  'client_confirmation'):
            return record_receipt(db, x)
        if op in ('resolve_token', 'lookup_token', 'reverse_lookup', 'token_lookup'):
            return resolve_token(
                db,
                token=pick(x, 'token', 'receipt_token', 'sign_token'),
                token_hash=pick(x, 'token_hash'),
            )
        if op in ('unseal', 'unseal_token', 'reveal_token', 'resolve_token_binding',
                  'token_mapping', 'bind_token', 'reveal_recipient'):
            return unseal_token(db, x)
        if op in ('reverse_token', 'reverse_token_binding', 'token_reversal',
                  'reverse_receipt_token'):
            return unseal_token(db, dict(x, reverse=True))
        if op in ('scope', 'classify', 'assess', 'build_scope', 'commit_scope'):
            return commit_scope(db, x)
        if op in ('scope_view', 'get_scope', 'view_scope'):
            return build_scope(db, pick(x, 'incident_id', 'incident', 'case_id', 'id'), at=pick(x, 'at'))
        raise ValueError(x['op'])


class IncidentScopeLedger:
    """Small object facade for callers that prefer a ledger object."""

    def __init__(self, db):
        self.db = db

    def run(self, payload):
        return run(self.db, payload)

    def open(self, **payload):
        payload['op'] = 'open'
        return run(self.db, payload)

    def record(self, op, **payload):
        payload['op'] = op
        return run(self.db, payload)

    def scope(self, incident_id, at=None):
        return build_scope(self.db, incident_id, at=at)

    def resolve_token(self, token=None, token_hash=None):
        return resolve_token(self.db, token, token_hash)

    def reverse_token(self, token=None, token_hash=None):
        return resolve_token(self.db, token, token_hash)

    def reveal_client(self, token=None, token_hash=None):
        return resolve_token(self.db, token, token_hash)

    def history(self, incident_id):
        return build_scope(self.db, incident_id)


def reverse_token_lookup(token_bindings, token):
    """Pure inverse lookup helper for token -> client mappings."""
    if not isinstance(token_bindings, dict):
        return None
    return token_bindings.get(token)


def invert_token_map(token_bindings):
    """Invert a client -> token mapping into token -> client."""
    if not isinstance(token_bindings, dict):
        return {}
    return {token: client for client, token in token_bindings.items()}


IncidentScope = IncidentScopeLedger
ScopeLedger = IncidentScopeLedger
IncidentScopeService = IncidentScopeLedger
ScopeService = IncidentScopeLedger
Ledger = IncidentScopeLedger


def assess_scope(db, incident_id, at=None, commit=False):
    if commit:
        return commit_scope(db, {'op': 'scope', 'incident_id': incident_id, 'at': at})
    return build_scope(db, incident_id, at=at)


def classify_scope(db, incident_id, at=None):
    return assess_scope(db, incident_id, at=at, commit=True)


def record_gateway_response(db, payload=None, **kwargs):
    data = dict(payload or {})
    data.update(kwargs)
    data['op'] = 'gateway_response'
    return run(db, data)


def record_client_receipt(db, payload=None, **kwargs):
    data = dict(payload or {})
    data.update(kwargs)
    data['op'] = 'client_receipt'
    return run(db, data)


def unseal_client_identity(db, payload=None, **kwargs):
    data = dict(payload or {})
    data.update(kwargs)
    data['op'] = 'unseal_token'
    return run(db, data)


def reverse_receipt_token_lookup(db, token=None, token_hash=None):
    return resolve_token(db, token=token, token_hash=token_hash)
