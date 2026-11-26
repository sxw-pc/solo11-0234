"""Real independent risk approval connected to effective budget versions.

The module connects three things that must never be collapsed into a signature
flag on a budget count:

1. ``risk_requests`` locks the ORIGINAL instrument (service, base quota
   version, target quota, zone, maintenance window and benefited customers)
   together with a canonical digest.  External/device signatures are pinned to
   that digest and stored in append-only tables.
2. Authority is resolved at the effective signing time: seat tenure, approval
   cap, scope, proxy scope/revocation and the ULTIMATE CONTROLLER.  Two
   technical accounts or a layered proxy chain collapse to one accountable
   controller, so they can never count as two independent risk bearers.
3. Activation performs an optimistic version comparison against the current
   budget head.  A stale request cannot skip a competing legal revision.
   Effective capacity fed to ``wave`` comes from the activated revision plus at
   most one time-boxed emergency permit, and every actual occupancy records
   the independent group (or emergency issuer) that bears it.

All public functions open their own :func:`cloudlab.store.transaction`; the
``*_in_tx`` helpers run inside the caller's transaction (used by ``wave``).
"""

import hashlib
import hmac
import json

from .store import transaction, record

DEFAULT_BASELINE_QUOTA = 1
REQUIRED_ROLES = ('customer_rep', 'security_lead')
EMERGENCY_ISSUER_ROLES = ('duty_lead', 'on_call_lead', 'incident_commander', 'supervisor')
EMERGENCY_REVIEWER_ROLES = ('customer_rep',)
MAX_EMERGENCY_EXTRA = 1

LOCKED_FIELDS = ('request_id', 'wave_id', 'service', 'base_version',
                 'old_budget', 'new_budget', 'zone',
                 'window_start', 'window_end', 'customers')


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def _dumps(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def _loads(value, default=None):
    if value in (None, ''):
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _row(db, sql, args=()):
    cur = db.execute(sql, args)
    row = cur.fetchone()
    return dict(row) if row is not None else None


def _all(db, sql, args=()):
    return [dict(r) for r in db.execute(sql, args).fetchall()]


def _first(d, *names, default=None):
    for name in names:
        if isinstance(d, dict) and name in d and d[name] is not None:
            return d[name]
    return default


def _as_int(value):
    if value is None or isinstance(value, bool):
        return None if value is None else int(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _window_parts(**kw):
    start = _first(kw, 'window_start', 'start', 'valid_from')
    end = _first(kw, 'window_end', 'end', 'finish', 'valid_to')
    window = _first(kw, 'window', 'maintenance_window', 'maintenance_window')
    if isinstance(window, dict):
        start = start if start is not None else _first(window, 'start', 'from', 'begin')
        end = end if end is not None else _first(window, 'end', 'to', 'until')
    elif isinstance(window, (list, tuple)) and len(window) == 2:
        start, end = window[0] if start is None else start, window[1] if end is None else end
    return _as_int(start), _as_int(end)


# ---------------------------------------------------------------------------
# document digest and device signatures
# ---------------------------------------------------------------------------

def document_digest(doc):
    """Canonical SHA-256 over the locked original content."""
    body = {key: doc.get(key) for key in LOCKED_FIELDS}
    return hashlib.sha256(_dumps(body).encode('utf-8')).hexdigest()


def request_digest(row):
    doc = {key: row.get(key) for key in LOCKED_FIELDS}
    # The table primary key is ``id`` while the locked document calls it
    # ``request_id``.
    if not doc.get('request_id'):
        doc['request_id'] = row.get('id')
    # JSON columns come back as strings; normalize to the original value.
    if isinstance(doc.get('customers'), str):
        doc['customers'] = _loads(doc['customers'])
    return document_digest(doc)


def device_code(device_key, digest, seat=None, at=None):
    """Demo device signature: HMAC over digest (bound to seat and time)."""
    if device_key is None:
        return None
    if seat is not None and at is not None:
        msg = '%s|%s|%s' % (digest, seat, at)
    else:
        msg = digest
    return hmac.new(str(device_key).encode('utf-8'), msg.encode('utf-8'), hashlib.sha256).hexdigest()


def verify_device_code(device_key, digest, provided, seat=None, at=None):
    if not provided or not device_key:
        return False
    candidates = [device_code(device_key, digest, seat, at),
                  device_code(device_key, digest)]
    return any(hmac.compare_digest(str(code), str(provided)) for code in candidates if code)


# ---------------------------------------------------------------------------
# registries: principals, seats, proxy grants, incidents
# ---------------------------------------------------------------------------

def add_principal(db, principal_id=None, name=None, kind='person',
                  controller_id=None, at=None, note=None, **kw):
    principal_id = principal_id or _first(kw, 'id', 'pid')
    controller_id = controller_id or principal_id
    with transaction(db):
        old = _row(db, 'SELECT * FROM principals WHERE id=?', (principal_id,))
        payload = (name, kind, controller_id, note, at)
        if old:
            same = (old['name'], old['kind'], old['controller_id'], old['note'], old['at']) == payload
            return {'decision': 'replay' if same else 'principal_conflict', 'id': principal_id}
        db.execute('INSERT INTO principals VALUES(?,?,?,?,?,?)',
                   (principal_id, name, kind, controller_id, note, at))
        record(db, 'approval', principal_id, 'principal', 1,
               {'name': name, 'kind': kind, 'controller_id': controller_id})
        return {'decision': 'registered', 'id': principal_id, 'controller_id': controller_id}


register_principal = add_principal


def add_seat(db, seat_id=None, holder_id=None, role=None, title=None,
             valid_from=None, valid_to=None, cap=None, max_increase=None,
             zones=None, services=None, device_key=None, active=1, at=None,
             holder_name=None, controller_id=None, holder_kind='person', **kw):
    seat_id = seat_id or _first(kw, 'id', 'seat')
    holder_id = holder_id or _first(kw, 'holder', 'principal', 'holder_principal')
    # Convenience: make sure the holder principal exists.
    if holder_id and not _row(db, 'SELECT 1 FROM principals WHERE id=?', (holder_id,)):
        add_principal(db, holder_id, holder_name or holder_id, holder_kind,
                      controller_id or holder_id, at)
    zones_json = _dumps(list(zones)) if zones is not None else None
    services_json = _dumps(list(services)) if services is not None else None
    with transaction(db):
        old = _row(db, 'SELECT * FROM seats WHERE id=?', (seat_id,))
        values = (holder_id, role, title, _as_int(valid_from), _as_int(valid_to),
                  _as_int(cap), _as_int(max_increase), zones_json, services_json,
                  device_key, int(active), at)
        if old:
            current = tuple(old[k] for k in
                            ('holder_id', 'role', 'title', 'valid_from', 'valid_to', 'cap',
                             'max_increase', 'zones', 'services', 'device_key', 'active', 'at'))
            return {'decision': 'replay' if current == values else 'seat_conflict', 'id': seat_id}
        db.execute('INSERT INTO seats VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                   (seat_id,) + values)
        record(db, 'approval', seat_id, 'seat', 1,
               {'holder': holder_id, 'role': role, 'valid_from': valid_from,
                'valid_to': valid_to, 'cap': cap, 'zones': zones})
        return {'decision': 'registered', 'id': seat_id, 'role': role, 'holder_id': holder_id}


register_seat = add_seat


def _root_delegation(db, delegation_id):
    """Walk a (possibly layered) proxy chain; return root grantor + layers."""
    layers = []
    current_id = delegation_id
    seen = set()
    root = None
    while current_id and current_id not in seen:
        seen.add(current_id)
        d = _row(db, 'SELECT * FROM delegations WHERE id=?', (current_id,))
        if not d:
            return {'missing': current_id, 'layers': layers}
        layers.append(d)
        root = d
        current_id = d.get('parent_id')
    return {'root': root, 'layers': layers}


def add_proxy(db, delegation_id=None, grantor_seat=None, grantor_id=None,
              agent_id=None, scope=None, granted_at=None, expires_at=None,
              parent_id=None, status='active', **kw):
    delegation_id = delegation_id or _first(kw, 'id', 'proxy_id')
    granted_at = _as_int(_first(kw, 'granted_at', 'at', default=granted_at))
    expires_at = _as_int(_first(kw, 'expires_at', 'valid_to', default=expires_at))
    if grantor_seat and not grantor_id:
        seat = _row(db, 'SELECT holder_id FROM seats WHERE id=?', (grantor_seat,))
        grantor_id = seat['holder_id'] if seat else None
    scope_json = _dumps(scope) if isinstance(scope, (dict, list)) else scope
    with transaction(db):
        old = _row(db, 'SELECT id FROM delegations WHERE id=?', (delegation_id,))
        if old:
            return {'decision': 'replay', 'id': delegation_id}
        db.execute("""INSERT INTO delegations(id,grantor_seat,grantor_id,agent_id,parent_id,
                      scope,granted_at,expires_at,revoked_at,revocation_received_at,receipt,status)
                      VALUES(?,?,?,?,?,?,?,?,NULL,NULL,NULL,?)""",
                   (delegation_id, grantor_seat, grantor_id, agent_id, parent_id,
                    scope_json, granted_at, expires_at, status))
        record(db, 'approval', delegation_id, 'proxy_grant', 1,
               {'grantor_seat': grantor_seat, 'grantor_id': grantor_id,
                'agent_id': agent_id, 'granted_at': granted_at, 'scope': scope})
        return {'decision': 'granted', 'id': delegation_id, 'grantor_id': grantor_id}


grant_proxy = add_proxy
add_delegation = add_proxy


def revoke_proxy(db, delegation_id, revoked_at=None, received_at=None,
                 receipt=None, at=None, **kw):
    """Record a revocation.

    ``revoked_at`` is the EFFECTIVE time of revocation; ``received_at`` is when
    the verifying system obtained the receipt (which may be much later).
    Authority checks always use the effective time against the signing time,
    so an out-of-order late receipt cannot resurrect a revoked proxy.
    """
    revoked_at = _as_int(_first(kw, 'revoked_at', 'effective_at', default=revoked_at))
    received_at = _as_int(_first(kw, 'received_at', 'receipt_at', 'recorded_at', 'now',
                                 default=received_at))
    with transaction(db):
        d = _row(db, 'SELECT * FROM delegations WHERE id=?', (delegation_id,))
        if not d:
            return {'decision': 'blocked', 'reason': 'unknown_delegation'}
        if d['revoked_at'] is not None:
            return {'decision': 'replay', 'id': delegation_id, 'revoked_at': d['revoked_at']}
        db.execute("""UPDATE delegations SET revoked_at=?, revocation_received_at=?,
                      receipt=?, status='revoked' WHERE id=?""",
                   (revoked_at, received_at, receipt, delegation_id))
        _ledger(db, kind='proxy_revoked', at=revoked_at, recorded_at=received_at,
                detail={'delegation': delegation_id, 'received_at': received_at})
        record(db, 'approval', delegation_id, 'proxy_revoke', 1,
               {'revoked_at': revoked_at, 'received_at': received_at})
        return {'decision': 'revoked', 'id': delegation_id,
                'revoked_at': revoked_at, 'received_at': received_at}


def add_incident(db, incident_id=None, kind='capacity', title=None, service=None,
                 zone=None, opened_at=None, verified_at=None, verifier_seat=None,
                 state='verified', detail=None, **kw):
    incident_id = incident_id or _first(kw, 'id', 'ticket_id')
    with transaction(db):
        old = _row(db, 'SELECT id FROM incidents WHERE id=?', (incident_id,))
        if old:
            return {'decision': 'replay', 'id': incident_id}
        if verified_at is None and state == 'verified':
            verified_at = opened_at
        db.execute('INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?)',
                   (incident_id, kind, title, service, zone, opened_at, verified_at,
                    verifier_seat, state, _dumps(detail) if detail is not None else None))
        record(db, 'approval', incident_id, 'incident', 1,
               {'kind': kind, 'zone': zone, 'state': state})
        return {'decision': 'registered', 'id': incident_id, 'state': state}


register_incident = add_incident


# ---------------------------------------------------------------------------
# ledger
# ---------------------------------------------------------------------------

def _ledger(db, **kw):
    db.execute("""INSERT INTO approval_ledger(event_id,kind,request_id,signature_id,seat,
                  at,recorded_at,principal_id,controller_id,digest,qualified,reasons,detail)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
               (kw.get('event_id'), kw.get('kind'), kw.get('request_id'),
                kw.get('signature_id'), kw.get('seat'), kw.get('at'),
                kw.get('recorded_at'), kw.get('principal_id'), kw.get('controller_id'),
                kw.get('digest'),
                None if kw.get('qualified') is None else int(bool(kw.get('qualified'))),
                _dumps(kw.get('reasons')) if kw.get('reasons') is not None else None,
                _dumps(kw.get('detail')) if kw.get('detail') is not None else None))


# ---------------------------------------------------------------------------
# risk request (original instrument)
# ---------------------------------------------------------------------------

def open_request(db, request_id=None, wave_id=None, applicant=None,
                 old_budget=None, new_budget=None, at=None, service=None,
                 zone=None, base_version=None, customers=None, policy=None, **kw):
    if isinstance(request_id, dict):
        return run(db, dict(request_id, op=request_id.get('op', 'request')))
    request_id = request_id or _first(kw, 'id', 'rid')
    at = _as_int(_first(kw, 'at', 'created_at', 'minute', default=at))
    old_budget = _as_int(old_budget)
    new_budget = _as_int(new_budget)
    base_version = _first(kw, 'base', 'version', 'old_version', 'budget_version',
                          'base_quota_version', default=base_version)
    base_version = str(base_version) if base_version is not None else (
        str(old_budget) if old_budget is not None else None)
    window_start, window_end = _window_parts(
        window=kw.get('window') or kw.get('maintenance_window'),
        window_start=kw.get('window_start') or kw.get('start'),
        window_end=kw.get('window_end') or kw.get('end'))
    customers = _first(kw, 'benefited_customers', 'beneficiaries', 'customer',
                       default=customers)
    if isinstance(customers, str):
        customers = [customers]
    zone = _first(kw, 'zone', default=zone)
    service = _first(kw, 'service', default=service)
    wave_id = _first(kw, 'wave', 'wave_id', default=wave_id)
    policy = policy or _first(kw, 'approval_policy')
    policy_json = _dumps(policy) if isinstance(policy, dict) else policy

    digest = document_digest({
        'request_id': request_id, 'wave_id': wave_id, 'service': service,
        'base_version': base_version, 'old_budget': old_budget,
        'new_budget': new_budget, 'zone': zone,
        'window_start': window_start, 'window_end': window_end,
        'customers': customers})

    with transaction(db):
        old = _row(db, 'SELECT * FROM risk_requests WHERE id=?', (request_id,))
        if old:
            same_digest = (old['digest'] or request_digest(old)) == digest
            core_same = (old['wave_id'] == wave_id and old['applicant'] == applicant
                         and old['old_budget'] == old_budget
                         and old['new_budget'] == new_budget and old['at'] == at)
            if same_digest and core_same:
                return {'decision': 'replay', 'id': request_id, 'digest': old['digest'] or digest,
                        'status': old['status']}
            return {'decision': 'request_conflict', 'id': request_id,
                    'reason': 'document_already_locked'}
        db.execute("""INSERT INTO risk_requests(id,wave_id,applicant,old_budget,new_budget,
                      at,status,service,zone,base_version,window_start,window_end,customers,
                      digest,submitted_at,activated_revision,policy)
                      VALUES(?,?,?,?,?,?, 'draft', ?,?,?,?,?,?,?,?,NULL,?)""",
                   (request_id, wave_id, applicant, old_budget, new_budget, at,
                    service, zone, base_version, window_start, window_end,
                    _dumps(customers) if customers is not None else None,
                    digest, at, policy_json))
        record(db, 'approval', request_id, 'propose', 1,
               {'wave': wave_id, 'applicant': applicant, 'old_budget': old_budget,
                'new_budget': new_budget, 'at': at, 'service': service, 'zone': zone,
                'base_version': base_version, 'digest': digest,
                'customers': customers, 'window': [window_start, window_end]})
        return {'decision': 'draft', 'id': request_id, 'status': 'draft', 'digest': digest}


create_request = open_request
propose_request = open_request


# ---------------------------------------------------------------------------
# authority resolution
# ---------------------------------------------------------------------------

def _principal_controller(db, principal_id):
    p = _row(db, 'SELECT * FROM principals WHERE id=?', (principal_id,)) if principal_id else None
    if p:
        return p['controller_id'] or p['id'], p
    return principal_id, None


def resolve_authority(db, req, seat_id, at, delegation_id=None, agent_id=None):
    """Resolve whether a signature by ``seat_id`` at ``at`` carries authority.

    Returns the accountable root principal / ultimate controller and the list
    of disqualifying reasons.  This is a pure read: activation calls it again
    for every signature so late revocations are reflected without mutating the
    immutable signature row.
    """
    result = {'qualified': False, 'seat': seat_id, 'at': at,
              'principal_id': None, 'controller_id': None, 'role': None,
              'via': 'direct', 'delegation_id': delegation_id, 'reasons': []}
    seat = _row(db, 'SELECT * FROM seats WHERE id=?', (seat_id,))
    if not seat:
        result['reasons'].append('unknown_seat')
        return result
    result['role'] = seat['role']
    principal_id = seat['holder_id']

    if seat['active'] is not None and not seat['active']:
        result['reasons'].append('seat_suspended')
    if at is not None:
        if seat['valid_from'] is not None and at < seat['valid_from']:
            result['reasons'].append('seat_not_yet_valid')
        if seat['valid_to'] is not None and at > seat['valid_to']:
            result['reasons'].append('seat_tenure_ended')

    new_budget = req['new_budget'] if req else None
    old_budget = req['old_budget'] if req else None
    if seat['cap'] is not None and new_budget is not None and new_budget > seat['cap']:
        result['reasons'].append('seat_cap_exceeded')
    increase = None
    if new_budget is not None and old_budget is not None:
        increase = new_budget - old_budget
    if seat['max_increase'] is not None and increase is not None and increase > seat['max_increase']:
        result['reasons'].append('seat_increase_limit')

    zones = _loads(seat['zones'])
    if zones and req and req['zone'] and req['zone'] not in zones:
        result['reasons'].append('seat_zone_denied')
    services = _loads(seat['services'])
    if services and req and req['service'] and req['service'] not in services:
        result['reasons'].append('seat_service_denied')

    # Proxy resolution (with effective-time revocation semantics).
    if delegation_id:
        chain = _root_delegation(db, delegation_id)
        if 'missing' in chain:
            result['reasons'].append('unknown_delegation')
        else:
            d = chain['layers'][0]
            result['via'] = 'proxy'
            if len(chain['layers']) > 1:
                result['layered_proxy'] = True
            if agent_id and d['agent_id'] and str(agent_id) != str(d['agent_id']):
                result['reasons'].append('proxy_agent_mismatch')
            if at is not None:
                if d['granted_at'] is not None and at < d['granted_at']:
                    result['reasons'].append('proxy_not_yet_granted')
                if d['expires_at'] is not None and at > d['expires_at']:
                    result['reasons'].append('proxy_expired')
                # The crucial check: effective revocation <= signing time
                # disqualifies regardless of when the receipt arrived.
                if d['revoked_at'] is not None and d['revoked_at'] <= at:
                    result['reasons'].append('proxy_revoked')
            scope = _loads(d['scope'], {}) or {}
            if isinstance(scope, dict):
                sz = scope.get('zones')
                if sz and req and req['zone'] and req['zone'] not in sz:
                    result['reasons'].append('proxy_zone_denied')
                ss = scope.get('services')
                if ss and req and req['service'] and req['service'] not in ss:
                    result['reasons'].append('proxy_service_denied')
                if scope.get('max_quota') is not None and new_budget is not None \
                        and new_budget > scope['max_quota']:
                    result['reasons'].append('proxy_cap_exceeded')
                if scope.get('max_increase') is not None and increase is not None \
                        and increase > scope['max_increase']:
                    result['reasons'].append('proxy_increase_limit')
            # Accountability flows to the ROOT grantor, never the technical agent.
            principal_id = chain['root']['grantor_id'] or principal_id
    elif agent_id:
        # Signing through an agent without naming the grant: the technical
        # account cannot establish delegated authority.
        result['reasons'].append('missing_delegation')

    controller_id, principal = _principal_controller(db, principal_id)
    result['principal_id'] = principal_id
    result['controller_id'] = controller_id
    if not principal:
        result['reasons'].append('principal_unregistered')
    result['qualified'] = not result['reasons']
    return result


# ---------------------------------------------------------------------------
# external signature ingestion
# ---------------------------------------------------------------------------

def accept_signature(db, signature_id=None, request_id=None, seat=None, at=None,
                     digest=None, signature=None, device_signature=None, code=None,
                     device_id=None, delegation_id=None, proxy=None, agent_id=None,
                     received_at=None, recorded_at=None, now=None, **kw):
    if isinstance(signature_id, dict):
        return run(db, dict(signature_id, op=signature_id.get('op', 'sign')))
    signature_id = signature_id or _first(kw, 'id', 'sid')
    request_id = request_id or _first(kw, 'request', 'rid')
    seat = seat or _first(kw, 'seat_id')
    at = _as_int(_first(kw, 'signed_at', 'minute', default=at))
    received_at = _as_int(received_at if received_at is not None
                          else recorded_at if recorded_at is not None
                          else now if now is not None
                          else kw.get('ingested_at'))
    delegation_id = delegation_id or proxy or _first(kw, 'proxy_id', 'delegation')
    provided_code = signature or device_signature or code
    legacy_ok = kw.get('legacy_ok', False)

    with transaction(db):
        old = _row(db, 'SELECT * FROM risk_signatures WHERE id=?', (signature_id,))
        if old:
            same_core = (old['request_id'] == request_id and old['seat'] == seat
                         and old['at'] == at)
            same_material = (old['digest'] == (digest or old['digest'])
                             and (not provided_code or old['device_signature'] == provided_code)
                             and (not delegation_id or old['delegation_id'] == delegation_id))
            if same_core and same_material:
                out = _signature_view(old)
                out.update({'decision': 'replay', 'replay': True})
                return out
            return {'decision': 'signature_conflict', 'id': signature_id}

        req = _row(db, 'SELECT * FROM risk_requests WHERE id=?', (request_id,))
        if not req:
            return {'decision': 'missing_request', 'request_id': request_id}

        expected_digest = req['digest'] or request_digest(req)
        if not req['digest']:
            db.execute('UPDATE risk_requests SET digest=? WHERE id=?',
                       (expected_digest, request_id))
        if digest and digest != expected_digest:
            record(db, 'approval', signature_id, 'sign_rejected', 1,
                   {'request': request_id, 'seat': seat, 'reason': 'digest_mismatch'})
            return {'decision': 'digest_mismatch', 'reason': 'digest_mismatch',
                    'request_id': request_id, 'expected_digest': expected_digest,
                    'provided_digest': digest}

        seat_row = _row(db, 'SELECT * FROM seats WHERE id=?', (seat,))
        extended_material = bool(provided_code or digest or delegation_id or agent_id
                                 or received_at is not None or kw.get('extended'))
        # Baseline compatibility: a bare sign against a completely unknown
        # seat keeps the old transport contract ('signed') but the row is not
        # governance-qualified.
        legacy = legacy_ok and not extended_material and seat_row is None

        if provided_code and seat_row and seat_row['device_key']:
            if not verify_device_code(seat_row['device_key'], expected_digest,
                                      provided_code, seat, at):
                record(db, 'approval', signature_id, 'sign_rejected', 1,
                       {'request': request_id, 'seat': seat,
                        'reason': 'invalid_device_signature'})
                return {'decision': 'invalid_device_signature',
                        'reason': 'invalid_device_signature'}

        authority = resolve_authority(db, req, seat, at, delegation_id, agent_id)
        qualified = 0 if legacy else int(authority['qualified'])
        # Legacy rows are accepted as external signatures but carry no real
        # authority (unknown seat -> never qualified).
        if legacy:
            authority['qualified'] = False
            qualified = 0
            authority['reasons'] = authority['reasons'] or ['unregistered_legacy_seat']

        db.execute("""INSERT INTO risk_signatures(id,request_id,seat,at,digest,device_id,
                      device_signature,principal_id,controller_id,role,delegation_id,
                      received_at,qualified,findings,extra)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                   (signature_id, request_id, seat, at, expected_digest, device_id,
                    provided_code, authority['principal_id'], authority['controller_id'],
                    authority['role'], delegation_id, received_at, qualified,
                    _dumps(authority['reasons']),
                    _dumps({'via': authority['via'], 'agent_id': agent_id,
                            'layered_proxy': authority.get('layered_proxy')})))
        _ledger(db, event_id=signature_id, kind='external_signature',
                request_id=request_id, signature_id=signature_id, seat=seat, at=at,
                recorded_at=received_at, principal_id=authority['principal_id'],
                controller_id=authority['controller_id'], digest=expected_digest,
                qualified=authority['qualified'], reasons=authority['reasons'],
                detail={'delegation': delegation_id, 'via': authority['via']})
        record(db, 'approval', signature_id, 'sign', 1,
               {'request': request_id, 'seat': seat, 'at': at,
                'qualified': authority['qualified'],
                'controller_id': authority['controller_id'],
                'reasons': authority['reasons'], 'delegation': delegation_id})

        if legacy:
            return {'decision': 'signed', 'legacy': True,
                    'qualified': False, 'qualifies': False,
                    'seat': seat, 'at': at,
                    'principal_id': None, 'controller_id': None,
                    'reasons': authority['reasons']}
        return {'decision': 'signed', 'id': signature_id, 'request_id': request_id,
                'seat': seat, 'at': at, 'digest': expected_digest,
                'qualified': authority['qualified'],
                'qualifies': authority['qualified'],
                'principal_id': authority['principal_id'],
                'controller_id': authority['controller_id'],
                'role': authority['role'], 'via': authority['via'],
                'reasons': authority['reasons'],
                'findings': authority['reasons']}


submit_signature = accept_signature
add_signature = accept_signature


def _signature_view(row):
    return {'id': row['id'], 'request_id': row['request_id'], 'seat': row['seat'],
            'at': row['at'], 'digest': row['digest'],
            'principal_id': row['principal_id'], 'controller_id': row['controller_id'],
            'role': row['role'], 'delegation_id': row['delegation_id'],
            'qualified': bool(row['qualified']),
            'reasons': _loads(row['findings'], [])}


# ---------------------------------------------------------------------------
# independent approval breakdown
# ---------------------------------------------------------------------------

def approval_policy(req):
    policy = _loads(req['policy'], {}) if req and req['policy'] else {}
    policy = policy if isinstance(policy, dict) else {}
    return {'controllers': int(policy.get('controllers', 2)),
            'roles': tuple(policy.get('roles', REQUIRED_ROLES)),
            'segregate_applicant': bool(policy.get('segregate_applicant', False))}


def approval_breakdown(db, request_id):
    req = _row(db, 'SELECT * FROM risk_requests WHERE id=?', (request_id,))
    if not req:
        return {'request_id': request_id, 'known': False,
                'qualified': [], 'rejected': [], 'groups': {},
                'independent_controllers': [], 'sufficient': False,
                'missing_roles': list(REQUIRED_ROLES)}
    policy = approval_policy(req)
    sigs = _all(db, 'SELECT * FROM risk_signatures WHERE request_id=? ORDER BY rowid',
                (request_id,))
    expected_digest = req['digest'] or request_digest(req)
    qualified, rejected = [], []
    groups = {}
    for sig in sigs:
        # Authority is ALWAYS recomputed from durable effective-time facts;
        # this is what makes a late revocation receipt disqualify a signature
        # without rewriting the immutable external signature row.
        authority = resolve_authority(db, req, sig['seat'], sig['at'],
                                      sig['delegation_id'], None)
        digest_ok = (not sig['digest']) or hmac.compare_digest(sig['digest'], expected_digest)
        item = {'signature_id': sig['id'], 'seat': sig['seat'], 'at': sig['at'],
                'role': authority['role'] or sig['role'],
                'principal_id': authority['principal_id'] or sig['principal_id'],
                'controller_id': authority['controller_id'] or sig['controller_id'],
                'via': authority['via'], 'delegation_id': sig['delegation_id'],
                'digest_pinned': digest_ok}
        if not digest_ok:
            authority['reasons'].append('digest_mismatch')
        if authority['qualified'] and digest_ok:
            item['reasons'] = []
            qualified.append(item)
            groups.setdefault(item['controller_id'], []).append(item)
        else:
            item['reasons'] = authority['reasons']
            rejected.append(item)

    # Applicant controller (for conflict flagging / optional segregation).
    applicant_controllers = set()
    applicant = req['applicant']
    if applicant:
        p = _row(db, 'SELECT controller_id FROM principals WHERE id=? OR name=?',
                 (applicant, applicant))
        if p:
            applicant_controllers.add(p['controller_id'])

    controllers = sorted(c for c in groups if c is not None)
    role_sets = {}
    for item in qualified:
        role_sets.setdefault(item['role'], set()).add(item['controller_id'])

    required_roles = policy['roles']
    assignment = _distinct_role_assignment(required_roles, role_sets)
    missing_roles = [r for r in required_roles if r not in role_sets or not role_sets[r]]
    segregated_ok = True
    if policy['segregate_applicant']:
        segregated_ok = all(c not in applicant_controllers for c in controllers)
    sufficient = (len(controllers) >= policy['controllers']
                  and assignment is not None and segregated_ok)
    return {'known': True, 'request_id': request_id, 'policy': policy,
            'qualified': qualified, 'rejected': rejected, 'groups': groups,
            'independent_controllers': controllers,
            'controller_count': len(controllers),
            'role_controllers': {r: sorted(c) for r, c in role_sets.items()},
            'missing_roles': missing_roles,
            'role_assignment': assignment,
            'applicant_controllers': sorted(applicant_controllers),
            'sufficient': sufficient}


independent_approvers = approval_breakdown
evaluate_request = approval_breakdown


def _distinct_role_assignment(roles, role_sets):
    """Find one controller per role such that all controllers are distinct."""
    assignment = {}

    def assign(index, used):
        if index == len(roles):
            return dict(assignment)
        role = roles[index]
        for controller in sorted(role_sets.get(role, ())):
            if controller in used:
                continue
            assignment[role] = controller
            found = assign(index + 1, used | {controller})
            if found:
                return found
        return None

    return assign(0, set())


# ---------------------------------------------------------------------------
# budget versions
# ---------------------------------------------------------------------------

def head_revision(db, zone=None, service=None):
    if service is not None:
        return _row(db, """SELECT * FROM budget_revisions
                           WHERE zone IS ? AND service=?
                           ORDER BY version DESC LIMIT 1""", (zone, service))
    return _row(db, """SELECT * FROM budget_revisions WHERE zone IS ?
                       ORDER BY version DESC LIMIT 1""", (zone,))


def first_revision(db, zone=None, service=None):
    if service is not None:
        return _row(db, """SELECT * FROM budget_revisions
                           WHERE zone IS ? AND service=?
                           ORDER BY version ASC LIMIT 1""", (zone, service))
    return _row(db, """SELECT * FROM budget_revisions WHERE zone IS ?
                       ORDER BY version ASC LIMIT 1""", (zone,))


def record_revision(db, revision_id=None, *, id=None, service=None, zone=None,
                    quota=None, at=None, kind='maintenance', base_version=None,
                    ref_type=None, ref_id=None, accountable=None, detail=None,
                    version=None, source=None, source_id=None, decided_by=None, **kw):
    revision_id = revision_id or id or _first(kw, 'revision', 'budget_id')
    quota = _as_int(_first(kw, 'new_quota', default=quota))
    at = _as_int(_first(kw, 'at', 'minute', default=at))
    ref_id = ref_id or source_id
    ref_type = ref_type or source
    if accountable is None and decided_by is not None:
        accountable = decided_by
    with transaction(db):
        head = head_revision(db, zone, service)
        if head:
            new_version = _as_int(version) or head['version'] + 1
            expected_base = head['version']
            if base_version is None:
                base_version = expected_base
            else:
                base_version = _as_int(base_version)
            if base_version != expected_base:
                return {'decision': 'blocked', 'reason': 'stale_base_version',
                        'conflict': 'competing_revision',
                        'expected_base_version': expected_base,
                        'provided_base_version': base_version,
                        'head_quota': head['quota']}
            if new_version != head['version'] + 1:
                return {'decision': 'blocked', 'reason': 'version_gap_or_conflict',
                        'expected_version': head['version'] + 1}
        else:
            new_version = _as_int(version) or 1
            base_version = _as_int(base_version)
        if _row(db, 'SELECT 1 FROM budget_revisions WHERE id=?', (revision_id,)):
            return {'decision': 'replay', 'id': revision_id}
        accountable_json = _dumps(accountable) if accountable is not None else None
        db.execute("""INSERT INTO budget_revisions(id,service,zone,version,base_version,
                      quota,kind,ref_type,ref_id,accountable,at,detail)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                   (revision_id, service, zone, new_version, base_version, quota, kind,
                    ref_type, ref_id, accountable_json, at,
                    _dumps(detail) if detail is not None else None))
        record(db, 'approval', revision_id, 'budget_revision', new_version,
               {'zone': zone, 'quota': quota, 'kind': kind,
                'base_version': base_version, 'version': new_version, 'ref_id': ref_id})
        return {'decision': 'recorded', 'id': revision_id, 'revision_id': revision_id,
                'version': new_version, 'base_version': base_version, 'quota': quota}


apply_revision = record_revision
budget_revision = record_revision


# ---------------------------------------------------------------------------
# formal activation (version compare + independent approvers)
# ---------------------------------------------------------------------------

def activate(db, request_id=None, at=None, now=None, revision_id=None,
             id=None, **kw):
    if isinstance(request_id, dict):
        x = request_id
        return run(db, dict(x, op=x.get('op', 'activate')))
    request_id = request_id or _first(kw, 'rid')
    at = _as_int(_first(kw, 'at', 'minute', default=at if at is not None else now))
    with transaction(db):
        req = _row(db, 'SELECT * FROM risk_requests WHERE id=?', (request_id,))
        if not req:
            return {'decision': 'blocked', 'reason': 'unknown_request'}
        if req['status'] == 'activated' and req['activated_revision']:
            rev = _row(db, 'SELECT * FROM budget_revisions WHERE id=?',
                       (req['activated_revision'],))
            return {'decision': 'activated', 'replay': True,
                    'request_id': request_id,
                    'revision_id': req['activated_revision'],
                    'version': rev['version'] if rev else None,
                    'quota': rev['quota'] if rev else req['new_budget']}

        head = head_revision(db, req['zone'], req['service'])
        base_version = _as_int(req['base_version'])
        if head and base_version is not None and base_version != head['version']:
            verdict = approval_breakdown(db, request_id)
            return {'decision': 'blocked', 'reason': 'stale_base_version',
                    'conflict': 'competing_revision',
                    'request_id': request_id,
                    'locked_base_version': base_version,
                    'current_version': head['version'],
                    'current_quota': head['quota'],
                    'independent_controllers': verdict['independent_controllers'],
                    'rejected': [{'seat': r['seat'], 'reasons': r['reasons']}
                                 for r in verdict['rejected']]}

        verdict = approval_breakdown(db, request_id)
        if not verdict['sufficient']:
            return {'decision': 'blocked',
                    'reason': 'insufficient_independent_approval',
                    'request_id': request_id,
                    'independent_controllers': verdict['independent_controllers'],
                    'controller_count': verdict['controller_count'],
                    'required_controllers': verdict['policy']['controllers'],
                    'missing_roles': verdict['missing_roles'],
                    'role_controllers': verdict['role_controllers'],
                    'rejected': [{'seat': r['seat'], 'reasons': r['reasons'],
                                  'controller_id': r['controller_id']}
                                 for r in verdict['rejected']]}

        revision_id = revision_id or id or ('bv-%s' % request_id)
        bearers = _bearer_statement(verdict)
        rev = record_revision(
            db, revision_id, service=req['service'], zone=req['zone'],
            quota=req['new_budget'], at=at if at is not None else req['at'],
            kind='formal', base_version=head['version'] if head else None,
            ref_type='risk_request', ref_id=request_id, accountable=bearers)
        if rev.get('decision') == 'blocked':
            return rev
        db.execute("UPDATE risk_requests SET status='activated', activated_revision=? WHERE id=?",
                   (revision_id, request_id))
        _ledger(db, kind='activated', request_id=request_id, at=at,
                detail={'revision': revision_id, 'version': rev['version'],
                        'quota': req['new_budget']},
                qualified=True)
        record(db, 'approval', request_id, 'activate', rev['version'],
               {'revision': revision_id, 'version': rev['version'],
                'quota': req['new_budget'],
                'controllers': verdict['independent_controllers']})
        return {'decision': 'activated', 'request_id': request_id,
                'revision_id': revision_id, 'version': rev['version'],
                'base_version': rev['base_version'], 'quota': req['new_budget'],
                'independent_controllers': verdict['independent_controllers'],
                'bearers': bearers, 'accountable': bearers,
                'role_assignment': verdict['role_assignment']}


commit = activate
apply_approval = activate


def _bearer_statement(verdict):
    """One accountable row per qualified signature + independent group view."""
    bearers = []
    for item in verdict['qualified']:
        bearers.append({key: item.get(key) for key in
                        ('principal_id', 'controller_id', 'role', 'seat',
                         'signature_id', 'via', 'at')})
    return bearers


# ---------------------------------------------------------------------------
# emergency permits
# ---------------------------------------------------------------------------

def _permit_view(row):
    if not row:
        return None
    d = dict(row)
    d['active_now'] = None
    return d


def permit_state_at(permit, at):
    """Return (active: bool, stop_reason: str|None) at effective time ``at``."""
    if at is None:
        return False, 'unknown_time'
    start = permit['valid_from'] if permit['valid_from'] is not None else permit['issued_at']
    if start is not None and at < start:
        return False, 'not_started'
    if permit['review_state'] == 'failed' and permit['reviewed_at'] is not None \
            and at >= permit['reviewed_at']:
        return False, 'review_failed'
    if permit['state'] in ('revoked', 'review_failed'):
        # Failed review stops NEW occupancy from the review minute onward.
        if permit['reviewed_at'] is not None and at >= permit['reviewed_at']:
            return False, 'review_failed'
    if permit['ended_at'] is not None and at >= permit['ended_at']:
        return False, 'ended'
    if permit['valid_until'] is not None and at > permit['valid_until']:
        return False, 'expired'
    return True, None


def issue_emergency(db, permit_id=None, *, incident_id=None, issuer_seat=None,
                    seat=None, at=None, issued_at=None, valid_until=None, until=None,
                    extra_quota=1, add=None, extra=None, zone=None, service=None,
                    reason=None, signature=None, device_signature=None, **kw):
    if isinstance(permit_id, dict):
        return run(db, dict(permit_id, op=permit_id.get('op', 'emergency')))
    permit_id = permit_id or _first(kw, 'id', 'emergency_id', 'pid')
    issuer_seat = issuer_seat or seat or _first(kw, 'issuer', 'on_call_seat')
    issued_at = _as_int(_first(kw, 'issued_at', 'at', 'minute', default=at if at is not None else issued_at))
    valid_until = _as_int(valid_until if valid_until is not None else until)
    extra_quota = _as_int(add if add is not None else (extra if extra is not None else extra_quota))
    extra_quota = 1 if extra_quota is None else extra_quota
    provided_code = signature or device_signature

    with transaction(db):
        old = _row(db, 'SELECT * FROM emergency_permits WHERE id=?', (permit_id,))
        if old:
            return {'decision': 'replay', 'id': permit_id}
        incident = _row(db, 'SELECT * FROM incidents WHERE id=?', (incident_id,))
        if not incident:
            return {'decision': 'blocked', 'reason': 'unknown_incident',
                    'incident_id': incident_id}
        if incident['state'] not in ('verified', 'confirmed', 'open'):
            return {'decision': 'blocked', 'reason': 'incident_not_verified',
                    'incident_id': incident_id, 'state': incident['state']}
        if incident['state'] == 'open' and not kw.get('incident_verified'):
            return {'decision': 'blocked', 'reason': 'incident_not_verified',
                    'incident_id': incident_id}

        issuer = _row(db, 'SELECT * FROM seats WHERE id=?', (issuer_seat,))
        if not issuer:
            return {'decision': 'blocked', 'reason': 'unknown_seat', 'seat': issuer_seat}
        if issuer['role'] not in EMERGENCY_ISSUER_ROLES and not kw.get('allow_role'):
            return {'decision': 'blocked', 'reason': 'not_authorized_duty_lead',
                    'role': issuer['role']}
        if issued_at is not None:
            if issuer['valid_from'] is not None and issued_at < issuer['valid_from']:
                return {'decision': 'blocked', 'reason': 'seat_not_yet_valid'}
            if issuer['valid_to'] is not None and issued_at > issuer['valid_to']:
                return {'decision': 'blocked', 'reason': 'seat_tenure_ended'}
        izones = _loads(issuer['zones'])
        if izones and zone and zone not in izones:
            return {'decision': 'blocked', 'reason': 'seat_zone_denied'}
        if provided_code and issuer['device_key']:
            if not verify_device_code(issuer['device_key'],
                                      'emergency:%s:%s' % (permit_id, incident_id),
                                      provided_code, issuer_seat, issued_at) \
                    and not verify_device_code(issuer['device_key'], incident_id,
                                               provided_code):
                return {'decision': 'blocked', 'reason': 'invalid_device_signature'}

        if not isinstance(extra_quota, int) or extra_quota < 1:
            return {'decision': 'blocked', 'reason': 'invalid_emergency_quota'}
        if extra_quota > MAX_EMERGENCY_EXTRA:
            return {'decision': 'blocked', 'reason': 'emergency_limit_exceeded',
                    'max_extra': MAX_EMERGENCY_EXTRA, 'requested_extra': extra_quota}
        if valid_until is None or issued_at is None or valid_until <= issued_at:
            return {'decision': 'blocked', 'reason': 'invalid_validity_window',
                    'issued_at': issued_at, 'valid_until': valid_until}

        controller_id, principal = _principal_controller(db, issuer['holder_id'])

        # Only one live emergency increase per service/zone at a time.
        for other in _all(db, 'SELECT * FROM emergency_permits WHERE zone IS ?', (zone,)):
            active, _ = permit_state_at(other, issued_at)
            if active and (service is None or other['service'] in (None, service)):
                return {'decision': 'blocked', 'reason': 'emergency_already_active',
                        'permit_id': other['id']}

        db.execute("""INSERT INTO emergency_permits(id,incident_id,issuer_seat,issuer_id,
                      controller_id,role,service,zone,extra_quota,issued_at,valid_from,
                      valid_until,signature_id,digest,state,review_state,reviewed_at,
                      reviewer_seat,reviewer_id,review_outcome,review_note,remedy,
                      remedy_at,ended_at,detail)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL,'issued','pending',
                             NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,?)""",
                   (permit_id, incident_id, issuer_seat, issuer['holder_id'],
                    controller_id, issuer['role'], service, zone, extra_quota,
                    issued_at, issued_at, valid_until,
                    _dumps({'reason': reason}) if reason else None))
        _ledger(db, event_id=permit_id, kind='emergency_issued', at=issued_at,
                principal_id=issuer['holder_id'], controller_id=controller_id,
                detail={'permit': permit_id, 'incident': incident_id,
                        'until': valid_until, 'extra': extra_quota})
        record(db, 'approval', permit_id, 'emergency_issue', 1,
               {'incident': incident_id, 'issuer_seat': issuer_seat,
                'issuer_id': issuer['holder_id'], 'controller_id': controller_id,
                'until': valid_until, 'extra': extra_quota})
        return {'decision': 'issued', 'permit_id': permit_id, 'id': permit_id,
                'incident_id': incident_id, 'issuer_seat': issuer_seat,
                'issuer_id': issuer['holder_id'], 'controller_id': controller_id,
                'extra_quota': extra_quota, 'issued_at': issued_at,
                'valid_until': valid_until, 'review_state': 'pending',
                'state': 'issued',
                'accountable': [{'principal_id': issuer['holder_id'],
                                 'controller_id': controller_id,
                                 'role': issuer['role'], 'seat': issuer_seat,
                                 'instrument': 'emergency_permit'}]}


grant_emergency = issue_emergency
emergency_permit = issue_emergency


def review_emergency(db, permit_id=None, at=None, outcome=None,
                     reviewer_seat=None, reviewer=None, note=None,
                     remedy=None, now=None, **kw):
    if isinstance(permit_id, dict):
        return run(db, dict(permit_id, op=permit_id.get('op', 'review')))
    permit_id = permit_id or _first(kw, 'id', 'emergency_id')
    at = _as_int(_first(kw, 'at', 'minute', default=at if at is not None else now))
    reviewer_seat = reviewer_seat or reviewer or _first(kw, 'reviewer_id', 'by')
    outcome = _first(kw, 'result', 'decision', 'verdict', default=outcome)
    outcome = {'pass': 'confirmed', 'confirm': 'confirmed', 'approved': 'confirmed',
               'ok': 'confirmed', 'success': 'confirmed',
               'fail': 'failed', 'failure': 'failed', 'rejected': 'failed',
               'not_confirmed': 'failed'}.get(outcome, outcome)
    with transaction(db):
        permit = _row(db, 'SELECT * FROM emergency_permits WHERE id=?', (permit_id,))
        if not permit:
            return {'decision': 'blocked', 'reason': 'unknown_emergency'}
        if permit['review_state'] and permit['review_state'] != 'pending':
            return {'decision': 'replay', 'id': permit_id,
                    'review_state': permit['review_state'],
                    'outcome': permit['review_outcome']}
        seat = _row(db, 'SELECT * FROM seats WHERE id=?', (reviewer_seat,))
        if not seat:
            return {'decision': 'blocked', 'reason': 'unknown_reviewer_seat'}
        if seat['role'] not in EMERGENCY_REVIEWER_ROLES and not kw.get('allow_reviewer_role'):
            return {'decision': 'blocked', 'reason': 'reviewer_not_customer_representative',
                    'role': seat['role']}
        if at is not None:
            if seat['valid_from'] is not None and at < seat['valid_from']:
                return {'decision': 'blocked', 'reason': 'reviewer_not_yet_valid'}
            if seat['valid_to'] is not None and at > seat['valid_to']:
                return {'decision': 'blocked', 'reason': 'reviewer_tenure_ended'}
        reviewer_id = seat['holder_id']
        if outcome == 'failed':
            remedy = remedy or ('new_occupancy_blocked;notify_benefiting_customer;'
                                'post_incident_review')
            db.execute("""UPDATE emergency_permits SET review_state='failed',
                          review_outcome='failed', reviewed_at=?, reviewer_seat=?,
                          reviewer_id=?, review_note=?, remedy=?, remedy_at=?,
                          state='review_failed', ended_at=? WHERE id=?""",
                       (at, reviewer_seat, reviewer_id, note, remedy, at, at,
                        permit_id))
            _ledger(db, kind='emergency_review_failed', at=at, seat=reviewer_seat,
                    principal_id=reviewer_id, detail={'remedy': remedy})
            record(db, 'approval', permit_id, 'emergency_review_failed', 1,
                   {'at': at, 'reviewer': reviewer_seat, 'remedy': remedy})
            decision = 'review_failed'
        else:
            db.execute("""UPDATE emergency_permits SET review_state='confirmed',
                          review_outcome='confirmed', reviewed_at=?, reviewer_seat=?,
                          reviewer_id=?, review_note=? WHERE id=?""",
                       (at, reviewer_seat, reviewer_id, note, permit_id))
            _ledger(db, kind='emergency_review_confirmed', at=at, seat=reviewer_seat,
                    principal_id=reviewer_id)
            record(db, 'approval', permit_id, 'emergency_review_confirmed', 1,
                   {'at': at, 'reviewer': reviewer_seat})
            decision = 'review_confirmed'
        updated = _row(db, 'SELECT * FROM emergency_permits WHERE id=?', (permit_id,))
        return {'decision': decision, 'id': permit_id, 'outcome': outcome,
                'review_state': 'failed' if outcome == 'failed' else 'confirmed',
                'reviewer_seat': reviewer_seat, 'reviewer_id': reviewer_id,
                'at': at, 'remedy': remedy if outcome == 'failed' else None,
                'permit': _permit_view(updated)}


# ---------------------------------------------------------------------------
# effective budget + wave connection
# ---------------------------------------------------------------------------

def effective_budget(db, zone=None, service=None, at=None, wave_id=None,
                     permit_id=None, request_id=None, revision_id=None):
    binding = _row(db, 'SELECT * FROM wave_authorizations WHERE wave_id=?',
                   (wave_id,)) if wave_id else None
    if binding:
        zone = zone or binding['zone']
        service = service or binding['service']
        permit_id = permit_id or binding['permit_id']
        request_id = request_id or binding['request_id']
        revision_id = revision_id or binding['revision_id']

    rev = None
    if revision_id:
        rev = _row(db, 'SELECT * FROM budget_revisions WHERE id=?', (revision_id,))
    elif request_id:
        req = _row(db, 'SELECT activated_revision FROM risk_requests WHERE id=?',
                   (request_id,))
        if req and req['activated_revision']:
            rev = _row(db, 'SELECT * FROM budget_revisions WHERE id=?',
                       (req['activated_revision'],))
    if rev is None:
        rev = head_revision(db, zone, service)

    first = first_revision(db, zone, service)
    baseline_quota = first['quota'] if first and first['quota'] is not None \
        else DEFAULT_BASELINE_QUOTA
    formal_quota = rev['quota'] if rev and rev['quota'] is not None else baseline_quota
    governed = rev is not None or binding is not None

    permits = _all(db, 'SELECT * FROM emergency_permits WHERE zone IS ?', (zone,))
    active_permits, inactive_permit = [], None
    for p in permits:
        if service is not None and p['service'] not in (None, service):
            continue
        if permit_id and p['id'] != permit_id:
            continue
        active, stop = permit_state_at(p, at) if at is not None else (False, 'unknown_time')
        if active:
            active_permits.append((p, stop))
        elif inactive_permit is None and at is not None and stop in ('expired', 'review_failed', 'ended'):
            inactive_permit = (p, stop)
    emergency_extra = min(MAX_EMERGENCY_EXTRA,
                          sum(p['extra_quota'] or 0 for p, _ in active_permits))
    cap = formal_quota + emergency_extra
    return {'governed': governed or bool(permits), 'zone': zone, 'service': service,
            'formal_quota': formal_quota, 'baseline_quota': baseline_quota,
            'cap': cap, 'effective_quota': cap,
            'head_version': rev['version'] if rev else None,
            'revision_id': rev['id'] if rev else None,
            'revision_kind': rev['kind'] if rev else None,
            'emergency_extra': emergency_extra,
            'active_permits': [_permit_view(p) for p, _ in active_permits],
            'expired_permit': ({'id': inactive_permit[0]['id'],
                                'reason': inactive_permit[1],
                                'valid_until': inactive_permit[0]['valid_until'],
                                'issuer_id': inactive_permit[0]['issuer_id'],
                                'controller_id': inactive_permit[0]['controller_id']}
                               if inactive_permit else None)}


budget_view = effective_budget


def payload_ref(x):
    """Extract an authorization reference from a wave plan/release payload."""
    if not isinstance(x, dict):
        return None
    ref = {}
    mapping = {'request_id': ('approval_id', 'risk_approval', 'request', 'rid',
                              'approval', 'approved_request', 'risk_request_id',
                              'risk_request', 'auth_id'),
               'revision_id': ('budget_revision', 'revision', 'effective_revision',
                               'revision_ref'),
               'permit_id': ('permit_id', 'emergency_id', 'emergency_permit',
                             'emergency', 'permit'),
               'service': ('service',),
               'zone': ('zone',)}
    for canonical, aliases in mapping.items():
        value = x.get(canonical)
        for alias in aliases:
            if value is None:
                value = x.get(alias)
        if value is not None and not isinstance(value, (dict, list)):
            ref[canonical] = value
    auth = x.get('authorization') or x.get('auth') or x.get('approval_ref')
    if isinstance(auth, dict):
        for key in ('request_id', 'revision_id', 'permit_id'):
            if auth.get(key):
                ref.setdefault(key, auth[key])
        if auth.get('approval_id'):
            ref.setdefault('request_id', auth['approval_id'])
    return ref or None


def occupancy_guard(db, *, wave_id=None, zone=None, at=None,
                    declared_limit=None, zone_count=0, ref=None, service=None):
    """Decide the enforceable cap / denial reason for one wave release.

    Returns a JSON-friendly dict.  ``wave`` uses ``cap`` in place of its
    plan-declared zone limit whenever governance applies.
    """
    declared_limit = _as_int(declared_limit) or DEFAULT_BASELINE_QUOTA
    view = effective_budget(db, zone=zone, service=service, at=at, wave_id=wave_id,
                            **({k: v for k, v in (ref or {}).items()
                                if k in ('permit_id', 'request_id', 'revision_id')}))
    formal_quota = view['formal_quota']
    baseline_quota = view['baseline_quota']
    cap = view['cap']
    governed = view['governed'] or declared_limit > 1

    # Resolve the formal instrument's bearers for attribution.
    accountable = []
    if view['revision_id']:
        rev = _row(db, 'SELECT accountable,ref_type,ref_id,kind FROM budget_revisions WHERE id=?',
                   (view['revision_id'],))
        if rev and rev['accountable']:
            accountable = _loads(rev['accountable'], [])

    active = view['active_permits']
    expired = view['expired_permit']
    result = {'governed': bool(governed), 'cap': cap,
              'formal_quota': formal_quota, 'baseline_quota': baseline_quota,
              'emergency_extra': view['emergency_extra'],
              'head_version': view['head_version'],
              'revision_id': view['revision_id'],
              'active_permit_ids': [p['id'] for p in active],
              'accountable': accountable,
              'allowed': zone_count < cap}

    if result['allowed']:
        if zone_count < formal_quota:
            result['slot_kind'] = ('formal' if view.get('revision_kind') == 'formal'
                                   else 'baseline')
            result['slot_accountable'] = accountable
        elif active:
            permit = active[0]
            result['slot_kind'] = 'emergency'
            result['permit_id'] = permit['id']
            result['slot_accountable'] = [{
                'principal_id': permit['issuer_id'],
                'controller_id': permit['controller_id'],
                'role': permit['role'], 'seat': permit['issuer_seat'],
                'instrument': 'emergency_permit', 'permit_id': permit['id'],
                'incident_id': permit['incident_id'],
                'responsible_for_incurred_risk': permit['issuer_id']}]
        else:
            # Should not happen (cap == formal_quota); stay safe.
            result['slot_kind'] = 'formal'
            result['slot_accountable'] = accountable
        result['reason'] = None
        return result

    # Capacity denied: choose the most truthful customer-facing reason.
    formal_covers_declared = False
    if view['revision_id']:
        rev = _row(db, 'SELECT quota,kind FROM budget_revisions WHERE id=?',
                   (view['revision_id'],))
        formal_covers_declared = bool(rev and rev['quota'] >= declared_limit
                                      and rev['kind'] == 'formal')
    if view['active_permits']:
        # A currently valid authority exists but its granted capacity is
        # numerically exhausted (e.g. the single emergency slot is in use).
        result['reason'] = None
    elif expired and not active and not formal_covers_declared and declared_limit > formal_quota:
        result['reason'] = ('emergency_review_failed'
                            if expired['reason'] == 'review_failed'
                            else ('emergency_revoked' if expired['reason'] == 'ended'
                                  else 'emergency_permit_expired'))
        result['expired_permit'] = expired
    elif declared_limit > baseline_quota and not formal_covers_declared:
        result['reason'] = 'risk_approval_required'
    else:
        # Genuine numeric exhaustion of a valid authority (or a legal
        # tightening such as the minute-19 zero-budget maintenance decision).
        result['reason'] = None
    if result['reason']:
        # The wave gate is still the same availability budget gate; the
        # specific reason explains which authority is missing or ended.
        result['budget_gate'] = 'availability_budget'
    return result


guard_release = occupancy_guard


def guard_public(guard):
    return {k: guard.get(k) for k in
            ('governed', 'cap', 'formal_quota', 'baseline_quota', 'emergency_extra',
             'head_version', 'revision_id', 'reason', 'active_permit_ids')}


# ---------------------------------------------------------------------------
# wave binding + occupancy attribution
# ---------------------------------------------------------------------------

def bind_wave(db, wave_id=None, *, request_id=None, revision_id=None,
              permit_id=None, service=None, zone=None, at=None, kind=None, **kw):
    if isinstance(wave_id, dict):
        return run(db, dict(wave_id, op=wave_id.get('op', 'bind')))
    wave_id = wave_id or _first(kw, 'id', 'wave')
    with transaction(db):
        return _bind_wave(db, wave_id, request_id=request_id, revision_id=revision_id,
                          permit_id=permit_id, service=service, zone=zone, at=at, kind=kind)


authorize_wave = bind_wave


def _bind_wave(db, wave_id, request_id=None, revision_id=None, permit_id=None,
               service=None, zone=None, at=None, kind=None):
    old = _row(db, 'SELECT * FROM wave_authorizations WHERE wave_id=?', (wave_id,))
    if old:
        compatible = ((not request_id or old['request_id'] == request_id)
                      and (not revision_id or old['revision_id'] == revision_id)
                      and (not permit_id or old['permit_id'] == permit_id))
        return {'decision': 'replay' if compatible else 'authorization_conflict',
                'wave_id': wave_id}
    if request_id and not revision_id:
        req = _row(db, 'SELECT * FROM risk_requests WHERE id=?', (request_id,))
        if req and req['activated_revision']:
            revision_id = req['activated_revision']
            zone = zone or req['zone']
            service = service or req['service']
    rev = _row(db, 'SELECT * FROM budget_revisions WHERE id=?', (revision_id,)) if revision_id else None
    if rev:
        zone = zone or rev['zone']
        service = service or rev['service']
    if not kind:
        kind = 'mixed' if (permit_id and revision_id) else (
            'emergency' if permit_id else ('formal' if revision_id or request_id else 'reference'))
    db.execute("""INSERT INTO wave_authorizations(wave_id,kind,request_id,revision_id,
                  version,permit_id,service,zone,bound_at,detail)
                  VALUES(?,?,?,?,?,?,?,?,?,?)""",
               (wave_id, kind, request_id, revision_id,
                rev['version'] if rev else None, permit_id, service, zone, at, None))
    record(db, 'approval', wave_id, 'wave_bound', 1,
           {'request_id': request_id, 'revision_id': revision_id,
            'permit_id': permit_id, 'zone': zone})
    return {'decision': 'bound', 'wave_id': wave_id, 'kind': kind,
            'request_id': request_id, 'revision_id': revision_id,
            'permit_id': permit_id, 'zone': zone}


def bind_from_payload(db, x):
    ref = payload_ref(x)
    if not ref or not x.get('id'):
        return None
    return _bind_wave(db, x['id'], at=x.get('at'), **ref)


def record_occupancy(db, *, transition_id, wave_id, node_id, zone, at, guard):
    """Persist who bears a successfully released occupancy."""
    db.execute("""INSERT OR REPLACE INTO release_attributions
                  (transition_id,wave_id,node_id,zone,at,slot_kind,cap,request_id,
                   revision_id,version,permit_id,accountable)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
               (transition_id, wave_id, node_id, zone, at,
                guard.get('slot_kind'), guard.get('cap'),
                None, guard.get('revision_id'), guard.get('head_version'),
                guard.get('permit_id') or (guard.get('active_permit_ids') or [None])[0],
                _dumps(guard.get('slot_accountable', []))))


# ---------------------------------------------------------------------------
# customer accountability report
# ---------------------------------------------------------------------------

def accountability(db, wave_id=None, zone=None, service=None):
    binding = _row(db, 'SELECT * FROM wave_authorizations WHERE wave_id=?',
                   (wave_id,)) if wave_id else None
    if binding:
        zone = zone or binding['zone']
        service = service or binding['service']

    occupancies = []
    sql = 'SELECT * FROM release_attributions WHERE 1=1'
    args = []
    if wave_id:
        sql += ' AND wave_id=?'
        args.append(wave_id)
    if zone:
        sql += ' AND zone=?'
        args.append(zone)
    for row in _all(db, sql + ' ORDER BY rowid', tuple(args)):
        item = dict(row)
        item['accountable'] = _loads(row['accountable'], [])
        occupancies.append(item)

    instruments = []
    bearer_keys = {}

    def collect(bearers, instrument):
        for b in bearers or []:
            key = b.get('controller_id') or b.get('principal_id')
            bearer_keys.setdefault(key, b)
            instruments  # no-op

    rev_sql = 'SELECT * FROM budget_revisions WHERE kind=? '
    rargs = ['formal']
    if zone:
        rev_sql += 'AND zone=? '
        rargs.append(zone)
    if service:
        rev_sql += 'AND service=? '
        rargs.append(service)
    for rev in _all(db, rev_sql + 'ORDER BY version', tuple(rargs)):
        bearers = _loads(rev['accountable'], [])
        instruments.append({'kind': 'formal_budget_increase',
                            'id': rev['ref_id'] or rev['id'],
                            'revision_id': rev['id'], 'version': rev['version'],
                            'quota': rev['quota'], 'at': rev['at'],
                            'bearers': bearers})
        collect(bearers, rev['id'])

    permit_sql = 'SELECT * FROM emergency_permits WHERE 1=1 '
    pargs = []
    if zone:
        permit_sql += 'AND zone=? '
        pargs.append(zone)
    for p in _all(db, permit_sql + 'ORDER BY issued_at', tuple(pargs)):
        view = _permit_view(p)
        instruments.append({'kind': 'emergency_extension_max_one',
                            'id': p['id'], 'incident_id': p['incident_id'],
                            'extra_quota': p['extra_quota'],
                            'issued_at': p['issued_at'],
                            'valid_until': p['valid_until'],
                            'real_issuer': {'seat': p['issuer_seat'],
                                            'principal_id': p['issuer_id'],
                                            'controller_id': p['controller_id']},
                            'review_state': p['review_state'],
                            'reviewed_at': p['reviewed_at'],
                            'reviewer_seat': p['reviewer_seat'],
                            'remedy': p['remedy'],
                            'historical_risk_bearer': p['issuer_id']})
        collect([{'principal_id': p['issuer_id'],
                  'controller_id': p['controller_id'],
                  'role': p['role'], 'seat': p['issuer_seat']}], p['id'])

    for occ in occupancies:
        collect(occ['accountable'], occ['transition_id'])

    effective = effective_budget(db, zone=zone, service=service,
                                 wave_id=wave_id) if zone else None
    return {'wave_id': wave_id, 'zone': zone, 'service': service,
            'effective_budget': effective,
            'instruments': instruments,
            'occupancy': occupancies,
            'independent_bearers': list(bearer_keys.values()),
            'independent_controller_count': len([k for k in bearer_keys if k]),
            'statement': _statement(bearer_keys, instruments, occupancies)}


attribution_report = accountability
who_is_accountable = accountability


def _statement(bearer_keys, instruments, occupancies):
    parts = []
    formal = [i for i in instruments if i['kind'] == 'formal_budget_increase']
    if formal:
        latest = formal[-1]
        controllers = sorted({b.get('controller_id') for b in latest['bearers']
                              if b.get('controller_id')})
        parts.append('formal quota %s (version %s) is borne by independent controllers %s'
                     % (latest['quota'], latest['version'], controllers))
    emergency = [i for i in instruments if i['kind'] == 'emergency_extension_max_one']
    for e in emergency:
        parts.append('emergency +%s %s until %s issued by %s; incurred short-term risk '
                     'stays with issuer even after expiry/review=%s'
                     % (e['extra_quota'], e['id'], e['valid_until'],
                        e['real_issuer']['principal_id'], e['review_state']))
    return '; '.join(parts)


# ---------------------------------------------------------------------------
# dict dispatcher (codebase convention: module.run(db, payload))
# ---------------------------------------------------------------------------

def run(db, x):
    if not isinstance(x, dict):
        raise ValueError('wave_approval.run expects a dict payload')
    op = x.get('op', 'status')
    data = dict(x)
    data.pop('op', None)
    if op in ('principal', 'register_principal', 'add_principal'):
        return add_principal(db, **data)
    if op in ('seat', 'register_seat', 'add_seat'):
        return add_seat(db, **data)
    if op in ('proxy', 'grant_proxy', 'add_delegation'):
        return add_proxy(db, **data)
    if op in ('revoke_proxy', 'revoke', 'revocation'):
        return revoke_proxy(db, **data)
    if op in ('incident', 'register_incident', 'add_incident'):
        return add_incident(db, **data)
    if op in ('request', 'propose', 'open_request', 'create_request',
              'file_request', 'application'):
        return open_request(db, **data)
    if op in ('sign', 'signature', 'submit_signature', 'accept_signature',
              'add_signature', 'submit', 'add_approval'):
        return accept_signature(db, **data)
    if op in ('approvers', 'evaluate', 'evaluate_request', 'breakdown',
              'independent_groups'):
        if op == 'independent_groups':
            return {'independent_controllers': independent_groups(
                db, data.get('request_id') or data.get('id'))}
        return approval_breakdown(db, data.get('request_id') or data.get('id'))
    if op in ('can_activate',):
        return {'can_activate': can_activate(
            db, data.get('request_id') or data.get('id'))}
    if op in ('revision', 'record_revision', 'budget_revision', 'apply_revision',
              'create_revision', 'budget_version'):
        return record_revision(db, **data)
    if op in ('activate', 'commit', 'apply', 'approve', 'approve_request'):
        return activate(db, **data)
    if op in ('emergency', 'issue_emergency', 'grant_emergency',
              'emergency_grant', 'duty_emergency'):
        return issue_emergency(db, **data)
    if op in ('review', 'review_emergency', 'emergency_review'):
        return review_emergency(db, **data)
    if op in ('bind', 'bind_wave', 'authorize_wave', 'authorize_wave_release'):
        return bind_wave(db, **data)
    if op in ('effective_budget', 'budget', 'effective', 'get_budget',
              'current_budget'):
        return effective_budget(db, **data)
    if op in ('guard', 'occupancy_guard'):
        return occupancy_guard(db, **data)
    if op in ('accountability', 'attribution', 'who', 'responsibility',
              'prove_accountability'):
        return accountability(db, **data)
    if op in ('digest', 'document_digest'):
        return {'digest': document_digest(data)}
    raise ValueError('unknown wave_approval op: %r' % op)


class ApprovalService:
    """Small method facade for callers that prefer an object API."""

    def __init__(self, db):
        self.db = db

    def run(self, payload):
        return run(self.db, payload)

    principal = lambda self, **kw: add_principal(self.db, **kw)           # noqa: E731
    seat = lambda self, **kw: add_seat(self.db, **kw)                     # noqa: E731
    proxy = lambda self, **kw: add_proxy(self.db, **kw)                   # noqa: E731
    revoke = lambda self, *a, **kw: revoke_proxy(self.db, *a, **kw)
    incident = lambda self, **kw: add_incident(self.db, **kw)             # noqa: E731
    request = lambda self, **kw: open_request(self.db, **kw)               # noqa: E731
    sign = lambda self, **kw: accept_signature(self.db, **kw)           # noqa: E731
    approvers = lambda self, rid: approval_breakdown(self.db, rid)
    revision = lambda self, **kw: record_revision(self.db, **kw)           # noqa: E731
    activate = lambda self, *a, **kw: activate(self.db, *a, **kw)
    emergency = lambda self, **kw: issue_emergency(self.db, **kw)         # noqa: E731
    review = lambda self, *a, **kw: review_emergency(self.db, *a, **kw)
    bind = lambda self, *a, **kw: bind_wave(self.db, *a, **kw)
    effective = lambda self, **kw: effective_budget(self.db, **kw)        # noqa: E731
    accountability = lambda self, **kw: accountability(self.db, **kw)     # noqa: E731


WaveApproval = ApprovalService
Service = ApprovalService
WaveApprovalService = ApprovalService

# Naming aliases so callers/tests using the domain vocabulary find the verbs.
verify_device_signature = verify_device_code
digest_document = document_digest
file_request = open_request
create_application = open_request
submit = accept_signature
add_approval = accept_signature
approve = activate
approve_request = activate
commit_approval = activate
emergency_grant = issue_emergency
grant_emergency_permit = issue_emergency
duty_emergency = issue_emergency
emergency_review = review_emergency
review_permit = review_emergency
create_revision = record_revision
budget_version = record_revision
get_budget = effective_budget
current_budget = effective_budget
prove_accountability = accountability
responsibility_report = accountability
occupancy_accountability = accountability
authorize_wave_release = bind_wave


def independent_groups(db, request_id):
    """Convenience: just the distinct ultimate-controller ids for a request."""
    return approval_breakdown(db, request_id)['independent_controllers']


def can_activate(db, request_id):
    """Convenience boolean used by callers that only need yes/no."""
    verdict = approval_breakdown(db, request_id)
    req = _row(db, 'SELECT * FROM risk_requests WHERE id=?', (request_id,))
    if not req:
        return False
    head = head_revision(db, req['zone'], req['service'])
    base_version = _as_int(req['base_version'])
    fresh = not (head and base_version is not None
                 and base_version != head['version'])
    return bool(verdict['sufficient'] and fresh)
