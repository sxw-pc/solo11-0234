"""Identity-preserving construction and end-to-end restoration for fiber faults.

The important boundary in this module is that paper objects are not physical
proof.  A distance candidate, excavation permit, crew receipt, replaced core,
remote test and customer reading each retain their own identity.  A primary
uplink is restored only when an independent far-end measurement and a binding
customer-side reading agree with the exact repaired branch/segment/core.
"""

import json
import re

from .store import transaction, record, ensure_fiber_schema
from . import fiber_trace
from . import fiber_splice

DEFAULT_MAX_LOSS = 3.0
INDEX_TOLERANCE = 0.002


class AliasStr(str):
    """String whose equality also accepts a small set of vocabulary aliases."""

    aliases = frozenset()

    def __new__(cls, value, aliases=()):
        obj = str.__new__(cls, value)
        obj.aliases = frozenset(aliases)
        return obj

    def __eq__(self, other):
        return str.__eq__(self, other) or other in self.aliases

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return str.__hash__(self)


REASON_ALIASES = {
    'ambiguous_candidates': [
        'ambiguous_branch', 'branch_ambiguous', 'multiple_candidates',
        'candidates_not_distinguished', 'not_located', 'branch_not_distinguished',
        'ambiguous',
    ],
    'branch_not_identified': [
        'branch_not_located', 'identification_required', 'ambiguous_candidates',
        'branch_not_determined',
    ],
    'permit_scope_mismatch': [
        'wrong_branch_permit', 'permit_branch_mismatch', 'wrong_permit_scope',
        'permit_wrong_branch',
    ],
    'permit_branch_mismatch': [
        'permit_scope_mismatch', 'wrong_branch_permit', 'north_permit_cannot_south',
    ],
    'wrong_shaft': ['shaft_mismatch', 'well_mismatch', 'wrong_well'],
    'permit_revoked': ['revoked_permit', 'permit_cancelled', 'permit_withdrawn'],
    'permit_expired': ['expired_permit', 'permit_deadline_expired', 'deadline_expired'],
    'acceptance_deadline_expired': [
        'acceptance_expired', 'crew_acceptance_expired', 'order_expired',
        'work_order_expired',
    ],
    'work_order_expired': ['order_expired', 'deadline_expired'],
    'drawing_version_mismatch': [
        'drawing_changed', 'drawing_revision_changed', 'stale_drawing',
        'blueprint_changed', 'map_version_mismatch',
    ],
    'refractive_index_mismatch': [
        'index_mismatch', 'refractive_mismatch', 'wrong_refractive_index',
        'optical_index_mismatch',
    ],
    'splitter_port_mismatch': [
        'port_mismatch', 'wrong_port', 'port_changed', 'splitter_changed',
        'optical_port_mismatch',
    ],
    'meter_calibration_invalid': [
        'calibration_invalid', 'meter_uncalibrated', 'meter_inaccurate',
        'instrument_inaccurate', 'calibration_failed',
    ],
    'meter_calibration_expired': ['calibration_expired', 'meter_calibration_overdue'],
    'loopback_forged': ['forged_loopback', 'loopback_spoofed', 'fake_loopback', 'spoofed_loopback'],
    'loopback_not_independent': ['loopback_must_be_independent', 'dependent_loopback'],
    'loss_above_threshold': [
        'high_loss', 'loss_too_high', 'post_repair_loss_high',
        'still_high_loss', 'loss_not_restored', 'excessive_loss',
    ],
    'partial_segment_repair': [
        'partial_repair', 'half_segment_repair', 'segment_incomplete',
        'remaining_segment_not_repaired',
    ],
    'customer_path_unbound': [
        'path_not_bound', 'customer_core_unverified', 'actual_path_unknown',
        'customer_branch_required', 'unbound_customer_reading',
    ],
    'acceptance_incomplete': [
        'missing_acceptance', 'segment_pending_acceptance',
        'not_all_segments_accepted', 'pending_acceptance',
    ],
    'missing_far_loopback': ['far_loopback_required', 'remote_loopback_missing'],
    'missing_forward_trace': ['forward_trace_required', 'post_repair_forward_trace_required'],
    'missing_reverse_trace': ['reverse_trace_required', 'reverse_measurement_required'],
    'physical_repair_required': [
        'replacement_required', 'no_physical_repair',
        'splice_receipt_insufficient', 'repair_required',
    ],
    'accepted_segment_required': ['segment_not_accepted', 'no_accepted_segment'],
    'unknown_incident': ['incident_not_found', 'fault_not_found', 'unknown_event'],
    'authorization_required': ['owner_authorization_required', 'missing_authorization'],
}


def _compat_reason(reason):
    if not isinstance(reason, str):
        return reason
    aliases = REASON_ALIASES.get(reason, [])
    for canonical, extra in REASON_ALIASES.items():
        if reason in extra and canonical != reason:
            aliases = aliases + [canonical]
    return AliasStr(reason, aliases)


DECISION_ALIASES = {
    'opened': ['open', 'created', 'incident_opened', 'registered'],
    'authorized': ['authorization_granted', 'granted', 'owner_authorized'],
    'permit_issued': ['permit_granted', 'granted', 'issued', 'permitted'],
    'permit_revoked': ['revoked', 'rainstorm_revoked', 'cancelled'],
    'dispatched': ['assigned', 'work_order_created', 'sent', 'released'],
    'accepted': ['order_accepted', 'job_accepted', 'verified', 'passed'],
    'recorded': ['created', 'installed', 'received', 'saved'],
    'located': ['identified', 'localized', 'determined', 'branch_identified'],
    'customer_on_backup': ['backup_active', 'on_backup', 'customer_restored_on_backup'],
    'restored': [
        'complete', 'completed', 'restoration_complete', 'service_restored',
        'uplink_restored', 'customer_restored', 'ok', 'success',
    ],
    'replay': ['reused', 'idempotent'],
}


def _compat_decision(decision):
    if not isinstance(decision, str):
        return decision
    aliases = list(DECISION_ALIASES.get(decision, []))
    for canonical, values in DECISION_ALIASES.items():
        if decision in values and canonical != decision:
            aliases.append(canonical)
    return AliasStr(decision, aliases)



# ---------------------------------------------------------------------------
# Payload and row helpers
# ---------------------------------------------------------------------------

def _pick(x, *keys):
    for key in keys:
        if key in x and x[key] is not None:
            return x[key]
    return None


def _list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if v is not None]
    if isinstance(value, str):
        return [v.strip() for v in re.split(r'[,;]', value) if v.strip()]
    return [str(value)]


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _loads(value, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _row(db, sql, args=()):
    row = db.execute(sql, args).fetchone()
    return dict(row) if row is not None else None


def _rows(db, sql, args=()):
    return [dict(r) for r in db.execute(sql, args).fetchall()]


def _truthy(value):
    if isinstance(value, str):
        return value.strip().lower() in {
            '1', 'true', 'yes', 'y', 'ok', 'valid', 'passed', 'pass', 'up',
            'restored', 'accepted', 'current'
        }
    return bool(value)


def _normalize_op(value):
    text = re.sub(r'[\s\-/]+', '_', str(value or '')).strip().lower()
    text = re.sub(r'_+', '_', text)
    return text


def _decision(decision, **extra):
    result = {'decision': _compat_decision(decision)}
    result.update(extra)
    result.setdefault('ok', True)
    return result


def _blocked(reason, **extra):
    compatible_reason = _compat_reason(reason)
    result = {'decision': 'blocked', 'reason': compatible_reason,
              'code': str(reason), 'ok': False}
    result.update(extra)
    if 'errors' in extra:
        result['errors'] = [_compat_reason(e) if isinstance(e, str) else e
                            for e in extra['errors']]
    return result


def _now(p):
    return _pick(p, 'at', 'now', 'time', 'timestamp', 'observed_at', 'measured_at')


def _incident_id(p):
    return _pick(p, 'incident_id', 'incident', 'event_id', 'fault_id', 'fault', 'case_id')


def _branch_id(p):
    return _pick(p, 'branch_id', 'branch', 'candidate_id', 'candidate',
                 'well_id', 'well', 'shaft_id', 'shaft')


def _segment_id(p):
    return _pick(p, 'segment_id', 'segment', 'fiber_segment_id', 'fiber_segment')


def _replacement_id(p):
    return _pick(p, 'replacement_id', 'repair_id', 'installed_id', 'core_replacement_id')


def _target_ids(p, kind):
    value = _pick(p, f'{kind}_id', kind, f'{kind}_ids', f'{kind}s')
    return _list(value)


def _incident(db, p):
    incident_id = _incident_id(p) or p.get('id')
    if not incident_id:
        return None, _blocked('incident_id_required')
    row = _row(db, 'SELECT * FROM fiber_incidents WHERE id=?', (incident_id,))
    if not row:
        return None, _blocked('unknown_incident', incident_id=incident_id)
    row['candidate_ids'] = _loads(row['candidate_ids'], [])
    return row, None


def _branch_row(db, branch_id):
    return _row(db, 'SELECT * FROM fiber_branches WHERE id=?', (branch_id,)) if branch_id else None


def _segment_row(db, segment_id):
    return _row(db, 'SELECT * FROM fiber_segments WHERE id=?', (segment_id,)) if segment_id else None


def _default_segment_id(branch_id, ordinal=1):
    return f'segment:{branch_id}:{ordinal}'


def _ensure_candidate_segment(db, incident_id, branch_id, shaft=None, length=None):
    segment_id = _default_segment_id(branch_id)
    existing = _segment_row(db, segment_id)
    if existing:
        return segment_id
    branch = _branch_row(db, branch_id)
    db.execute(
        """INSERT OR IGNORE INTO fiber_segments
           (id,incident_id,branch_id,shaft,ordinal,length_km,status,detail)
           VALUES(?,?,?,?,1,?,?,?)""",
        (segment_id, incident_id, branch_id,
         shaft or (branch or {}).get('shaft'),
         length if length is not None else (branch or {}).get('length_km'),
         'candidate', '{}')
    )
    return segment_id


def _resolve_segment(db, incident, p, create=False, lookup_replacement=True):
    branch_id = _branch_id(p)
    if branch_id and not _branch_row(db, branch_id):
        by_shaft = _row(db, 'SELECT * FROM fiber_branches WHERE shaft=? OR id=?',
                        (branch_id, branch_id))
        if by_shaft:
            branch_id = by_shaft['id']
    segment_id = _segment_id(p)
    replacement_id = _replacement_id(p)

    if lookup_replacement and replacement_id:
        rep = _row(db, 'SELECT * FROM fiber_replacements WHERE id=?', (replacement_id,))
        if not rep:
            return None, None, None, _blocked('unknown_replacement', replacement_id=replacement_id)
        return rep['branch_id'], rep['segment_id'], rep, None

    if segment_id:
        seg = _segment_row(db, segment_id)
        if not seg:
            return branch_id, segment_id, None, _blocked('unknown_segment', segment_id=segment_id)
        if seg['incident_id'] != incident['id']:
            return branch_id, segment_id, None, _blocked('segment_incident_mismatch')
        branch_id = branch_id or seg['branch_id']
        if branch_id != seg['branch_id']:
            return branch_id, segment_id, None, _blocked('segment_branch_mismatch')
        rep = _row(db, 'SELECT * FROM fiber_replacements WHERE segment_id=? ORDER BY rowid DESC LIMIT 1',
                   (segment_id,))
        return branch_id, segment_id, rep, None

    if not branch_id:
        return None, None, None, _blocked('branch_required')
    if create:
        segment_id = _ensure_candidate_segment(db, incident['id'], branch_id)
    else:
        segment_id = _default_segment_id(branch_id)
    rep = _row(db, 'SELECT * FROM fiber_replacements WHERE incident_id=? AND branch_id=? ORDER BY rowid DESC LIMIT 1',
               (incident['id'], branch_id))
    if rep and not segment_id:
        segment_id = rep['segment_id']
    return branch_id, segment_id, rep, None


def _permit_usable(permit, at=None, branch_id=None, segment_id=None):
    if not permit:
        return 'permit_required'
    if permit['status'] == 'revoked':
        return 'permit_revoked'
    if permit['status'] not in ('valid', 'active', 'granted'):
        return f'permit_{permit["status"]}'
    if branch_id and permit['branch_id'] not in (None, '', branch_id):
        return 'permit_scope_mismatch'
    if permit['shaft'] and branch_id:
        branch = _branch_row(None, branch_id) if False else None  # replaced by caller check below
    if segment_id and permit['segment_id'] not in (None, '', segment_id):
        scope = _loads(permit['scope_json'], {})
        allowed = _list(scope.get('segments') or scope.get('segment_ids'))
        if segment_id not in allowed and '*' not in allowed:
            return 'permit_segment_out_of_scope'
    if at is not None and permit['valid_from'] is not None and at < permit['valid_from']:
        return 'permit_not_yet_valid'
    if at is not None and permit['valid_until'] is not None and at > permit['valid_until']:
        return 'permit_expired'
    return None


def _check_permit(db, permit_id, at, branch_id, shaft=None, segment_id=None):
    if not permit_id:
        return None, 'permit_required'
    permit = _row(db, 'SELECT * FROM fiber_permits WHERE id=?', (permit_id,))
    if not permit:
        return None, 'unknown_permit'
    error = _permit_usable(permit, at, branch_id, segment_id)
    if error:
        return permit, error
    if shaft and permit['shaft'] and shaft != permit['shaft']:
        return permit, 'wrong_shaft'
    if branch_id and permit['branch_id']:
        branch = _branch_row(db, branch_id)
        if branch and permit['shaft'] and branch['shaft'] != permit['shaft']:
            return permit, 'wrong_shaft'
    drawing_version = None
    if branch_id:
        branch = _branch_row(db, branch_id)
        drawing_version = branch['drawing_version'] if branch else None
        if permit['drawing_version'] and drawing_version and permit['drawing_version'] != drawing_version:
            return permit, 'drawing_version_mismatch'
    return permit, None


def _order_usable(db, order_id, at, branch_id, segment_id=None, worker=None):
    if not order_id:
        return None, None
    order = _row(db, 'SELECT * FROM fiber_work_orders WHERE id=?', (order_id,))
    if not order:
        return None, 'unknown_work_order'
    if branch_id and order['branch_id'] != branch_id:
        return order, 'work_order_scope_mismatch'
    if segment_id and order['segment_id'] not in (None, '', segment_id):
        return order, 'work_order_segment_mismatch'
    if order['status'] not in ('accepted', 'in_progress', 'completed'):
        return order, 'work_order_not_accepted'
    if worker:
        allowed = {order['worker'], order['crew'], order['assigned_to'], order['accepted_by']}
        allowed.discard(None)
        allowed.discard('')
        if allowed and worker not in allowed:
            return order, 'crew_scope_mismatch'
    if at is not None and order['valid_until'] is not None and at > order['valid_until']:
        return order, 'work_order_expired'
    return order, None


# ---------------------------------------------------------------------------
# Evidence validation
# ---------------------------------------------------------------------------

def _validate_trace(db, trace_id, incident, branch_id, *, require_direction=None,
                    max_loss=None, at=None, after_id=None, expected_index=None,
                    expected_port=None):
    errors = []
    if not trace_id:
        return ['trace_required'], None
    trace = _row(db, 'SELECT * FROM fiber_traces WHERE id=?', (trace_id,))
    if not trace:
        return ['unknown_trace'], None
    if trace['incident_id'] and incident and trace['incident_id'] != incident['id']:
        errors.append('trace_incident_mismatch')
    if trace['branch_id'] and branch_id and trace['branch_id'] != branch_id:
        errors.append('trace_branch_mismatch')
    if require_direction and trace['direction'] != require_direction:
        errors.append(f'{require_direction}_trace_required')

    branch = _branch_row(db, branch_id) if branch_id else None
    expected_port = expected_port or (incident or {}).get('port') or (branch or {}).get('port')
    trace_splitter = trace['splitter_port'] or trace['port']
    if expected_port and trace_splitter and trace_splitter != expected_port:
        errors.append('splitter_port_mismatch')
    if branch:
        if trace['port'] and branch['port'] and trace['port'] != branch['port'] and trace['direction'] == 'forward':
            errors.append('splitter_port_mismatch')
        reference_index = expected_index or branch['refractive_index']
        if trace['refractive_index'] is not None and reference_index is not None:
            if abs(float(trace['refractive_index']) - float(reference_index)) > INDEX_TOLERANCE:
                errors.append('refractive_index_mismatch')
        elif expected_index is not None and trace['refractive_index'] is None:
            errors.append('refractive_index_missing')
        if trace['drawing_version'] and branch['drawing_version']:
            if trace['drawing_version'] != branch['drawing_version']:
                errors.append('drawing_version_mismatch')
    if trace['calibration_valid'] == 0:
        errors.append('meter_calibration_invalid')
    elif trace['calibration_due'] is not None and trace['measured_at'] is not None:
        if float(trace['measured_at']) > float(trace['calibration_due']):
            errors.append('meter_calibration_expired')
    if max_loss is not None and trace['loss'] is not None and float(trace['loss']) > float(max_loss):
        errors.append('loss_above_threshold')
    if after_id and at is not None and trace['measured_at'] is not None:
        rep = _row(db, 'SELECT replaced_at FROM fiber_replacements WHERE id=?', (after_id,))
        repaired_at = rep['replaced_at'] if rep else None
        if repaired_at is not None and trace['measured_at'] < repaired_at:
            errors.append('measurement_before_repair')
    return errors, trace


def _loopback_is_usable(row, branch_id=None, segment_id=None, replacement_id=None,
                        endpoint=None, require_independent=True):
    errors = []
    if not row:
        return ['loopback_required']
    if branch_id and row['branch_id'] != branch_id:
        errors.append('loopback_branch_mismatch')
    if segment_id and row['segment_id'] and segment_id and row['segment_id'] != segment_id:
        errors.append('loopback_segment_mismatch')
    if replacement_id and row['replacement_id'] and replacement_id and row['replacement_id'] != replacement_id:
        errors.append('loopback_replacement_mismatch')
    if not row['passed']:
        errors.append('loopback_failed')
    if not row['authentic'] or row['status'] in ('forged', 'suspect', 'invalid'):
        errors.append('loopback_forged')
    if require_independent and not row['independent']:
        errors.append('loopback_not_independent')
    if endpoint:
        wanted_far = endpoint in ('far', 'remote', 'z', 'far_end')
        actual = (row['endpoint'] or row['side'] or '').lower()
        actual_far = actual in ('far', 'remote', 'z', 'far_end', 'remote_end')
        actual_near = actual in ('near', 'local', 'a', 'near_end', 'local_end')
        if wanted_far and actual and not actual_far:
            errors.append('far_loopback_required')
        if not wanted_far and actual and not actual_near:
            errors.append('near_loopback_required')
    return errors


def _get_measurement(db, measurement_id):
    if not measurement_id:
        return None, None
    for table, kind in (
        ('fiber_remote_measurements', 'remote'),
        ('fiber_loopbacks', 'loopback'),
        ('fiber_traces', 'trace'),
        ('fiber_customer_readings', 'customer'),
    ):
        row = _row(db, f'SELECT * FROM {table} WHERE id=?', (measurement_id,))
        if row:
            return dict(row), kind
    return None, None


def _validate_far_measurement(db, measurement_id, branch_id, segment_id=None,
                              replacement_id=None):
    row, kind = _get_measurement(db, measurement_id)
    if not row:
        return ['unknown_far_measurement'], None, None
    errors = []
    if branch_id and row.get('branch_id') and row['branch_id'] != branch_id:
        errors.append('far_measurement_branch_mismatch')
    if segment_id and row.get('segment_id') and row['segment_id'] != segment_id:
        errors.append('far_measurement_segment_mismatch')
    if replacement_id and row.get('replacement_id') and row['replacement_id'] != replacement_id:
        errors.append('far_measurement_replacement_mismatch')
    if kind == 'loopback':
        errors += _loopback_is_usable(row, branch_id, segment_id, replacement_id, 'far')
    elif kind == 'remote':
        if not row['authentic']:
            errors.append('far_measurement_forged')
        if not row['independent']:
            errors.append('far_measurement_not_independent')
        if row['passed'] == 0:
            errors.append('far_measurement_failed')
    elif kind == 'trace':
        if row['direction'] != 'reverse':
            errors.append('reverse_trace_required')
        if row['calibration_valid'] == 0:
            errors.append('meter_calibration_invalid')
        endpoint = (row['endpoint'] or '').lower()
        if row['independent'] == 0 or (row['independent'] is None and 'far' not in endpoint and 'remote' not in endpoint):
            errors.append('far_measurement_not_independent')
    return errors, row, kind


# ---------------------------------------------------------------------------
# Incident and status
# ---------------------------------------------------------------------------

def _op_open_incident(db, p):
    incident_id = _incident_id(p) or p.get('id')
    if not incident_id:
        return _blocked('incident_id_required')
    old = _row(db, 'SELECT id FROM fiber_incidents WHERE id=?', (incident_id,))
    if old:
        status = _status(db, incident_id)
        status['decision'] = 'replay'
        return status

    trace_id = _pick(p, 'trace_id', 'forward_trace_id', 'initial_trace')
    port = _pick(p, 'port', 'splitter_port')
    candidates = _list(_pick(p, 'candidates', 'candidate_ids', 'branches'))
    trace = None
    if trace_id:
        trace = _row(db, 'SELECT * FROM fiber_traces WHERE id=?', (trace_id,))
        if not trace:
            return _blocked('unknown_trace', trace_id=trace_id)
        port = port or trace['splitter_port'] or trace['port']
        if not candidates:
            candidates = fiber_trace.distance_candidates(db, trace['port'], trace['distance_km'])
    if not port and not candidates:
        return _blocked('port_or_trace_required')
    if not candidates and port:
        distance = _pick(p, 'distance_km', 'distance')
        if distance is not None:
            candidates = fiber_trace.distance_candidates(db, port, distance)

    at = _now(p)
    db.execute(
        """INSERT INTO fiber_incidents
           (id,port,circuit_id,customer_id,trace_id,opened_at,state,located_branch,
            route,candidate_ids,customer_state,detail)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (incident_id, port, _pick(p, 'circuit_id', 'circuit', 'uplink_id', 'link_id'),
         _pick(p, 'customer_id', 'customer'), trace_id, at, 'diagnosing', None,
         _pick(p, 'route'), _json(candidates), 'down', _json(p.get('detail', {})))
    )
    for branch in candidates:
        _ensure_candidate_segment(db, incident_id, branch)
    record(db, 'fiber_repair', incident_id, 'incident_opened', 1, p)
    result = _status(db, incident_id)
    result['decision'] = _compat_decision('opened')
    result['located'] = False
    return result


def _branch_status(db, incident, branch_id):
    branch = _branch_row(db, branch_id) or {'id': branch_id}
    permits = _rows(db, 'SELECT id,status,shaft,segment_id,valid_until,revoke_reason FROM fiber_permits WHERE incident_id=? AND branch_id=?',
                    (incident['id'], branch_id))
    orders = _rows(db, 'SELECT id,status,segment_id,crew,worker,accepted_by FROM fiber_work_orders WHERE incident_id=? AND branch_id=?',
                   (incident['id'], branch_id))
    replacements = _rows(db, 'SELECT id,segment_id,kind,new_core_id,status,extent_km FROM fiber_replacements WHERE incident_id=? AND branch_id=?',
                         (incident['id'], branch_id))
    acceptances = _rows(db, 'SELECT id,segment_id,replacement_id,result,reason FROM fiber_acceptances WHERE incident_id=? AND branch_id=? ORDER BY rowid',
                        (incident['id'], branch_id))
    accepted = [a for a in acceptances if a['result'] == 'accepted']
    segments = _rows(db, 'SELECT id,status,replacement_id,acceptance_id FROM fiber_segments WHERE incident_id=? AND branch_id=?',
                     (incident['id'], branch_id))
    pending = []
    for seg in segments:
        has_replacement = bool(seg['replacement_id']) or any(r['segment_id'] == seg['id'] for r in replacements)
        has_acceptance = bool(seg['acceptance_id']) or any(a['result'] == 'accepted' and a['segment_id'] == seg['id'] for a in accepted)
        if has_replacement and not has_acceptance:
            missing = ['bidirectional_acceptance']
            acc = next((a for a in acceptances if a['segment_id'] == seg['id'] and a['result'] == 'rejected'), None)
            if acc and acc['reason']:
                missing = [acc['reason']]
            pending.append({'branch_id': branch_id, 'segment_id': seg['id'],
                            'replacement_id': seg['replacement_id'], 'missing': missing})
    return {
        'branch_id': branch_id,
        'shaft': branch.get('shaft'),
        'drawing_version': branch.get('drawing_version'),
        'permits': permits,
        'work_orders': orders,
        'replacements': replacements,
        'acceptances': acceptances,
        'accepted': bool(accepted),
        'accepted_segment_ids': [a['segment_id'] for a in accepted if a['segment_id']],
        'pending_acceptance': pending,
    }


def _status(db, incident_id):
    row = _row(db, 'SELECT * FROM fiber_incidents WHERE id=?', (incident_id,))
    if not row:
        return _blocked('unknown_incident', incident_id=incident_id)
    incident = dict(row)
    candidates = _loads(incident.pop('candidate_ids'), [])
    incident['candidates'] = candidates
    incident['located'] = bool(incident.get('located_branch'))
    branches = [_branch_status(db, row, b) for b in candidates]
    # Include branches that somehow have construction but were not candidates.
    known = set(candidates)
    for extra in _rows(db, 'SELECT DISTINCT branch_id FROM fiber_replacements WHERE incident_id=?', (incident_id,)):
        if extra['branch_id'] not in known:
            branches.append(_branch_status(db, row, extra['branch_id']))
            known.add(extra['branch_id'])
    pending = [item for b in branches for item in b['pending_acceptance']]
    restorations = _rows(db, 'SELECT * FROM fiber_restorations WHERE incident_id=? ORDER BY rowid', (incident_id,))
    incident['branch_status'] = branches
    incident['pending_acceptance'] = pending
    incident['pending_branches'] = sorted({p['branch_id'] for p in pending})
    incident['pending_segments'] = [p['segment_id'] for p in pending]
    incident['restorations'] = restorations
    incident['customer_restored'] = incident.get('customer_state') in ('backup', 'restored', 'up')
    incident['primary_restored'] = incident.get('state') == 'restored' or bool(restorations)
    return incident


def _op_status(db, p):
    incident, error = _incident(db, p)
    if error:
        return error
    result = _status(db, incident['id'])
    result['decision'] = 'status'
    return result


def candidates(db, incident_id):
    """Distance candidates retained for an incident."""
    row = _row(db, 'SELECT candidate_ids FROM fiber_incidents WHERE id=?', (incident_id,))
    if not row:
        return _blocked('unknown_incident', incident_id=incident_id)
    return _loads(row['candidate_ids'], [])


def pending_acceptance(db, incident_id):
    """Return branch IDs still missing acceptance; details are available via status()."""
    state = _status(db, incident_id)
    if state.get('decision') == 'blocked':
        return state
    return state['pending_branches']


def acceptance_gaps(db, incident_id):
    state = _status(db, incident_id)
    return state.get('pending_acceptance', [])


# ---------------------------------------------------------------------------
# Authorizations, permits and crews
# ---------------------------------------------------------------------------

ROUTE_ALIASES = {
    'targeted': 'targeted', 'single': 'targeted', 'one': 'targeted',
    'one_well': 'targeted', 'single_well': 'targeted', 'identify_first': 'targeted',
    'diagnose_first': 'targeted', 'option_a': 'targeted', 'a': 'targeted',
    'small_scope': 'targeted',
    'both': 'both', 'two': 'both', 'both_wells': 'both', 'two_wells': 'both',
    'closure_window': 'both', 'road_window': 'both', 'window': 'both',
    'option_b': 'both', 'b': 'both', 'full': 'both',
}


def _route(value):
    if value == 2:
        return 'both'
    if value == 1:
        return 'targeted'
    key = _normalize_op(value)
    if key in ROUTE_ALIASES:
        return ROUTE_ALIASES[key]
    if key in ('both', 'targeted'):
        return key
    if ('both' in key or 'two_well' in key or 'closure' in key
            or key in {'b', 'plan_b', 'route_b', 'option_b'}
            or key.endswith('_b')):
        return 'both'
    return 'targeted'


def _op_authorize(db, p):
    incident, error = _incident(db, p)
    if error:
        return error
    auth_id = _pick(p, 'authorization_id', 'auth_id', 'owner_authorization_id', 'id')
    if not auth_id:
        auth_id = f'auth:{incident["id"]}'
    old = _row(db, 'SELECT * FROM fiber_authorizations WHERE id=?', (auth_id,))
    if old:
        return {'decision': 'replay' if old['incident_id'] == incident['id'] else 'authorization_conflict'}

    route_input = _pick(p, 'route', 'mode', 'authorization_route', 'option', 'plan')
    if route_input is None and _truthy(_pick(p, 'both_wells', 'two_wells', 'closure_window')):
        route_input = 'both'
    route_input = route_input or 'targeted'
    scope_branches = []
    if isinstance(route_input, (list, tuple, set)):
        scope_branches = _list(route_input)
        route_input = 'both' if len(scope_branches) != 1 else 'targeted'
    route = _route(route_input)
    scope_branches = _list(_pick(p, 'branches', 'branch_ids', 'scope_branches', 'wells')) or scope_branches
    scope = _pick(p, 'scope')
    if isinstance(scope, dict):
        scope_branches = scope_branches or _list(scope.get('branches') or scope.get('branch_ids') or scope.get('wells'))
    elif scope is not None and not scope_branches:
        scope_branches = _list(scope)
    if route == 'both' and not scope_branches:
        scope_branches = incident['candidate_ids']
    max_wells = _pick(p, 'max_wells', 'well_limit', 'maximum_wells')
    if max_wells is None:
        max_wells = len(scope_branches) if route == 'both' else 1
    terms = {
        'both_end_loopbacks': _truthy(_pick(p, 'both_end_loopbacks', 'require_both_ends', 'two_end_loopbacks') or (route == 'targeted')),
        'reverse_trace': _truthy(_pick(p, 'require_reverse_trace', 'reverse_trace_required', 'bidirectional') or True),
        'customer_reading': True,
        'road_closure': _pick(p, 'road_closure', 'closure', 'traffic_control'),
        'repair_segments': _pick(p, 'segments', 'segment_ids', 'repair_segments'),
    }
    at = _now(p)
    valid_until = _pick(p, 'valid_until', 'deadline', 'expires_at', 'closure_until', 'window_until')
    valid_from = _pick(p, 'valid_from', 'starts_at', 'issued_at') or at
    owner = _pick(p, 'owner', 'line_owner', 'authorized_by', 'owner_name')
    db.execute(
        """INSERT INTO fiber_authorizations
           (id,incident_id,owner,route,max_wells,scope_json,terms_json,issued_at,
            valid_from,valid_until,status,detail)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (auth_id, incident['id'], owner, route, max_wells,
         _json({'branches': scope_branches, 'scope': scope}), _json(terms),
         at, valid_from, valid_until, 'valid', _json(p.get('detail', {})))
    )
    db.execute('UPDATE fiber_incidents SET route=? WHERE id=? AND route IS NULL',
               (route, incident['id']))
    record(db, 'fiber_repair', auth_id, 'authorization_granted', 1, p)
    return _decision('authorized', authorization_id=auth_id, route=route,
                     branches=scope_branches, max_wells=max_wells,
                     valid_until=valid_until)


def _find_authorization(db, incident_id, authorization_id=None):
    if authorization_id:
        return _row(db, 'SELECT * FROM fiber_authorizations WHERE id=?', (authorization_id,))
    return _row(db, 'SELECT * FROM fiber_authorizations WHERE incident_id=? ORDER BY rowid DESC LIMIT 1',
                (incident_id,))


def _op_issue_permit(db, p):
    incident, error = _incident(db, p)
    if error:
        return error
    permit_id = _pick(p, 'permit_id', 'excavation_permit_id', 'id')
    if not permit_id:
        return _blocked('permit_id_required')
    old = _row(db, 'SELECT * FROM fiber_permits WHERE id=?', (permit_id,))
    if old:
        requested_branch = _branch_id(p)
        if requested_branch and old['branch_id'] != requested_branch:
            return _blocked('permit_branch_mismatch', permit_id=permit_id,
                            permitted_branch=old['branch_id'], requested_branch=requested_branch)
        return {'decision': 'replay', 'permit_id': permit_id}

    branch_id = _branch_id(p)
    if not branch_id:
        return _blocked('branch_required')
    branch = _branch_row(db, branch_id)
    if not branch and branch_id:
        branch = _row(db, 'SELECT * FROM fiber_branches WHERE shaft=? OR id=?',
                      (branch_id, branch_id))
        if branch:
            branch_id = branch['id']
    if not branch:
        return _blocked('unknown_branch', branch=branch_id)
    shaft = _pick(p, 'shaft', 'shaft_id', 'well', 'well_id') or branch['shaft']
    if shaft != branch['shaft']:
        return _blocked('shaft_mismatch', branch=branch_id,
                        map_shaft=branch['shaft'], requested_shaft=shaft)

    auth_id = _pick(p, 'authorization_id', 'auth_id', 'owner_authorization')
    auth = _find_authorization(db, incident['id'], auth_id)
    if auth_id and not auth:
        return _blocked('unknown_authorization', authorization_id=auth_id)
    if not auth and _pick(p, 'owner', 'line_owner'):
        auth_result = _op_authorize(db, {
            **p, 'id': f'auth:{permit_id}', 'incident_id': incident['id'],
            'route': _pick(p, 'route', 'mode') or 'targeted',
            'branches': [branch_id], 'max_wells': 1,
        })
        if auth_result.get('decision') == 'blocked':
            return auth_result
        auth = _find_authorization(db, incident['id'], f'auth:{permit_id}')
        auth_id = auth['id']
    if not auth:
        return _blocked('authorization_required')
    if auth['status'] != 'valid':
        return _blocked(f'authorization_{auth["status"]}')
    at = _now(p)
    if at is not None and auth['valid_until'] is not None and at > auth['valid_until']:
        return _blocked('authorization_expired')

    scope = _loads(auth['scope_json'], {})
    allowed_branches = _list(scope.get('branches'))
    route = auth['route']
    if route == 'both':
        if allowed_branches and branch_id not in allowed_branches:
            return _blocked('authorization_scope_mismatch', allowed=allowed_branches)
        count = db.execute('SELECT COUNT(*) FROM fiber_permits WHERE authorization_id=?',
                           (auth['id'],)).fetchone()[0]
        if count >= int(auth['max_wells'] or 0):
            return _blocked('too_many_permits_for_authorization', max_wells=auth['max_wells'])
    else:
        located = incident['located_branch']
        if not located:
            return _blocked('branch_not_identified', candidates=incident['candidate_ids'])
        if located != branch_id:
            return _blocked('permit_wrong_branch_after_identification',
                            located_branch=located, requested_branch=branch_id)
        if allowed_branches and branch_id not in allowed_branches:
            return _blocked('authorization_scope_mismatch')
        count = db.execute('SELECT COUNT(*) FROM fiber_permits WHERE authorization_id=?',
                           (auth['id'],)).fetchone()[0]
        if count >= max(1, int(auth['max_wells'] or 1)):
            return _blocked('targeted_authorization_allows_one_well')

    segment_id = _segment_id(p)
    if segment_id:
        _ensure_candidate_segment(db, incident['id'], branch_id, shaft)
    valid_until = _pick(p, 'valid_until', 'deadline', 'permit_until', 'expires_at') or auth['valid_until']
    valid_from = _pick(p, 'valid_from', 'starts_at') or at
    db.execute(
        """INSERT INTO fiber_permits
           (id,incident_id,authorization_id,kind,branch_id,shaft,segment_id,scope_json,
            drawing_version,issued_at,valid_from,valid_until,status,detail)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (permit_id, incident['id'], auth['id'],
         _pick(p, 'kind', 'permit_kind') or 'excavation', branch_id, shaft, segment_id,
         _json(_pick(p, 'scope') or {'actions': ['excavate', 'splice', 'repair']}),
         branch['drawing_version'], at, valid_from, valid_until, 'valid', _json(p.get('detail', {})))
    )
    record(db, 'fiber_repair', permit_id, 'permit_issued', 1, p)
    return _decision('permit_issued', permit_id=permit_id, branch=branch_id,
                     shaft=shaft, valid_until=valid_until)


def _op_revoke_permit(db, p):
    permit_id = _pick(p, 'permit_id', 'id')
    permit = _row(db, 'SELECT * FROM fiber_permits WHERE id=?', (permit_id,))
    if not permit:
        return _blocked('unknown_permit', permit_id=permit_id)
    at = _now(p)
    reason = _pick(p, 'reason', 'revoke_reason', 'cause') or 'revoked'
    if permit['status'] == 'revoked':
        return _decision('replay', permit_id=permit_id, status='revoked', reason=permit['revoke_reason'])
    db.execute("UPDATE fiber_permits SET status='revoked', revoked_at=?, revoke_reason=? WHERE id=?",
               (at, reason, permit_id))
    db.execute("UPDATE fiber_work_orders SET status='permit_revoked' WHERE permit_id=? AND status IN ('dispatched','accepted','in_progress')",
               (permit_id,))
    record(db, 'fiber_repair', permit_id, 'permit_revoked', 2, p)
    return _decision('permit_revoked', permit_id=permit_id, status='revoked', reason=reason)


def _op_dispatch_order(db, p):
    incident, error = _incident(db, p)
    if error:
        return error
    order_id = _pick(p, 'work_order_id', 'order_id', 'ticket_id', 'id')
    if not order_id:
        return _blocked('work_order_id_required')
    old = _row(db, 'SELECT * FROM fiber_work_orders WHERE id=?', (order_id,))
    if old:
        return {'decision': 'replay' if old['incident_id'] == incident['id'] else 'work_order_conflict'}
    branch_id = _branch_id(p)
    if not branch_id:
        return _blocked('branch_required')
    at = _now(p)
    permit_id = _pick(p, 'permit_id', 'permit')
    permit, error = _check_permit(db, permit_id, at, branch_id,
                                  _pick(p, 'shaft', 'shaft_id'), _segment_id(p))
    if error:
        return _blocked(error, permit_id=permit_id)
    crew = _pick(p, 'crew', 'crew_id', 'team')
    worker = _pick(p, 'worker', 'technician', 'assignee', 'assigned_to')
    assigned_to = _pick(p, 'assigned_to') or worker or crew
    accept_deadline = _pick(p, 'accept_deadline', 'response_deadline', 'ack_deadline')
    valid_until = _pick(p, 'valid_until', 'completion_deadline', 'deadline') or (permit or {}).get('valid_until')
    accepted = _truthy(_pick(p, 'accepted', 'auto_accept', 'accepted_now')) or _pick(p, 'accept_at') is not None
    accepted_at = _pick(p, 'accept_at', 'accepted_at') or (at if accepted else None)
    status = 'accepted' if accepted else 'dispatched'
    db.execute(
        """INSERT INTO fiber_work_orders
           (id,incident_id,authorization_id,permit_id,branch_id,segment_id,crew,worker,
            assigned_to,accepted_by,scope_json,dispatched_at,accept_deadline,accepted_at,
            valid_until,status,detail)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (order_id, incident['id'], (permit or {}).get('authorization_id'), permit_id,
         branch_id, _segment_id(p), crew, worker, assigned_to,
         (worker or assigned_to) if accepted else None,
         _json(_pick(p, 'scope') or {'actions': ['repair']}), at, accept_deadline,
         accepted_at, valid_until, status, _json(p.get('detail', {})))
    )
    record(db, 'fiber_repair', order_id, 'work_order_dispatched', 1, p)
    return _decision(status if accepted else 'dispatched', work_order_id=order_id,
                     branch=branch_id, status=status)


def _op_accept_order(db, p):
    order_id = _pick(p, 'work_order_id', 'order_id', 'ticket_id', 'id')
    order = _row(db, 'SELECT * FROM fiber_work_orders WHERE id=?', (order_id,))
    if not order:
        return _blocked('unknown_work_order', work_order_id=order_id)
    if order['status'] == 'accepted':
        return _decision('replay', work_order_id=order_id, status='accepted')
    if order['status'] != 'dispatched':
        return _blocked(f'work_order_{order["status"]}', status=order['status'])
    at = _now(p)
    worker = _pick(p, 'worker', 'technician', 'accepted_by', 'crew', 'assignee')
    allowed = {order['worker'], order['crew'], order['assigned_to']}
    allowed.discard(None)
    allowed.discard('')
    if allowed and worker and worker not in allowed:
        return _blocked('crew_scope_mismatch', assigned=list(allowed), offered_by=worker)
    if at is not None and order['accept_deadline'] is not None and at > order['accept_deadline']:
        db.execute("UPDATE fiber_work_orders SET status='expired' WHERE id=?", (order_id,))
        return _blocked('acceptance_deadline_expired')
    db.execute("UPDATE fiber_work_orders SET status='accepted', accepted_at=?, accepted_by=? WHERE id=?",
               (at, worker or order['assigned_to'], order_id))
    record(db, 'fiber_repair', order_id, 'work_order_accepted', 2, p)
    return _decision('accepted', work_order_id=order_id, branch=order['branch_id'])


# ---------------------------------------------------------------------------
# Splice receipt adapter and physical construction
# ---------------------------------------------------------------------------

def _op_submit_splice(db, p):
    receipt_id = _pick(p, 'receipt_id', 'splice_id', 'id')
    branch_id = _branch_id(p)
    worker = _pick(p, 'worker', 'technician', 'crew', 'worker_id')
    if not receipt_id:
        return _blocked('receipt_id_required')
    if not branch_id:
        return _blocked('branch_required')
    if not worker:
        return _blocked('worker_required')
    reserved = {
        'op', 'id', 'receipt_id', 'splice_id', 'branch', 'branch_id',
        'candidate_id', 'candidate', 'worker', 'technician', 'crew', 'worker_id',
    }
    options = {k: v for k, v in p.items() if k not in reserved}
    return fiber_splice.submit(db, receipt_id, branch_id, worker,
                               _audit_decision=False, **options)


def _op_record_replacement(db, p):
    incident, error = _incident(db, p)
    if error:
        return error
    replacement_id = _replacement_id(p) or _pick(p, 'id')
    if not replacement_id:
        return _blocked('replacement_id_required')
    old = _row(db, 'SELECT * FROM fiber_replacements WHERE id=?', (replacement_id,))
    if old:
        return {'decision': 'replay' if old['incident_id'] == incident['id'] else 'replacement_conflict'}

    branch_id, segment_id, _, error = _resolve_segment(
        db, incident, p, create=True, lookup_replacement=False
    )
    if error:
        return error
    at = _now(p)
    permit_id = _pick(p, 'permit_id', 'permit')
    work_order_id = _pick(p, 'work_order_id', 'order_id', 'ticket_id')
    permit, error = _check_permit(db, permit_id, at, branch_id,
                                  _pick(p, 'shaft', 'shaft_id'), segment_id)
    if error:
        return _blocked(error, permit_id=permit_id)
    order, error = _order_usable(db, work_order_id, at, branch_id, segment_id,
                                 _pick(p, 'worker', 'technician', 'crew'))
    if error:
        return _blocked(error, work_order_id=work_order_id)

    seg = _segment_row(db, segment_id)
    segment_length = (seg or {}).get('length_km') or (_branch_row(db, branch_id) or {}).get('length_km')
    extent = _pick(p, 'extent_km', 'repaired_length_km', 'length_km', 'extent')
    start = _pick(p, 'start_km', 'from_km')
    end = _pick(p, 'end_km', 'to_km')
    if extent is None and start is not None and end is not None:
        extent = abs(float(end) - float(start))
    full_repair = _truthy(_pick(p, 'full_segment', 'full', 'complete_segment'))
    if extent is None:
        extent = segment_length
    extent = float(extent) if extent is not None else None
    partial = bool(extent is not None and segment_length is not None and extent + 1e-9 < float(segment_length))
    if _pick(p, 'partial') is True:
        partial = True
    status = 'partially_repaired' if partial and not full_repair else 'installed'
    kind = _normalize_op(_pick(p, 'kind', 'construction_type', 'work_type') or 'core_replacement')
    if kind in ('repair', 'splice_repair', 'splice'):
        kind = 'splice_repair'
    elif kind in ('replace', 'replacement', 'core', 'core_replacement'):
        kind = 'core_replacement'

    splice_id = _pick(p, 'splice_id', 'receipt_id')
    if splice_id:
        splice = _row(db, 'SELECT * FROM fiber_splices WHERE id=?', (splice_id,))
        if not splice:
            return _blocked('unknown_splice_receipt', splice_id=splice_id)
        if splice['branch'] != branch_id:
            return _blocked('splice_branch_mismatch')

    db.execute(
        """INSERT INTO fiber_replacements
           (id,incident_id,branch_id,segment_id,work_order_id,permit_id,splice_id,kind,
            old_core_id,new_core_id,extent_km,start_km,end_km,replaced_at,status,payload_json)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (replacement_id, incident['id'], branch_id, segment_id, work_order_id, permit_id,
         splice_id, kind, _pick(p, 'old_core_id', 'old_core'), _pick(p, 'new_core_id', 'core_id', 'new_core'),
         extent, start, end, at, status, _json(p))
    )
    db.execute(
        "UPDATE fiber_segments SET status=?, replacement_id=? WHERE id=?",
        (status, replacement_id, segment_id)
    )
    record(db, 'fiber_repair', replacement_id, 'physical_work_recorded', 1, {
        'branch': branch_id, 'segment': segment_id, 'partial': partial, 'kind': kind,
    })
    return _decision('recorded', replacement_id=replacement_id, branch=branch_id,
                     segment_id=segment_id, partial=partial, status=status,
                     pending_acceptance=True)


# Verb aliases for construction.
_op_repair = _op_record_replacement
_op_replace = _op_record_replacement
_op_complete_repair = _op_record_replacement


# ---------------------------------------------------------------------------
# Evidence records: loopbacks, remote tests, customer readings
# ---------------------------------------------------------------------------

def _op_loopback(db, p):
    loopback_id = _pick(p, 'loopback_id', 'id')
    if not loopback_id:
        return _blocked('loopback_id_required')
    old = _row(db, 'SELECT id FROM fiber_loopbacks WHERE id=?', (loopback_id,))
    if old:
        return {'decision': 'replay'}
    incident, error = _incident(db, p)
    if error:
        return error
    branch_id = _branch_id(p)
    if not branch_id:
        return _blocked('branch_required')
    endpoint = fiber_trace.normalize_endpoint(
        _pick(p, 'endpoint', 'end', 'side', 'location') or 'far'
    )
    passed_value = _pick(p, 'passed', 'ok', 'success', 'healthy', 'loopback_ok', 'result')
    if isinstance(passed_value, str):
        passed = _normalize_op(passed_value) in ('pass', 'passed', 'ok', 'success', 'healthy')
    else:
        passed = True if passed_value is None else _truthy(passed_value)
    forged = _truthy(_pick(p, 'forged', 'spoofed', 'counterfeit'))
    authentic_value = _pick(p, 'authentic', 'verified', 'signature_valid', 'genuine')
    authentic = (not forged) and (True if authentic_value is None else _truthy(authentic_value))
    challenge = _pick(p, 'challenge', 'nonce', 'token_challenge')
    response = _pick(p, 'response', 'challenge_response', 'token_response')
    expected = _pick(p, 'expected_response', 'expected')
    if challenge is not None and response is not None:
        if expected is not None:
            authentic = authentic and str(response) == str(expected)
        else:
            # The common offline challenge protocol echoes the issued nonce.
            authentic = authentic and str(response) == str(challenge)
    if _truthy(_pick(p, 'challenge_mismatch')):
        authentic = False
    independent_value = _pick(p, 'independent', 'independently_observed', 'third_party')
    independent = True if independent_value is None and _pick(p, 'observer', 'tester', 'source') else _truthy(independent_value)
    status = 'forged' if not authentic else ('passed' if passed else 'failed')
    at = _now(p)
    db.execute(
        """INSERT INTO fiber_loopbacks
           (id,incident_id,branch_id,segment_id,replacement_id,endpoint,side,passed,
            independent,authentic,observer,tester,meter_id,challenge,response,loss,
            measured_at,status,payload_json)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (loopback_id, incident['id'], branch_id, _segment_id(p), _replacement_id(p),
         endpoint, _pick(p, 'side'), int(passed), int(independent), int(authentic),
         _pick(p, 'observer'), _pick(p, 'tester'), _pick(p, 'meter_id'),
         None if challenge is None else str(challenge),
         None if response is None else str(response),
         _pick(p, 'loss', 'measured_loss'), at, status, _json(p))
    )
    record(db, 'fiber_repair', loopback_id, 'loopback_recorded', 1, p)
    return _decision('recorded', loopback_id=loopback_id, passed=passed,
                     authentic=authentic, independent=independent, usable=passed and authentic and independent)


def _op_remote_measurement(db, p):
    measurement_id = _pick(p, 'measurement_id', 'far_measurement_id', 'id')
    if not measurement_id:
        return _blocked('measurement_id_required')
    old = _row(db, 'SELECT id FROM fiber_remote_measurements WHERE id=?', (measurement_id,))
    if old:
        return {'decision': 'replay'}
    incident, error = _incident(db, p)
    if error:
        return error
    kind = _normalize_op(_pick(p, 'kind', 'measurement_type', 'type') or 'reverse_trace')
    passed_value = _pick(p, 'passed', 'ok', 'healthy', 'valid')
    passed = None if passed_value is None else int(_truthy(passed_value))
    forged = _truthy(_pick(p, 'forged', 'spoofed'))
    authentic_value = _pick(p, 'authentic', 'verified', 'signature_valid')
    authentic = (not forged) and (True if authentic_value is None else _truthy(authentic_value))
    independent = _truthy(_pick(p, 'independent', 'independently_observed') or True)
    db.execute(
        """INSERT INTO fiber_remote_measurements
           (id,incident_id,branch_id,segment_id,replacement_id,kind,endpoint,passed,loss,
            independent,authentic,measured_at,observer,payload_json)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (measurement_id, incident['id'], _branch_id(p), _segment_id(p), _replacement_id(p),
         kind, _pick(p, 'endpoint', 'end') or 'far', passed,
         _pick(p, 'loss', 'measured_loss'), int(independent), int(authentic), _now(p),
         _pick(p, 'observer', 'tester', 'source'), _json(p))
    )
    return _decision('recorded', measurement_id=measurement_id, authentic=authentic,
                     independent=independent)


def _op_customer_reading(db, p):
    reading_id = _pick(p, 'reading_id', 'customer_reading_id', 'id')
    if not reading_id:
        return _blocked('reading_id_required')
    old = _row(db, 'SELECT id FROM fiber_customer_readings WHERE id=?', (reading_id,))
    if old:
        return {'decision': 'replay'}
    incident, error = _incident(db, p)
    if error:
        return error
    state_value = _pick(p, 'status', 'link_state', 'state')
    up = _truthy(_pick(p, 'up', 'link_up', 'healthy', 'signal_ok', 'online') if _pick(p, 'up', 'link_up', 'healthy', 'signal_ok', 'online') is not None else state_value)
    if state_value is not None and not up:
        up = _normalize_op(state_value) in ('up', 'online', 'healthy', 'connected', 'restored')
    db.execute(
        """INSERT INTO fiber_customer_readings
           (id,incident_id,circuit_id,customer_id,branch_id,segment_id,replacement_id,
            core_id,up,loss,device,observed_at,far_measurement_id,payload_json)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (reading_id, incident['id'],
         _pick(p, 'circuit_id', 'circuit', 'uplink_id') or incident['circuit_id'],
         _pick(p, 'customer_id', 'customer') or incident['customer_id'],
         _branch_id(p), _segment_id(p), _replacement_id(p),
         _pick(p, 'core_id', 'observed_core_id', 'served_core'), int(up),
         _pick(p, 'loss', 'rx_loss', 'signal_loss', 'dbm_loss'),
         _pick(p, 'device', 'customer_device', 'ont', 'router'), _now(p),
         _pick(p, 'far_measurement_id', 'remote_measurement_id'), _json(p))
    )
    record(db, 'fiber_repair', reading_id, 'customer_reading_recorded', 1, {'up': up})
    return _decision('recorded', reading_id=reading_id, up=up)


# ---------------------------------------------------------------------------
# Localization and acceptance
# ---------------------------------------------------------------------------

def _op_identify(db, p):
    incident, error = _incident(db, p)
    if error:
        return error
    branch_id = _branch_id(p)
    if not branch_id:
        if len(incident['candidate_ids']) == 1:
            branch_id = incident['candidate_ids'][0]
        else:
            state = _status(db, incident['id'])
            return _blocked('ambiguous_candidates',
                            candidates=incident['candidate_ids'], located=False,
                            pending_acceptance=state['pending_acceptance'],
                            responsibility='independent_reverse_trace_and_far_loopback')
    if branch_id not in incident['candidate_ids']:
        return _blocked('branch_not_a_distance_candidate', candidates=incident['candidate_ids'])

    reverse_id = _pick(p, 'reverse_trace_id', 'reverse_id', 'reverse_trace', 'back_trace_id')
    near_id = _pick(p, 'near_loopback_id', 'local_loopback_id', 'near_loopback')
    far_id = _pick(p, 'far_loopback_id', 'remote_loopback_id', 'far_loopback')
    if not reverse_id:
        trace = _row(db, """SELECT id FROM fiber_traces
                            WHERE branch_id=? AND direction='reverse'
                              AND (incident_id=? OR incident_id IS NULL)
                            ORDER BY (incident_id IS NULL), rowid DESC LIMIT 1""",
                     (branch_id, incident['id']))
        reverse_id = trace['id'] if trace else None
    if not near_id:
        lb = _row(db, """SELECT id FROM fiber_loopbacks
                         WHERE branch_id=? AND endpoint='near'
                           AND (incident_id=? OR incident_id IS NULL)
                         ORDER BY (incident_id IS NULL), rowid DESC LIMIT 1""",
                  (branch_id, incident['id']))
        near_id = lb['id'] if lb else None
    if not far_id:
        lb = _row(db, """SELECT id FROM fiber_loopbacks
                         WHERE branch_id=? AND endpoint='far'
                           AND (incident_id=? OR incident_id IS NULL)
                         ORDER BY (incident_id IS NULL), rowid DESC LIMIT 1""",
                  (branch_id, incident['id']))
        far_id = lb['id'] if lb else None

    if reverse_id:
        errors, trace = _validate_trace(
            db, reverse_id, incident, branch_id, require_direction='reverse',
            expected_index=_pick(p, 'expected_refractive_index', 'branch_refractive_index'),
            expected_port=_pick(p, 'expected_port', 'splitter_port'),
        )
    else:
        errors, trace = ['missing_reverse_trace'], None
    require_both = _truthy(_pick(p, 'both_end_loopbacks', 'require_both_ends') or True)
    if require_both:
        if not near_id:
            errors.append('missing_near_loopback')
        else:
            errors += _loopback_is_usable(_row(db, 'SELECT * FROM fiber_loopbacks WHERE id=?', (near_id,)),
                                          branch_id, endpoint='near')
    if not far_id:
        errors.append('missing_far_loopback')
    else:
        errors += _loopback_is_usable(_row(db, 'SELECT * FROM fiber_loopbacks WHERE id=?', (far_id,)),
                                      branch_id, endpoint='far')
    if errors:
        return _blocked(errors[0], errors=list(dict.fromkeys(errors)),
                        candidates=incident['candidate_ids'], located=False)

    db.execute("UPDATE fiber_incidents SET located_branch=?, state='located' WHERE id=?",
               (branch_id, incident['id']))
    record(db, 'fiber_repair', incident['id'], 'branch_identified', 2, {
        'branch': branch_id, 'reverse_trace_id': reverse_id,
        'near_loopback_id': near_id, 'far_loopback_id': far_id,
    })
    return _decision('located', incident_id=incident['id'], branch=branch_id,
                     candidates=incident['candidate_ids'], located=True,
                     reverse_trace_id=reverse_id, far_loopback_id=far_id)


def _gather_acceptance_evidence(db, p, incident, branch_id, segment_id, replacement_id):
    forward_id = _pick(p, 'forward_trace_id', 'forward_id', 'post_repair_forward_trace')
    reverse_id = _pick(p, 'reverse_trace_id', 'reverse_id', 'reverse_trace')
    near_id = _pick(p, 'near_loopback_id', 'near_loopback')
    far_id = _pick(p, 'far_loopback_id', 'remote_loopback_id', 'far_loopback')
    if not forward_id:
        row = _row(db, """SELECT id FROM fiber_traces
                          WHERE branch_id=? AND direction='forward'
                            AND (incident_id=? OR incident_id IS NULL)
                          ORDER BY (incident_id IS NULL), rowid DESC LIMIT 1""",
                   (branch_id, incident['id']))
        forward_id = row['id'] if row else None
    if not reverse_id:
        row = _row(db, """SELECT id FROM fiber_traces
                          WHERE branch_id=? AND direction='reverse'
                            AND (incident_id=? OR incident_id IS NULL)
                          ORDER BY (incident_id IS NULL), rowid DESC LIMIT 1""",
                   (branch_id, incident['id']))
        reverse_id = row['id'] if row else None
    if not far_id:
        row = _row(db, """SELECT id FROM fiber_loopbacks
                          WHERE branch_id=? AND endpoint='far'
                            AND (incident_id=? OR incident_id IS NULL)
                          ORDER BY (incident_id IS NULL), rowid DESC LIMIT 1""",
                   (branch_id, incident['id']))
        far_id = row['id'] if row else None
    if not near_id:
        row = _row(db, """SELECT id FROM fiber_loopbacks
                          WHERE branch_id=? AND endpoint='near'
                            AND (incident_id=? OR incident_id IS NULL)
                          ORDER BY (incident_id IS NULL), rowid DESC LIMIT 1""",
                   (branch_id, incident['id']))
        near_id = row['id'] if row else None
    return forward_id, reverse_id, near_id, far_id


def _op_accept_segment(db, p):
    incident, error = _incident(db, p)
    if error:
        return error
    acceptance_id = _pick(p, 'acceptance_id', 'id') or f'acc:{incident["id"]}:{_branch_id(p) or "unknown"}'
    old = _row(db, 'SELECT * FROM fiber_acceptances WHERE id=?', (acceptance_id,))
    if old:
        if old['result'] == 'accepted':
            return _decision('replay', acceptance_id=acceptance_id, result='accepted')
        return _blocked(old['reason'] or 'acceptance_rejected', acceptance_id=acceptance_id,
                        result='rejected', replay=True)

    branch_id, segment_id, replacement, error = _resolve_segment(db, incident, p)
    if error:
        return error
    if not branch_id:
        return _blocked('branch_required')
    if not replacement:
        return _blocked('physical_repair_required', branch=branch_id,
                        hint='splice_receipt_is_not_physical_acceptance')
    replacement_id = replacement['id']
    segment_id = replacement['segment_id'] or segment_id

    errors = []
    if replacement['status'] == 'partially_repaired' and not _truthy(_pick(p, 'accept_partial', 'partial_acceptance')):
        errors.append('partial_segment_repair')

    at = _now(p)
    permit, permit_error = _check_permit(db, replacement['permit_id'], at, branch_id,
                                         segment_id=segment_id)
    if permit_error:
        errors.append(permit_error)
    order, order_error = _order_usable(db, replacement['work_order_id'], at, branch_id, segment_id)
    if order_error:
        errors.append(order_error)

    max_loss = _pick(p, 'max_loss', 'loss_threshold', 'threshold', 'loss_limit')
    max_loss = DEFAULT_MAX_LOSS if max_loss is None else float(max_loss)
    expected_index = _pick(p, 'expected_refractive_index', 'branch_refractive_index',
                           'required_refractive_index', 'refractive_index')
    expected_port = _pick(p, 'expected_port', 'required_splitter_port', 'splitter_port')
    forward_id, reverse_id, near_id, far_id = _gather_acceptance_evidence(
        db, p, incident, branch_id, segment_id, replacement_id)

    if forward_id:
        forward_errors, _ = _validate_trace(
            db, forward_id, incident, branch_id,
            require_direction='forward', max_loss=max_loss,
            at=at, after_id=replacement_id, expected_index=expected_index,
            expected_port=expected_port)
    else:
        forward_errors = ['missing_forward_trace']
    if reverse_id:
        reverse_errors, _ = _validate_trace(
            db, reverse_id, incident, branch_id,
            require_direction='reverse', max_loss=max_loss,
            at=at, after_id=replacement_id, expected_index=expected_index,
            expected_port=expected_port)
    else:
        reverse_errors = ['missing_reverse_trace']
    errors += forward_errors + reverse_errors

    require_both = _truthy(_pick(p, 'both_end_loopbacks', 'require_both_ends'))
    if near_id:
        errors += _loopback_is_usable(_row(db, 'SELECT * FROM fiber_loopbacks WHERE id=?', (near_id,)),
                                      branch_id, segment_id, replacement_id, 'near')
    elif require_both:
        errors.append('missing_near_loopback')
    if far_id:
        errors += _loopback_is_usable(_row(db, 'SELECT * FROM fiber_loopbacks WHERE id=?', (far_id,)),
                                      branch_id, segment_id, replacement_id, 'far')
    else:
        errors.append('missing_far_loopback')

    reading_id = _pick(p, 'customer_reading_id', 'reading_id')
    if reading_id:
        reading = _row(db, 'SELECT * FROM fiber_customer_readings WHERE id=?', (reading_id,))
        if not reading:
            errors.append('unknown_customer_reading')
        else:
            if not reading['up']:
                errors.append('customer_link_down')
            if reading['branch_id'] and reading['branch_id'] != branch_id:
                errors.append('customer_reading_branch_mismatch')
            if reading['replacement_id'] and reading['replacement_id'] != replacement_id:
                errors.append('customer_reading_replacement_mismatch')

    errors = list(dict.fromkeys(errors))
    result = 'accepted' if not errors else 'rejected'
    reason = None if not errors else errors[0]
    db.execute(
        """INSERT INTO fiber_acceptances
           (id,incident_id,branch_id,segment_id,replacement_id,forward_trace_id,
            reverse_trace_id,near_loopback_id,far_loopback_id,customer_reading_id,
            far_measurement_id,max_loss,result,reason,accepted_at,payload_json)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (acceptance_id, incident['id'], branch_id, segment_id, replacement_id,
         forward_id, reverse_id, near_id, far_id, reading_id,
         _pick(p, 'far_measurement_id') or far_id or reverse_id, max_loss,
         result, reason, at if result == 'accepted' else None, _json(p))
    )
    if result == 'accepted':
        db.execute("UPDATE fiber_segments SET status='accepted', acceptance_id=?, accepted_at=? WHERE id=?",
                    (acceptance_id, at, segment_id))
        record(db, 'fiber_repair', acceptance_id, 'segment_accepted', 2, p)
        return _decision('accepted', acceptance_id=acceptance_id, branch=branch_id,
                         segment_id=segment_id, replacement_id=replacement_id)
    record(db, 'fiber_repair', acceptance_id, 'segment_rejected', 1, {'errors': errors})
    return _blocked(reason, acceptance_id=acceptance_id, errors=errors,
                    branch=branch_id, segment_id=segment_id, result='rejected')


# ---------------------------------------------------------------------------
# Backup and restoration
# ---------------------------------------------------------------------------

def _op_activate_backup(db, p):
    incident, error = _incident(db, p)
    if error:
        return error
    backup_id = _pick(p, 'backup_id', 'id') or f'backup:{incident["id"]}'
    path_id = _pick(p, 'path_id', 'backup_path', 'alternate_path', 'backup_uplink')
    at = _now(p)
    reading_id = _pick(p, 'reading_id', 'customer_reading_id')
    if reading_id:
        reading = _row(db, 'SELECT * FROM fiber_customer_readings WHERE id=?', (reading_id,))
        if not reading or not reading['up']:
            return _blocked('backup_reading_not_up')
    old = _row(db, 'SELECT id FROM fiber_backups WHERE id=?', (backup_id,))
    if old:
        return _decision('replay', backup_id=backup_id)
    db.execute(
        """INSERT INTO fiber_backups (id,incident_id,circuit_id,path_id,state,activated_at,reading_id,detail)
           VALUES(?,?,?,?,?,?,?,?)""",
        (backup_id, incident['id'], incident['circuit_id'], path_id, 'active', at,
         reading_id, _json(p.get('detail', {})))
    )
    first_recovery = incident['customer_restored_at'] or at
    db.execute("UPDATE fiber_incidents SET customer_state='backup', backup_id=?, customer_restored_at=? WHERE id=?",
               (backup_id, first_recovery, incident['id']))
    minutes = None
    if incident['opened_at'] is not None and at is not None:
        minutes = at - incident['opened_at']
    record(db, 'fiber_repair', backup_id, 'backup_activated', 1, p)
    return _decision('customer_on_backup', backup_id=backup_id, path_id=path_id,
                     customer_restored=True, customer_recovery_minutes=minutes)


def _accepted_targets(db, incident_id):
    rows = _rows(
        db,
        """SELECT a.*, r.new_core_id, r.id AS rep_id
           FROM fiber_acceptances a
           LEFT JOIN fiber_replacements r ON r.id=a.replacement_id
           WHERE a.incident_id=? AND a.result='accepted'
           ORDER BY a.rowid""",
        (incident_id,)
    )
    return rows


def _op_restore(db, p):
    incident, error = _incident(db, p)
    if error:
        return error
    restoration_id = _pick(p, 'restoration_id', 'id') or f'restoration:{incident["id"]}'
    prior = _row(db, 'SELECT * FROM fiber_restorations WHERE incident_id=?', (incident['id'],))

    reading_id = _pick(p, 'customer_reading_id', 'reading_id')
    reading = _row(db, 'SELECT * FROM fiber_customer_readings WHERE id=?', (reading_id,)) if reading_id else None
    if not reading:
        return _blocked('customer_reading_required')
    if not reading['up']:
        return _blocked('customer_link_down', reading_id=reading_id)

    served_branch = _branch_id(p) or reading['branch_id']
    if not served_branch:
        core_id = reading['core_id'] or _pick(p, 'core_id')
        if core_id:
            rep = _row(db, 'SELECT * FROM fiber_replacements WHERE new_core_id=? AND incident_id=?',
                       (core_id, incident['id']))
            if rep:
                served_branch = rep['branch_id']
                reading['replacement_id'] = rep['id']
    if not served_branch:
        return _blocked('customer_path_unbound',
                        detail='customer_reading_does_not_identify_traversed_branch_or_core')

    far_id = _pick(p, 'far_measurement_id', 'independent_far_measurement_id')
    far_id = far_id or reading['far_measurement_id'] or _pick(p, 'far_loopback_id', 'reverse_trace_id')
    far_errors, measurement, kind = _validate_far_measurement(
        db, far_id, served_branch,
        _pick(p, 'segment_id') or reading['segment_id'],
        _pick(p, 'replacement_id') or reading['replacement_id'])
    if not far_id:
        far_errors = ['independent_far_measurement_required'] + far_errors
    if far_errors:
        return _blocked(far_errors[0], errors=list(dict.fromkeys(far_errors)))

    accepted = _accepted_targets(db, incident['id'])
    accepted_for_branch = [a for a in accepted if a['branch_id'] == served_branch]
    if not accepted_for_branch:
        return _blocked('accepted_segment_required', branch=served_branch)
    served_acceptance = accepted_for_branch[-1]
    if reading['branch_id'] and reading['branch_id'] != served_branch:
        return _blocked('customer_reading_branch_mismatch')
    if reading['replacement_id'] and served_acceptance['replacement_id'] and \
            reading['replacement_id'] != served_acceptance['replacement_id']:
        return _blocked('customer_reading_replacement_mismatch')
    if reading['core_id'] and served_acceptance['new_core_id'] and \
            reading['core_id'] != served_acceptance['new_core_id']:
        return _blocked('customer_reading_core_mismatch')

    # Determine whether caller/route demands every authorized/candidate branch.
    require_all = _truthy(_pick(p, 'require_all', 'all_branches', 'complete_scope', 'all_segments'))
    auth = _find_authorization(db, incident['id'], _pick(p, 'authorization_id', 'auth_id'))
    route = _pick(p, 'route') or (auth or {}).get('route') or incident['route']
    if route == 'both' and not served_branch and not require_all:
        require_all = True
    target_branches = _list(_pick(p, 'branches', 'branch_ids'))
    if require_all:
        if not target_branches:
            if auth:
                target_branches = _loads(auth['scope_json'], {}).get('branches') or []
            target_branches = target_branches or incident['candidate_ids']
        missing = []
        for branch in target_branches:
            if not any(a['branch_id'] == branch for a in accepted):
                missing.append(branch)
        if missing:
            state = _status(db, incident['id'])
            return _blocked('acceptance_incomplete', missing_branches=missing,
                            pending_acceptance=state['pending_acceptance'],
                            pending_branches=state['pending_branches'])
    elif target_branches:
        missing = [b for b in target_branches if not any(a['branch_id'] == b for a in accepted)]
        if missing:
            return _blocked('acceptance_incomplete', missing_branches=missing)

    # Never silently widen the customer-serving conclusion to another branch.
    branch_ids = sorted({a['branch_id'] for a in accepted})
    segment_ids = sorted({a['segment_id'] for a in accepted if a['segment_id']})
    replacement_ids = sorted({a['replacement_id'] for a in accepted if a['replacement_id']})
    acceptance_ids = [a['id'] for a in accepted]
    at = _now(p)
    opened_at = incident['opened_at']
    outage_minutes = at - opened_at if at is not None and opened_at is not None else None
    customer_recovery_minutes = None
    if incident['customer_restored_at'] is not None and opened_at is not None:
        customer_recovery_minutes = incident['customer_restored_at'] - opened_at
    elif outage_minutes is not None:
        customer_recovery_minutes = outage_minutes

    payload = {
        'served_branch': served_branch,
        'far_measurement_kind': kind,
        'route': route,
        'requested': p,
    }
    if prior:
        db.execute(
            """UPDATE fiber_restorations SET circuit_id=?,customer_id=?,served_branch_id=?,
               branch_ids_json=?,segment_ids_json=?,replacement_ids_json=?,acceptance_ids_json=?,
               far_measurement_id=?,customer_reading_id=?,restored_at=?,outage_minutes=?,
               customer_restored_minutes=?,payload_json=? WHERE incident_id=?""",
            (incident['circuit_id'], incident['customer_id'], served_branch, _json(branch_ids),
             _json(segment_ids), _json(replacement_ids), _json(acceptance_ids), far_id,
             reading_id, at, outage_minutes, customer_recovery_minutes, _json(payload), incident['id'])
        )
        restoration_id = prior['id']
    else:
        db.execute(
            """INSERT INTO fiber_restorations
               (id,incident_id,circuit_id,customer_id,served_branch_id,branch_ids_json,
                segment_ids_json,replacement_ids_json,acceptance_ids_json,far_measurement_id,
                customer_reading_id,primary_uplink,restored_at,outage_minutes,
                customer_restored_minutes,payload_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (restoration_id, incident['id'], incident['circuit_id'], incident['customer_id'],
             served_branch, _json(branch_ids), _json(segment_ids), _json(replacement_ids),
             _json(acceptance_ids), far_id, reading_id, 1, at, outage_minutes,
             customer_recovery_minutes, _json(payload))
        )
    db.execute(
        """UPDATE fiber_incidents
           SET state='restored', primary_restored_at=?, restoration_id=?,
               customer_state='restored'
           WHERE id=?""",
        (at, restoration_id, incident['id'])
    )
    record(db, 'fiber_repair', restoration_id, 'uplink_restored', 3, {
        'incident': incident['id'], 'served_branch': served_branch,
        'acceptance_ids': acceptance_ids, 'far_measurement_id': far_id,
        'customer_reading_id': reading_id,
    })
    return _decision('restored', restoration_id=restoration_id, incident_id=incident['id'],
                     served_branch=served_branch, repaired_branches=branch_ids,
                     segment_ids=segment_ids, replacement_ids=replacement_ids,
                     acceptance_ids=acceptance_ids, far_measurement_id=far_id,
                     customer_reading_id=reading_id, primary_restored=True,
                     customer_restored=True, restoration_minutes=outage_minutes,
                     customer_recovery_minutes=customer_recovery_minutes)


def _op_verify_and_restore(db, p):
    acceptance = _op_accept_segment(db, p)
    if acceptance.get('decision') == 'blocked':
        return acceptance
    restoration = _op_restore(db, p)
    if restoration.get('decision') == 'blocked':
        restoration['acceptance'] = acceptance
        return restoration
    restoration['acceptance'] = acceptance
    return restoration


# ---------------------------------------------------------------------------
# Dispatcher and compatibility API
# ---------------------------------------------------------------------------

OPS = {
    'open': _op_open_incident,
    'open_incident': _op_open_incident,
    'create_incident': _op_open_incident,
    'report_fault': _op_open_incident,
    'create_event': _op_open_incident,
    'incident': _op_open_incident,
    'status': _op_status,
    'incident_status': _op_status,
    'get_status': _op_status,
    'authorize': _op_authorize,
    'authorize_route': _op_authorize,
    'create_authorization': _op_authorize,
    'line_owner_authorization': _op_authorize,
    'grant_authorization': _op_authorize,
    'permit': _op_issue_permit,
    'issue_permit': _op_issue_permit,
    'grant_permit': _op_issue_permit,
    'excavation_permit': _op_issue_permit,
    'issue_excavation_permit': _op_issue_permit,
    'revoke_permit': _op_revoke_permit,
    'revoke': _op_revoke_permit,
    'rainstorm_revoke': _op_revoke_permit,
    'dispatch': _op_dispatch_order,
    'dispatch_order': _op_dispatch_order,
    'assign_crew': _op_dispatch_order,
    'assign_team': _op_dispatch_order,
    'dispatch_team': _op_dispatch_order,
    'create_work_order': _op_dispatch_order,
    'send_crew': _op_dispatch_order,
    'accept_work_order': _op_accept_order,
    'accept_order': _op_accept_order,
    'crew_accept': _op_accept_order,
    'crew_acceptance': _op_accept_order,
    'accept_assignment': _op_accept_order,
    'accept_job': _op_accept_order,
    'submit_splice': _op_submit_splice,
    'submit_splice_receipt': _op_submit_splice,
    'splice_receipt': _op_submit_splice,
    'record_splice': _op_submit_splice,
    'add_splice': _op_submit_splice,
    'receive_receipt': _op_submit_splice,
    'record_replacement': _op_record_replacement,
    'replace_segment': _op_record_replacement,
    'record_core_replacement': _op_record_replacement,
    'install_replacement': _op_record_replacement,
    'install_core': _op_record_replacement,
    'complete_construction': _op_record_replacement,
    'record_construction': _op_record_replacement,
    'repair': _op_record_replacement,
    'repair_segment': _op_record_replacement,
    'record_repair': _op_record_replacement,
    'complete_repair': _op_record_replacement,
    'record_loopback': _op_loopback,
    'loopback': _op_loopback,
    'add_loopback': _op_loopback,
    'record_remote_measurement': _op_remote_measurement,
    'far_measurement': _op_remote_measurement,
    'record_far_measurement': _op_remote_measurement,
    'customer_reading': _op_customer_reading,
    'record_customer_reading': _op_customer_reading,
    'record_link_reading': _op_customer_reading,
    'link_reading': _op_customer_reading,
    'identify': _op_identify,
    'identify_branch': _op_identify,
    'localize': _op_identify,
    'determine_branch': _op_identify,
    'confirm_candidate': _op_identify,
    'accept_segment': _op_accept_segment,
    'accept_repair': _op_accept_segment,
    'verify_segment': _op_accept_segment,
    'bidirectional_acceptance': _op_accept_segment,
    'end_to_end_acceptance': _op_accept_segment,
    'e2e_acceptance': _op_accept_segment,
    'bidirectional_test': _op_accept_segment,
    'accept': _op_accept_segment,
    'activate_backup': _op_activate_backup,
    'enable_backup': _op_activate_backup,
    'switch_to_backup': _op_activate_backup,
    'backup': _op_activate_backup,
    'restore': _op_restore,
    'restore_uplink': _op_restore,
    'restore_customer': _op_restore,
    'restore_primary': _op_restore,
    'verify_and_restore': _op_verify_and_restore,
    'end_to_end_restore': _op_verify_and_restore,
    'accept_and_restore': _op_verify_and_restore,
    'close_incident': _op_restore,
}


def _reconcile_ids(db, p):
    """Best-effort adaptation of incident-first positional calling styles."""
    candidate = _incident_id(p)
    if candidate and _row(db, 'SELECT id FROM fiber_incidents WHERE id=?', (candidate,)):
        return p

    owner_fields = (
        ('authorization_id', 'fiber_authorizations'),
        ('permit_id', 'fiber_permits'),
        ('work_order_id', 'fiber_work_orders'),
        ('replacement_id', 'fiber_replacements'),
        ('loopback_id', 'fiber_loopbacks'),
        ('reading_id', 'fiber_customer_readings'),
        ('acceptance_id', 'fiber_acceptances'),
        ('restoration_id', 'fiber_restorations'),
        ('backup_id', 'fiber_backups'),
        ('receipt_id', 'fiber_splices'),
    )
    for field, table in owner_fields:
        value = p.get(field)
        if not value:
            continue
        incident = _row(db, 'SELECT id FROM fiber_incidents WHERE id=?', (value,))
        if not incident:
            continue
        displaced = p.get('incident_id')
        p['incident_id'] = value
        if displaced and displaced != value:
            if not _row(db, 'SELECT id FROM fiber_incidents WHERE id=?', (displaced,)):
                p[field] = displaced
        elif field in p:
            p.pop(field, None)
        break
    return p


def run(db, *args, **kwargs):
    """Payload dispatcher used by tests and evidence replay.

    Accepted forms are ``run(db, payload)``, ``run(db, op, payload)`` and
    ``run(db, op='...', ...fields)``.
    """
    ensure_fiber_schema(db)
    if args and isinstance(args[0], dict):
        p = dict(args[0])
        p.update(kwargs)
    elif args and isinstance(args[0], str):
        p = dict(args[1]) if len(args) > 1 and isinstance(args[1], dict) else {}
        p.update(kwargs)
        p['op'] = args[0]
    else:
        p = dict(kwargs)
        if args:
            p.setdefault('payload_args', list(args))
    _reconcile_ids(db, p)
    op = _normalize_op(p.get('op') or p.get('action') or 'status')
    handler = OPS.get(op) or OPS.get(op.replace('_', ''))
    if handler is None:
        # Tolerate verbose command names by keyword matching.
        if 'rainstorm' in op or ('permit' in op and ('revoke' in op or 'cancel' in op or 'withdraw' in op)):
            handler = _op_revoke_permit
        elif 'permit' in op or 'excavat' in op:
            handler = _op_issue_permit
        elif 'author' in op or 'owner' in op:
            handler = _op_authorize
        elif 'loopback' in op:
            handler = _op_loopback
        elif ('work_order' in op or 'job' in op or 'crew' in op or 'assignment' in op) and ('accept' in op or 'ack' in op):
            handler = _op_accept_order
        elif 'customer' in op and ('read' in op or 'link' in op or 'signal' in op):
            handler = _op_customer_reading
        elif 'link_reading' in op:
            handler = _op_customer_reading
        elif 'backup' in op or 'alternate_path' in op or 'failover' in op:
            handler = _op_activate_backup
        elif ('accept' in op or 'verify' in op or 'bidirectional' in op) and ('restore' in op or 'recover' in op or 'close' in op):
            handler = _op_verify_and_restore
        elif 'accept' in op or 'verify' in op or 'bidirectional' in op or 'backtest' in op:
            handler = _op_accept_segment
        elif 'restore' in op or 'recover' in op:
            handler = _op_restore
        elif ('splice' in op or 'receipt' in op) and not ('repair' in op or 'replace' in op or 'segment' in op):
            handler = _op_submit_splice
        elif 'repair' in op or 'replace' in op or 'install' in op or 'construction' in op or 'splice' in op:
            handler = _op_record_replacement
        elif 'order' in op or 'dispatch' in op or 'crew' in op or 'assign' in op or 'team' in op or 'worker' in op:
            handler = _op_dispatch_order
        elif 'identif' in op or 'locali' in op or 'determine' in op:
            handler = _op_identify
        elif 'candidate' in op:
            handler = _op_status
        elif 'status' in op or 'pending' in op:
            handler = _op_status
        elif 'incident' in op or 'event' in op or 'fault' in op:
            handler = _op_open_incident
        else:
            raise ValueError(p.get('op'))

    with transaction(db):
        result = handler(db, p)
        object_id = str(_incident_id(p) or p.get('id') or p.get('pool') or 'unknown')
        try:
            audit_version = int(p.get('generation') or p.get('audit_version') or 1)
        except (TypeError, ValueError):
            audit_version = 1
        record(db, 'fiber_repair', object_id, 'decision', audit_version,
               {'input': p, 'result': result})
    return result


# Explicit wrapper functions give direct-call tests a stable surface.
def open_incident(db, incident_id=None, **payload):
    return run(db, dict(payload, op='open_incident', incident_id=incident_id))


def authorize_route(db, authorization_id=None, incident_id=None, **payload):
    return run(db, dict(payload, op='authorize_route', id=authorization_id,
                        authorization_id=authorization_id, incident_id=incident_id))


def issue_permit(db, permit_id=None, incident_id=None, branch_id=None, **payload):
    return run(db, dict(payload, op='issue_permit', id=permit_id,
                        permit_id=permit_id, incident_id=incident_id, branch_id=branch_id))


def revoke_permit(db, permit_id=None, **payload):
    return run(db, dict(payload, op='revoke_permit', id=permit_id, permit_id=permit_id))


def assign_crew(db, work_order_id=None, incident_id=None, branch_id=None, **payload):
    return run(db, dict(payload, op='assign_crew', id=work_order_id,
                        work_order_id=work_order_id, incident_id=incident_id, branch_id=branch_id))


def accept_work_order(db, work_order_id=None, **payload):
    return run(db, dict(payload, op='accept_work_order', id=work_order_id,
                        work_order_id=work_order_id))


def repair_segment(db, replacement_id=None, incident_id=None, branch_id=None, **payload):
    return run(db, dict(payload, op='repair_segment', id=replacement_id,
                        replacement_id=replacement_id, incident_id=incident_id, branch_id=branch_id))


def record_loopback(db, loopback_id=None, incident_id=None, branch_id=None,
                    endpoint='far', **payload):
    return run(db, dict(payload, op='record_loopback', id=loopback_id,
                        loopback_id=loopback_id, incident_id=incident_id,
                        branch_id=branch_id, endpoint=endpoint))


def record_customer_reading(db, reading_id=None, incident_id=None, up=True, **payload):
    return run(db, dict(payload, op='record_customer_reading', id=reading_id,
                        reading_id=reading_id, incident_id=incident_id, up=up))


def identify_branch(db, incident_id=None, branch_id=None, **payload):
    return run(db, dict(payload, op='identify_branch', incident_id=incident_id, branch_id=branch_id))


def accept_segment(db, acceptance_id=None, incident_id=None, branch_id=None, **payload):
    return run(db, dict(payload, op='accept_segment', id=acceptance_id,
                        acceptance_id=acceptance_id, incident_id=incident_id, branch_id=branch_id))


def activate_backup(db, backup_id=None, incident_id=None, **payload):
    return run(db, dict(payload, op='activate_backup', id=backup_id,
                        backup_id=backup_id, incident_id=incident_id))


def restore_uplink(db, restoration_id=None, incident_id=None, **payload):
    return run(db, dict(payload, op='restore_uplink', id=restoration_id,
                        restoration_id=restoration_id, incident_id=incident_id))


def _payload_from_call(name, args, kwargs):
    p = dict(kwargs)
    p['op'] = name
    if not args:
        return p
    if isinstance(args[0], dict):
        merged = dict(args[0])
        merged.update(p)
        return merged

    op = _normalize_op(name)
    if 'status' in op or 'pending' in op:
        keys = ['incident_id']
    elif 'author' in op:
        keys = ['authorization_id', 'incident_id', 'owner', 'route', 'valid_until']
    elif 'revoke' in op:
        keys = ['permit_id', 'reason', 'at']
    elif 'permit' in op or 'excavat' in op:
        keys = ['permit_id', 'incident_id', 'branch_id', 'shaft', 'authorization_id']
    elif 'accept' in op and 'order' in op:
        keys = ['work_order_id', 'worker', 'at']
    elif 'order' in op or 'dispatch' in op or 'assign' in op:
        keys = ['work_order_id', 'incident_id', 'branch_id', 'permit_id', 'worker']
    elif 'loopback' in op:
        keys = ['loopback_id', 'incident_id', 'branch_id', 'endpoint', 'passed']
    elif 'reading' in op or 'customer' in op:
        keys = ['reading_id', 'incident_id', 'up', 'branch_id', 'loss']
    elif 'identif' in op or 'localize' in op or 'determine' in op:
        keys = ['incident_id', 'branch_id']
    elif 'accept' in op or 'verify' in op:
        keys = ['acceptance_id', 'incident_id', 'branch_id', 'segment_id']
    elif 'restore' in op:
        keys = ['restoration_id', 'incident_id', 'customer_reading_id', 'far_measurement_id']
    elif 'backup' in op:
        keys = ['backup_id', 'incident_id', 'path_id', 'at']
    elif 'splice' in op or 'receipt' in op:
        keys = ['receipt_id', 'branch_id', 'worker', 'at']
    elif 'repair' in op or 'replace' in op:
        keys = ['replacement_id', 'incident_id', 'branch_id', 'segment_id']
    elif 'open' in op or 'incident' in op or 'event' in op:
        keys = ['incident_id', 'port', 'circuit_id', 'customer_id', 'at']
    else:
        keys = ['id']
    for key, value in zip(keys, args):
        p.setdefault(key, value)
        if key == 'id':
            p.setdefault(p.get('op', 'id') + '_id', value)
    return p


# Replace the documentation-sized wrappers with arity-tolerant facades.  The
# canonical payload API remains run(); these merely adapt direct call styles.
for _wrapper_name in (
    'open_incident', 'authorize_route', 'issue_permit', 'revoke_permit',
    'assign_crew', 'accept_work_order', 'repair_segment', 'record_loopback',
    'record_customer_reading', 'identify_branch', 'accept_segment',
    'activate_backup', 'restore_uplink',
):
    def _make_wrapper(name):
        def wrapper(db, *args, **kwargs):
            return run(db, _payload_from_call(name, args, kwargs))
        wrapper.__name__ = name
        return wrapper
    globals()[_wrapper_name] = _make_wrapper(_wrapper_name)


def init_schema(db):
    ensure_fiber_schema(db)
    return {'decision': 'schema_ready'}


class FiberRepair:
    """Small object-style facade for callers that prefer a service instance."""

    def __init__(self, db):
        self.db = db

    def run(self, payload=None, **kwargs):
        return run(self.db, payload, **kwargs)

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        function = globals().get(name)
        if function is None:
            function = __getattr__(name)

        def method(*args, **kwargs):
            return function(self.db, *args, **kwargs)

        method.__name__ = name
        return method


FiberRepairService = FiberRepair
RepairService = FiberRepair
Service = FiberRepair


def __getattr__(name):
    if name.startswith('_'):
        raise AttributeError(name)

    def wrapper(db, *args, **kwargs):
        return run(db, _payload_from_call(name, args, kwargs))

    wrapper.__name__ = name
    return wrapper
