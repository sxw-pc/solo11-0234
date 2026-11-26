import json

from .store import transaction, record, ensure_fiber_schema


def _first(options, *names):
    for name in names:
        if name in options and options[name] is not None:
            return options[name]
    return None


def _truthy(value):
    if isinstance(value, str):
        return value.strip().lower() in {'1', 'true', 'yes', 'y', 'valid', 'ok', 'pass', 'passed'}
    return bool(value)


def normalize_direction(value):
    text = _normalize_simple(value)
    reverse_tokens = ('reverse', 'reversed', 'backward', 'back', 'z_to_a',
                      'far_to_near', 'remote_to_local', 'rtl', 'upstream')
    forward_tokens = ('forward', 'fwd', 'normal', 'a_to_z', 'near_to_far',
                      'local_to_remote', 'ltr', 'downstream')
    if text in {'reverse', 'reversed', 'backward', 'back', 'z_to_a', 'far_to_near', 'rtl'}:
        return 'reverse'
    if any(token in text for token in reverse_tokens):
        return 'reverse'
    if any(token in text for token in forward_tokens):
        return 'forward'
    return 'forward'


def _normalize_simple(value):
    text = str(value or 'forward').strip().lower().replace('-', '_').replace(' ', '_')
    while '__' in text:
        text = text.replace('__', '_')
    return text


def normalize_endpoint(value):
    text = _normalize_simple(value or 'far')
    if any(token in text for token in ('far', 'remote', 'z_end', 'z_side', 'z')):
        return 'far'
    if any(token in text for token in ('near', 'local', 'a_end', 'a_side')) or text == 'a':
        return 'near'
    return text


def calibration_facts(payload, measured_at=None):
    """Return (calibration_id, meter_id, valid, due).

    Unknown calibration is represented by valid=None.  Explicit invalid/expired
    evidence is represented by valid=0 so downstream acceptance can reject it.
    """
    calibration = payload.get('calibration')
    cal_id = _first(payload, 'calibration_id', 'cal_id')
    meter_id = _first(payload, 'meter_id', 'otdr_id', 'instrument_id')
    due = _first(payload, 'calibration_due', 'calibration_valid_until',
                 'cal_valid_until', 'valid_until', 'calibration_expires_at')
    valid = _first(payload, 'calibration_valid', 'calibrated', 'meter_calibrated',
                   'calibration_ok', 'valid_calibration')

    if isinstance(calibration, dict):
        cal_id = cal_id or calibration.get('id') or calibration.get('calibration_id')
        meter_id = meter_id or calibration.get('meter_id')
        due = due or calibration.get('valid_until') or calibration.get('due') or calibration.get('expires_at')
        if valid is None:
            valid = calibration.get('valid', calibration.get('calibrated'))
        status = str(calibration.get('status', '')).lower()
        if status in {'invalid', 'expired', 'failed', 'uncalibrated', 'revoked'}:
            valid = False
        elif status in {'valid', 'calibrated', 'current', 'ok'} and valid is None:
            valid = True
    elif isinstance(calibration, str):
        cal_id = cal_id or calibration
        if calibration.strip().lower() in {'invalid', 'expired', 'uncalibrated', 'failed'}:
            valid = False

    if valid is None and due is not None and measured_at is not None:
        valid = measured_at <= due
    elif valid is not None:
        valid = _truthy(valid)

    if valid is False:
        valid_db = 0
    elif valid is True:
        valid_db = 1
    else:
        valid_db = None
    return cal_id, meter_id, valid_db, due


def distance_candidates(db, port, distance_km, tolerance=0.01):
    ensure_fiber_schema(db)
    return [
        r['id'] for r in db.execute(
            """SELECT id FROM fiber_branches
               WHERE port=? AND ABS(CAST(length_km AS REAL)-CAST(? AS REAL))<=?
               ORDER BY id""",
            (port, distance_km, tolerance)
        )
    ]


def _merge_observe_positionals(positional, options):
    for value in positional:
        if isinstance(value, dict):
            merged = dict(value)
            merged.update(options)
            options = merged
            continue
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            if 0.5 < float(value) < 2.5:
                options.setdefault('refractive_index', value)
            else:
                options.setdefault('at', value)
            continue
        text = str(value)
        normalized = normalize_direction(text)
        if _normalize_simple(text) in {
            'forward', 'fwd', 'reverse', 'reversed', 'backward', 'back',
            'z_to_a', 'far_to_near', 'rtl',
        }:
            options.setdefault('direction', normalized)
        elif any(token in text.lower() for token in ('dwg', 'drawing', 'revision', 'blueprint', 'map_version')):
            options.setdefault('drawing_version', text)
        elif 'cal' in text.lower():
            options.setdefault('calibration_id', text)
        else:
            options.setdefault('splitter_port', text)
    return options


def observe(db, trace_id, port, distance_km, loss, *positional, **options):
    options = _merge_observe_positionals(positional, options)
    ensure_fiber_schema(db)
    direction = normalize_direction(_first(options, 'direction', 'orientation') or 'forward')
    measured_at = _first(options, 'at', 'measured_at', 'observed_at', 'time')
    cal_id, meter_id, cal_valid, cal_due = calibration_facts(options, measured_at)
    refractive_index = _first(options, 'refractive_index', 'index', 'n', 'group_index', 'ri')
    if refractive_index is not None:
        refractive_index = float(refractive_index)
    drawing_version = _first(options, 'drawing_version', 'drawing', 'map_version', 'revision')
    splitter_port = _first(options, 'splitter_port', 'split_port', 'p_port') or port
    branch_id = _first(options, 'branch', 'branch_id', 'candidate')
    segment_id = _first(options, 'segment', 'segment_id')
    incident_id = _first(options, 'incident', 'incident_id', 'event_id', 'fault_id')
    endpoint = _first(options, 'endpoint', 'end', 'side')
    independent = _first(options, 'independent', 'independently_measured')
    observer = _first(options, 'observer', 'tester', 'technician', 'source')
    raw = json.dumps(options, ensure_ascii=False, sort_keys=True, default=str)
    decision_input = {
        'op': 'observe', 'trace_id': trace_id, 'port': port,
        'distance_km': distance_km, 'loss': loss,
    }
    decision_input.update(options)

    with transaction(db):
        old = db.execute('SELECT port,distance_km,loss,direction,refractive_index,drawing_version FROM fiber_traces WHERE id=?',
                         (trace_id,)).fetchone()
        if old:
            same_core = (
                old['port'] == port
                and float(old['distance_km']) == float(distance_km)
                and float(old['loss']) == float(loss)
            )
            same_meta = (
                old['direction'] == direction
                and (old['refractive_index'] is None or refractive_index is None
                     or abs(old['refractive_index'] - refractive_index) < 1e-9)
                and (old['drawing_version'] is None or drawing_version is None
                     or old['drawing_version'] == drawing_version)
            )
            if same_core and same_meta:
                result = {'decision': 'replay'}
            else:
                result = {'decision': 'trace_conflict'}
            record(db, 'fiber_trace', trace_id, 'decision', 1,
                   {'input': decision_input, 'result': result})
            return result

        db.execute(
            """INSERT INTO fiber_traces
               (id,port,distance_km,loss,direction,splitter_port,refractive_index,
                drawing_version,branch_id,segment_id,incident_id,endpoint,measured_at,
                meter_id,calibration_id,calibration_valid,calibration_due,independent,
                observer,raw_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (trace_id, port, distance_km, loss, direction, splitter_port,
             refractive_index, drawing_version, branch_id, segment_id, incident_id,
             endpoint, measured_at, meter_id, cal_id, cal_valid, cal_due,
             None if independent is None else int(bool(independent)), observer, raw)
        )
        record(db, 'fiber', trace_id, 'observe', 1, {
            'port': port,
            'distance_km': distance_km,
            'loss': loss,
            'direction': direction,
            'splitter_port': splitter_port,
            'refractive_index': refractive_index,
            'drawing_version': drawing_version,
            'calibration_id': cal_id,
            'calibration_valid': cal_valid,
            'branch_id': branch_id,
            'segment_id': segment_id,
            'incident_id': incident_id,
            'at': measured_at,
        })
        candidates = distance_candidates(db, splitter_port or port, distance_km)
        result = {'decision': 'observed', 'candidates': candidates,
                  'ambiguous': len(candidates) > 1, 'direction': direction}
        if cal_valid == 0:
            result['calibration_valid'] = False
            result['usable'] = False
        record(db, 'fiber_trace', trace_id, 'decision', 1,
               {'input': decision_input, 'result': result})
        return result


def run(db, payload):
    """Payload entry point for evidence replay."""
    data = dict(payload)
    op = data.pop('op', 'observe')
    if op in ('observe', 'record_trace', 'measure'):
        trace_id = data.pop('trace_id', data.pop('id', None))
        port = data.pop('port')
        distance_km = data.pop('distance_km', data.pop('distance', None))
        loss = data.pop('loss')
        return observe(db, trace_id, port, distance_km, loss, **data)
    if op == 'candidates':
        return {'decision': 'candidates',
                'candidates': distance_candidates(db, data['port'], data['distance_km'])}
    raise ValueError(op)


# Descriptive aliases.
record_trace = observe
measure = observe
candidates = distance_candidates
