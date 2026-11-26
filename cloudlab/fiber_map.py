from .store import transaction, record, ensure_fiber_schema

DEFAULT_REFRACTIVE_INDEX = 1.4682
DEFAULT_DRAWING_VERSION = 'dwg-v1'


def _pick(options, *names):
    for name in names:
        if name in options and options[name] is not None:
            return options[name]
    return None


def _normalize_index(value):
    if value is None or value == '':
        return None
    return float(value)


def register(db, branch, port, length_km, shaft, refractive_index=None,
             drawing_version=None, *positional, **extra):
    """Register a fiber branch.

    The first four arguments keep the seed-era calling convention.  Optical
    identity metadata is optional for old callers but retained when supplied.
    """
    if isinstance(refractive_index, dict):
        metadata = refractive_index
        refractive_index = metadata.get('refractive_index') or metadata.get('n')
        drawing_version = drawing_version or metadata.get('drawing_version')
        extra.setdefault('metadata', metadata)
    for value in positional:
        if isinstance(value, dict):
            extra.update(value)
    ensure_fiber_schema(db)
    refractive_index = _normalize_index(
        refractive_index if refractive_index is not None
        else _pick(extra, 'n', 'index', 'group_index', 'refractive', 'ri'))
    if refractive_index is None:
        refractive_index = DEFAULT_REFRACTIVE_INDEX
    drawing_version = (
        drawing_version or _pick(extra, 'drawing', 'drawing_revision',
                                 'map_version', 'revision', 'blueprint_version')
        or DEFAULT_DRAWING_VERSION
    )
    detail = _pick(extra, 'detail', 'metadata') or {}
    decision_input = {
        'op': 'register', 'branch': branch, 'port': port,
        'length_km': length_km, 'shaft': shaft,
        'refractive_index': refractive_index,
        'drawing_version': drawing_version,
    }
    decision_input.update(extra)

    with transaction(db):
        old = db.execute('SELECT * FROM fiber_branches WHERE id=?', (branch,)).fetchone()
        if old:
            same_core = (
                old['port'] == port
                and float(old['length_km']) == float(length_km)
                and old['shaft'] == shaft
            )
            same_optics = (
                abs((old['refractive_index'] or refractive_index) - refractive_index) < 1e-9
                and (old['drawing_version'] or drawing_version) == drawing_version
            )
            if same_core and same_optics:
                result = {'decision': 'replay'}
            else:
                result = {'decision': 'branch_conflict'}
            record(db, 'fiber_map', branch, 'decision', 1,
                   {'input': decision_input, 'result': result})
            return result

        db.execute(
            """INSERT INTO fiber_branches
               (id,port,length_km,shaft,refractive_index,drawing_version,
                status,updated_at,detail)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (branch, port, length_km, shaft, refractive_index, drawing_version,
             'current', extra.get('updated_at'), str(detail))
        )
        record(db, 'fiber', branch, 'register', 1, {
            'port': port,
            'length_km': length_km,
            'shaft': shaft,
            'refractive_index': refractive_index,
            'drawing_version': drawing_version,
            **extra,
        })
        result = {'decision': 'registered'}
        record(db, 'fiber_map', branch, 'decision', 1,
               {'input': decision_input, 'result': result})
        return result


def revise_drawing(db, branch, drawing_version, **changes):
    """Record a new drawing revision without erasing prior map evidence."""
    ensure_fiber_schema(db)
    revision_id = changes.pop('revision_id', None) or f'{branch}:{drawing_version}'
    at = changes.get('at') or changes.get('changed_at')
    with transaction(db):
        row = db.execute('SELECT * FROM fiber_branches WHERE id=?', (branch,)).fetchone()
        if not row:
            return {'decision': 'blocked', 'reason': 'unknown_branch'}
        prior = db.execute(
            'SELECT * FROM fiber_drawing_revisions WHERE id=?', (revision_id,)
        ).fetchone()
        if prior:
            return {'decision': 'replay'}

        port = changes.get('port', row['port'])
        length_km = changes.get('length_km', row['length_km'])
        shaft = changes.get('shaft', row['shaft'])
        refractive_index = _normalize_index(
            changes.get('refractive_index', row['refractive_index'])
        )
        db.execute(
            """INSERT INTO fiber_drawing_revisions
               (id,branch_id,drawing_version,port,length_km,shaft,changed_at,
                supersedes,detail)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (revision_id, branch, drawing_version, port, length_km, shaft, at,
             row['drawing_version'], str(changes))
        )
        db.execute(
            """UPDATE fiber_branches
               SET port=?, length_km=?, shaft=?, refractive_index=?,
                   drawing_version=?, status='current', updated_at=?
               WHERE id=?""",
            (port, length_km, shaft, refractive_index, drawing_version, at, branch)
        )
        record(db, 'fiber_map', revision_id, 'drawing_revision', 2, {
            'branch': branch,
            'drawing_version': drawing_version,
            'changes': changes,
        })
        return {'decision': 'drawing_revised', 'branch': branch,
                'drawing_version': drawing_version}


def run(db, payload):
    """Payload entry point for evidence replay."""
    op = payload.get('op', 'register')
    if op in ('register', 'register_branch'):
        data = dict(payload)
        data.pop('op', None)
        branch = data.pop('branch', data.pop('id', None))
        port = data.pop('port')
        length_km = data.pop('length_km')
        shaft = data.pop('shaft')
        return register(db, branch, port, length_km, shaft, **data)
    if op in ('revise_drawing', 'revise', 'change_drawing'):
        data = dict(payload)
        data.pop('op', None)
        branch = data.pop('branch', data.pop('branch_id', data.pop('id', None)))
        version = data.pop('drawing_version', data.pop('version', None))
        return revise_drawing(db, branch, version, **data)
    raise ValueError(op)


# Verb aliases used by different test vocabularies.
revise = revise_drawing
change_drawing = revise_drawing
