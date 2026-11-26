from .store import transaction, record, audit_run, ensure_schema


def _claim_id(x):
    return x.get('id') or x.get('claim_id') or x.get('claim')


def run(db, x):
    ensure_schema(db)
    return _audited_run(db, x)


@audit_run('warranty')
def _audited_run(db, x):
    with transaction(db):
        op = x.get('op', 'open_claim')
        if op in ('open_claim', 'open', 'file_claim'):
            claim_id = _claim_id(x)
            x.setdefault('id', claim_id)
            return _open_claim(
                db,
                claim_id,
                x.get('transition') or x.get('transition_id') or x.get('fault'),
                x.get('vendor'),
                x,
            )
        raise ValueError(op)


def open_claim(db, claim_id, transition, vendor, **options):
    ensure_schema(db)
    payload = {'op': 'open_claim', 'id': claim_id,
               'transition': transition, 'vendor': vendor}
    payload.update(options)
    return _audited_run(db, payload)


def _open_claim(db, claim_id, transition, vendor, options=None):
    options = options or {}
    if not claim_id or not transition or not vendor:
        return {'decision': 'blocked', 'reason': 'incomplete_claim'}

    old = db.execute('SELECT transition_id,vendor,fault_key FROM warranty_claims WHERE id=?',
                     (claim_id,)).fetchone()
    if old:
        if old['transition_id'] == transition and old['vendor'] == vendor:
            return {'decision': 'replay'}
        return {'decision': 'claim_conflict'}

    # The transition/fault is the natural economic uniqueness key. A caller
    # supplied label must not be able to split one fault into two entitlements.
    fault_key = transition
    duplicate = db.execute(
        'SELECT id,vendor FROM warranty_claims WHERE transition_id=? AND id<>?',
        (transition, claim_id),
    ).fetchone()
    if duplicate:
        return {
            'decision': 'claim_conflict',
            'reason': 'duplicate_fault',
            'existing_claim': duplicate['id'],
        }

    failed = db.execute(
        'SELECT 1 FROM transition_probes WHERE transition_id=? AND healthy=0 LIMIT 1',
        (transition,),
    ).fetchone()
    if not failed:
        return {'decision': 'blocked', 'reason': 'no_failed_probe'}

    db.execute(
        """INSERT INTO warranty_claims
           (id,transition_id,vendor,state,fault_key,buyer,created_at)
           VALUES(?,?,?,'draft',?,?,?)""",
        (claim_id, transition, vendor, fault_key,
         options.get('buyer') or options.get('purchaser'),
         options.get('now') or options.get('created_at')),
    )
    record(db, 'warranty', claim_id, 'open', 1,
           {'transition': transition, 'vendor': vendor, 'fault_key': fault_key})
    return {'decision': 'draft'}


def __getattr__(name):
    # Compatibility facade: resolution workflows live in their own module, but
    # callers may naturally import them from cloudlab.warranty.
    if name.startswith('__') and name.endswith('__'):
        raise AttributeError(name)
    from . import warranty_resolution
    if hasattr(warranty_resolution, name):
        return getattr(warranty_resolution, name)
    raise AttributeError(name)
