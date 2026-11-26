import json

from .store import transaction, record, ensure_fiber_schema


def submit(db, receipt_id, branch, worker, *positional, _audit_decision=True, **options):
    """Receive a crew splice receipt."""
    for value in positional:
        if isinstance(value, dict):
            merged = dict(value)
            merged.update(options)
            options = merged
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            options.setdefault('at', value)
        elif isinstance(value, str):
            lowered = value.lower()
            if lowered.startswith(('pm', 'permit')) or 'permit' in lowered:
                options.setdefault('permit_id', value)
            elif lowered.startswith(('wo', 'order', 'ticket')) or 'order' in lowered:
                options.setdefault('work_order_id', value)
            else:
                options.setdefault('note', value)
    ensure_fiber_schema(db)
    incident_id = options.get('incident_id') or options.get('incident') or options.get('event_id')
    permit_id = options.get('permit_id') or options.get('permit')
    work_order_id = options.get('work_order_id') or options.get('order_id') or options.get('ticket_id')
    segment_id = options.get('segment_id') or options.get('segment')
    receipt_at = options.get('at') or options.get('receipt_at') or options.get('performed_at')
    decision_input = {'op': 'submit', 'receipt_id': receipt_id,
                      'branch': branch, 'worker': worker}
    decision_input.update(options)

    with transaction(db):
        old = db.execute('SELECT branch,worker FROM fiber_splices WHERE id=?', (receipt_id,)).fetchone()
        if old:
            if (old['branch'], old['worker']) == (branch, worker):
                result = {'decision': 'replay'}
            else:
                result = {'decision': 'splice_conflict'}
            if _audit_decision:
                record(db, 'fiber_splice', receipt_id, 'decision', 1,
                       {'input': decision_input, 'result': result})
            return result

        if not db.execute('SELECT 1 FROM fiber_branches WHERE id=?', (branch,)).fetchone():
            result = {'decision': 'unknown_branch'}
            if _audit_decision:
                record(db, 'fiber_splice', receipt_id, 'decision', 1,
                       {'input': decision_input, 'result': result})
            return result

        auth_state = 'unlinked'
        authorized = False
        permit = None
        if permit_id:
            permit = db.execute('SELECT * FROM fiber_permits WHERE id=?', (permit_id,)).fetchone()
            if not permit:
                auth_state = 'unknown_permit'
            elif permit['branch_id'] not in (None, branch):
                auth_state = 'wrong_branch_permit'
            elif permit['status'] != 'valid':
                auth_state = f'permit_{permit["status"]}'
            elif permit['valid_until'] is not None and receipt_at is not None and receipt_at > permit['valid_until']:
                auth_state = 'permit_expired'
            else:
                auth_state = 'permit_linked'
                authorized = True

        if work_order_id:
            order = db.execute('SELECT * FROM fiber_work_orders WHERE id=?', (work_order_id,)).fetchone()
            if not order:
                auth_state = 'unknown_work_order'
                authorized = False
            elif order['branch_id'] != branch:
                auth_state = 'wrong_branch_work_order'
                authorized = False
            elif order['status'] not in ('accepted', 'in_progress', 'completed'):
                auth_state = f'work_order_{order["status"]}'
                authorized = False
            else:
                auth_state = 'work_order_linked' if auth_state == 'unlinked' else auth_state
                authorized = authorized or (permit_id is None)

        db.execute(
            """INSERT INTO fiber_splices
               (id,branch,worker,incident_id,permit_id,work_order_id,segment_id,
                receipt_at,authorization_state,payload_json)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (receipt_id, branch, worker, incident_id, permit_id, work_order_id,
             segment_id, receipt_at, auth_state,
             json.dumps(options, ensure_ascii=False, sort_keys=True, default=str))
        )
        record(db, 'fiber', receipt_id, 'splice', 1, {
            'branch': branch,
            'worker': worker,
            'incident_id': incident_id,
            'permit_id': permit_id,
            'work_order_id': work_order_id,
            'segment_id': segment_id,
            'at': receipt_at,
            'authorization_state': auth_state,
        })
        result = {'decision': 'received', 'receipt_id': receipt_id,
                  'branch': branch, 'accepted_as_verification': False,
                  'authorization_state': auth_state}
        if not authorized and (permit_id or work_order_id):
            result['authorized'] = False
            result['reason'] = auth_state
        else:
            result['authorized'] = authorized if (permit_id or work_order_id) else None
        if _audit_decision:
            record(db, 'fiber_splice', receipt_id, 'decision', 1,
                   {'input': decision_input, 'result': result})
        return result


def run(db, payload):
    """Payload entry point for evidence replay."""
    data = dict(payload)
    op = data.pop('op', 'submit')
    if op in ('submit', 'receive'):
        receipt_id = data.pop('receipt_id', data.pop('id', None))
        branch = data.pop('branch', data.pop('branch_id', None))
        worker = data.pop('worker', data.pop('crew', None))
        return submit(db, receipt_id, branch, worker, **data)
    raise ValueError(op)


# Common alias.
receive = submit
