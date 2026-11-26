import hashlib
import json
import sqlite3
import threading
from contextlib import contextmanager


LEGAL_SCHEMA = """
CREATE TABLE IF NOT EXISTS trusted_authorities(
    issuer TEXT PRIMARY KEY,
    secret TEXT NOT NULL,
    authority_name TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    registered_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS legal_orders(
    order_id TEXT PRIMARY KEY,
    command_id TEXT UNIQUE,
    issuer TEXT NOT NULL,
    authority TEXT,
    target_customer TEXT NOT NULL,
    service TEXT NOT NULL,
    window_start INTEGER,
    window_end INTEGER,
    allowed_fields TEXT NOT NULL,
    case_ref TEXT,
    recipient TEXT,
    terms TEXT NOT NULL DEFAULT '{}',
    issued_at INTEGER NOT NULL DEFAULT 0,
    valid_from INTEGER NOT NULL DEFAULT 0,
    valid_until INTEGER NOT NULL DEFAULT 0,
    order_bytes BLOB NOT NULL,
    order_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    signer_key_id TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS order_revocations(
    revocation_id TEXT PRIMARY KEY,
    command_id TEXT UNIQUE,
    order_id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    at INTEGER NOT NULL,
    reason TEXT,
    revocation_bytes BLOB NOT NULL,
    revocation_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS customer_attributions(
    mapping_id TEXT PRIMARY KEY,
    command_id TEXT UNIQUE,
    customer_id TEXT NOT NULL,
    service_id TEXT,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    evidence_id INTEGER,
    source TEXT,
    basis TEXT,
    mapped_at INTEGER NOT NULL DEFAULT 0,
    received_at INTEGER NOT NULL DEFAULT 0,
    recorded_at INTEGER NOT NULL DEFAULT 0,
    signed_by TEXT,
    signature TEXT,
    detail TEXT NOT NULL DEFAULT '{}',
    mapping_bytes BLOB,
    mapping_hash TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    supersedes TEXT
);
CREATE INDEX IF NOT EXISTS idx_customer_subject ON customer_attributions(subject_type,subject_id,status);
CREATE TABLE IF NOT EXISTS maintenance_receipts(
    receipt_id TEXT PRIMARY KEY,
    command_id TEXT UNIQUE,
    provider TEXT,
    ticket_id TEXT,
    subject_type TEXT,
    subject_id TEXT,
    node_id TEXT,
    wave_id TEXT,
    transition_id TEXT,
    migration_id TEXT,
    service TEXT,
    at INTEGER,
    received_at INTEGER NOT NULL DEFAULT 0,
    outcome TEXT,
    zone TEXT,
    location TEXT,
    detail TEXT NOT NULL DEFAULT '{}',
    receipt_bytes BLOB NOT NULL,
    receipt_hash TEXT NOT NULL,
    signature TEXT
);
CREATE TABLE IF NOT EXISTS evidence_artifacts(
    artifact_id TEXT PRIMARY KEY,
    command_id TEXT UNIQUE,
    idempotency_key TEXT UNIQUE,
    order_id TEXT,
    kind TEXT NOT NULL,
    channel TEXT NOT NULL,
    recipient TEXT NOT NULL,
    audience TEXT,
    query_rights TEXT NOT NULL DEFAULT '[]',
    revision INTEGER NOT NULL DEFAULT 1,
    revision_kind TEXT NOT NULL DEFAULT 'original',
    parent_artifact_id TEXT,
    source_artifact_id TEXT,
    scope TEXT NOT NULL DEFAULT '{}',
    document TEXT NOT NULL DEFAULT '{}',
    artifact_bytes BLOB NOT NULL,
    artifact_hash TEXT NOT NULL,
    platform_key_id TEXT,
    platform_signature TEXT,
    custodian_id TEXT,
    custodian_key_id TEXT,
    custodian_signature TEXT,
    custodian_attestation TEXT NOT NULL DEFAULT '{}',
    evidence_root TEXT,
    evidence_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'issued',
    output_path TEXT,
    created_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_artifact_order ON evidence_artifacts(order_id,revision);
CREATE TABLE IF NOT EXISTS delivery_receipts(
    receipt_id TEXT PRIMARY KEY,
    command_id TEXT UNIQUE,
    artifact_id TEXT NOT NULL,
    order_id TEXT,
    recipient TEXT NOT NULL,
    status TEXT NOT NULL,
    received_by TEXT,
    at INTEGER NOT NULL DEFAULT 0,
    detail TEXT NOT NULL DEFAULT '{}',
    receipt_bytes BLOB NOT NULL,
    receipt_hash TEXT NOT NULL,
    signature TEXT
);
CREATE INDEX IF NOT EXISTS idx_delivery_artifact ON delivery_receipts(artifact_id,at);
CREATE TABLE IF NOT EXISTS publication_scopes(
    scope_id TEXT PRIMARY KEY,
    command_id TEXT UNIQUE,
    artifact_id TEXT,
    order_id TEXT,
    service TEXT NOT NULL,
    window_start INTEGER,
    window_end INTEGER,
    requested_start INTEGER,
    requested_end INTEGER,
    granularity TEXT,
    min_group_size INTEGER NOT NULL DEFAULT 2,
    group_size INTEGER,
    event_count INTEGER NOT NULL DEFAULT 0,
    scope_hash TEXT NOT NULL,
    published_at INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_publication_service_window ON publication_scopes(service,window_start,window_end);
CREATE TRIGGER IF NOT EXISTS publication_scopes_immutable_update
BEFORE UPDATE ON publication_scopes
BEGIN
    SELECT CASE
        WHEN OLD.scope_hash IS NOT NEW.scope_hash
          OR OLD.artifact_id IS NOT NEW.artifact_id
          OR OLD.window_start IS NOT NEW.window_start
          OR OLD.window_end IS NOT NEW.window_end
        THEN RAISE(ABORT, 'publication scope is immutable external state')
    END;
END;
CREATE TRIGGER IF NOT EXISTS publication_scopes_no_delete
BEFORE DELETE ON publication_scopes
BEGIN
    SELECT RAISE(ABORT, 'publication scope deletion cannot undo public disclosure');
END;
CREATE TRIGGER IF NOT EXISTS legal_orders_no_delete
BEFORE DELETE ON legal_orders
BEGIN
    SELECT RAISE(ABORT, 'judicial instrument bytes must be retained');
END;
CREATE TRIGGER IF NOT EXISTS order_revocations_immutable_update
BEFORE UPDATE ON order_revocations
BEGIN
    SELECT RAISE(ABORT, 'revocation records are append-only');
END;
CREATE TRIGGER IF NOT EXISTS order_revocations_no_delete
BEFORE DELETE ON order_revocations
BEGIN
    SELECT RAISE(ABORT, 'revocation records must be retained');
END;
CREATE TRIGGER IF NOT EXISTS customer_attributions_no_delete
BEFORE DELETE ON customer_attributions
BEGIN
    SELECT RAISE(ABORT, 'customer attribution history cannot be erased; append a correction');
END;
CREATE TRIGGER IF NOT EXISTS customer_attributions_identity_immutable
BEFORE UPDATE ON customer_attributions
WHEN OLD.customer_id IS NOT NEW.customer_id
  OR OLD.subject_type IS NOT NEW.subject_type
  OR OLD.subject_id IS NOT NEW.subject_id
  OR OLD.mapping_hash IS NOT NEW.mapping_hash
  OR OLD.command_id IS NOT NEW.command_id
BEGIN
    SELECT RAISE(ABORT, 'customer attribution identity cannot be relabelled; append a correction');
END;
CREATE TRIGGER IF NOT EXISTS evidence_artifacts_immutable_bytes
BEFORE UPDATE ON evidence_artifacts
BEGIN
    SELECT CASE
        WHEN OLD.artifact_bytes != NEW.artifact_bytes
          OR OLD.artifact_hash != NEW.artifact_hash
          OR OLD.command_id IS NOT NEW.command_id
          OR OLD.revision IS NOT NEW.revision
        THEN RAISE(ABORT, 'official artifact bytes are immutable; create a correction or supplement')
    END;
END;
CREATE TRIGGER IF NOT EXISTS evidence_artifacts_no_delete
BEFORE DELETE ON evidence_artifacts
BEGIN
    SELECT RAISE(ABORT, 'served dossiers cannot be deleted');
END;
CREATE TRIGGER IF NOT EXISTS delivery_receipts_no_update
BEFORE UPDATE ON delivery_receipts
BEGIN
    SELECT RAISE(ABORT, 'delivery receipts are append-only');
END;
CREATE TRIGGER IF NOT EXISTS delivery_receipts_no_delete
BEFORE DELETE ON delivery_receipts
BEGIN
    SELECT RAISE(ABORT, 'delivery receipts must be retained');
END;
CREATE TABLE IF NOT EXISTS privacy_incidents(
    incident_id TEXT PRIMARY KEY,
    command_id TEXT UNIQUE,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'bystander_disclosure',
    order_id TEXT,
    artifact_id TEXT,
    service TEXT,
    description TEXT,
    exposed_scopes TEXT NOT NULL DEFAULT '[]',
    detail TEXT NOT NULL DEFAULT '{}',
    recorded_at INTEGER NOT NULL DEFAULT 0
);
CREATE TRIGGER IF NOT EXISTS privacy_incidents_immutable_update
BEFORE UPDATE ON privacy_incidents
BEGIN
    SELECT RAISE(ABORT, 'privacy incidents are append-only');
END;
CREATE TRIGGER IF NOT EXISTS privacy_incidents_no_delete
BEFORE DELETE ON privacy_incidents
BEGIN
    SELECT RAISE(ABORT, 'privacy incidents cannot be erased by deleting an attachment');
END;
"""


def connect(filename):
    db = sqlite3.connect(filename, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA busy_timeout=3000')
    db.execute('''CREATE TABLE IF NOT EXISTS evidence (
        id INTEGER PRIMARY KEY,
        subsystem TEXT NOT NULL,
        object_id TEXT NOT NULL,
        event TEXT NOT NULL,
        version INTEGER NOT NULL,
        detail TEXT NOT NULL,
        occurred_at INTEGER,
        prev_hash TEXT,
        record_hash TEXT,
        chain_hash TEXT
    )''')
    db.executescript("""CREATE TABLE IF NOT EXISTS nodes(id TEXT PRIMARY KEY, architecture TEXT, features TEXT, generation INTEGER, observed_at INTEGER, version TEXT, verified_at INTEGER, zone TEXT);
    CREATE TABLE IF NOT EXISTS api_usage(id TEXT PRIMARY KEY, workload TEXT, api TEXT, generation INTEGER, state TEXT);
CREATE TABLE IF NOT EXISTS waves(id TEXT PRIMARY KEY, target TEXT, parent TEXT, max_unavailable INTEGER, zone_budgets TEXT, state TEXT);
    CREATE TABLE IF NOT EXISTS transitions(id TEXT PRIMARY KEY, wave_id TEXT, node_id TEXT, zone TEXT, node_generation INTEGER, released_at INTEGER, state TEXT);
    CREATE TABLE IF NOT EXISTS transition_probes(id TEXT PRIMARY KEY, transition_id TEXT, node_generation INTEGER, target TEXT, at INTEGER, healthy INTEGER);
CREATE TABLE IF NOT EXISTS migrations(id TEXT PRIMARY KEY, workload TEXT, old_api TEXT, new_api TEXT, expected TEXT, observed TEXT, baseline_config TEXT, state TEXT);
    CREATE TABLE IF NOT EXISTS rollbacks(id TEXT PRIMARY KEY, migration_id TEXT, node_id TEXT, node_version TEXT, config_version TEXT, state TEXT);
    CREATE TABLE IF NOT EXISTS workload_configs(workload TEXT PRIMARY KEY, version TEXT, state TEXT);""")
    db.executescript(LEGAL_SCHEMA)
    _migrate_columns(db)
    _backfill_evidence_chain(db)
    return db


def _columns(db, table):
    return {row[1] for row in db.execute(f'PRAGMA table_info({table})')}


def _add_column_if_missing(db, table, column, declaration):
    if column not in _columns(db, table):
        db.execute(f'ALTER TABLE {table} ADD COLUMN {column} {declaration}')


def _migrate_columns(db):
    evidence_cols = _columns(db, 'evidence')
    for column, declaration in [
        ('occurred_at', 'INTEGER'), ('prev_hash', 'TEXT'),
        ('record_hash', 'TEXT'), ('chain_hash', 'TEXT'),
    ]:
        if column not in evidence_cols:
            db.execute(f'ALTER TABLE evidence ADD COLUMN {column} {declaration}')

    migration_cols = _columns(db, 'migrations')
    for column, declaration in [
        ('occurred_at', 'INTEGER'), ('customer_id', 'TEXT'), ('service', 'TEXT'),
        ('node_id', 'TEXT'), ('wave_id', 'TEXT'), ('transition_id', 'TEXT'),
        ('command_id', 'TEXT'),
    ]:
        if column not in migration_cols:
            db.execute(f'ALTER TABLE migrations ADD COLUMN {column} {declaration}')

    transition_cols = _columns(db, 'transitions')
    for column, declaration in [
        ('customer_id', 'TEXT'), ('service', 'TEXT'), ('migration_id', 'TEXT'),
        ('command_id', 'TEXT'),
    ]:
        if column not in transition_cols:
            db.execute(f'ALTER TABLE transitions ADD COLUMN {column} {declaration}')


def canonical_json(value):
    """Deterministic canonical bytes used for hashes and official documents."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def _event_time(detail):
    if not isinstance(detail, dict):
        return None
    source = detail.get('input') if isinstance(detail.get('input'), dict) else detail
    if not isinstance(source, dict):
        return None
    for key in ('at', 'now', 'timestamp', 'time', 'minute', 'occurred_at',
                'observed_at', 'released_at', 'issued_at', 'recorded_at'):
        value = source.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            return int(value)
    return None


def _hash_evidence_row(eid, subsystem, object_id, event, version, occurred_at, detail):
    return sha256_hex(canonical_json([
        eid, subsystem, object_id, event, version, occurred_at, detail
    ]))


def _backfill_evidence_chain(db):
    rows = db.execute('SELECT * FROM evidence ORDER BY id').fetchall()
    previous_chain = None
    for row in rows:
        occurred_at = row['occurred_at'] if 'occurred_at' in row.keys() else None
        if occurred_at is None:
            occurred_at = _event_time(json.loads(row['detail']))
            db.execute('UPDATE evidence SET occurred_at=? WHERE id=?', (occurred_at, row['id']))
        record_hash = row['record_hash'] if 'record_hash' in row.keys() else None
        if not record_hash:
            record_hash = _hash_evidence_row(
                row['id'], row['subsystem'], row['object_id'], row['event'],
                row['version'], occurred_at, row['detail']
            )
        chain_hash = sha256_hex((previous_chain or '') + record_hash)
        db.execute(
            'UPDATE evidence SET occurred_at=?, prev_hash=?, record_hash=?, chain_hash=? WHERE id=?',
            (occurred_at, previous_chain, record_hash, chain_hash, row['id'])
        )
        previous_chain = chain_hash


@contextmanager
def transaction(db):
    nested = db.in_transaction
    db.execute('SAVEPOINT nested_action' if nested else 'BEGIN IMMEDIATE')
    try:
        yield
        db.execute('RELEASE SAVEPOINT nested_action' if nested else 'COMMIT')
    except:
        if nested:
            db.execute('ROLLBACK TO SAVEPOINT nested_action')
            db.execute('RELEASE SAVEPOINT nested_action')
        else:
            db.execute('ROLLBACK')
        raise


def _json_default(value):
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=lambda item: str(item))
    return str(value)


def record(db, subsystem, object_id, event, version, detail, occurred_at=None):
    detail_text = json.dumps(detail, ensure_ascii=False, sort_keys=True, default=_json_default)
    if occurred_at is None:
        occurred_at = _event_time(detail)
    previous = db.execute('SELECT chain_hash FROM evidence ORDER BY id DESC LIMIT 1').fetchone()
    previous_chain = previous['chain_hash'] if previous else None
    cursor = db.execute(
        '''INSERT INTO evidence(subsystem,object_id,event,version,detail,occurred_at,prev_hash)
           VALUES(?,?,?,?,?,?,?)''',
        (subsystem, object_id, event, int(version or 0), detail_text, occurred_at, previous_chain)
    )
    eid = cursor.lastrowid
    record_hash = _hash_evidence_row(
        eid, subsystem, object_id, event, int(version or 0), occurred_at, detail_text
    )
    chain_hash = sha256_hex((previous_chain or '') + record_hash)
    db.execute(
        'UPDATE evidence SET record_hash=?, chain_hash=? WHERE id=?',
        (record_hash, chain_hash, eid)
    )
    return eid


def verify_evidence_chain(db):
    rows = db.execute('SELECT * FROM evidence ORDER BY id').fetchall()
    previous_chain = None
    for row in rows:
        record_hash = _hash_evidence_row(
            row['id'], row['subsystem'], row['object_id'], row['event'],
            row['version'], row['occurred_at'], row['detail']
        )
        chain_hash = sha256_hex((previous_chain or '') + record_hash)
        if row['record_hash'] != record_hash or row['prev_hash'] != previous_chain or row['chain_hash'] != chain_hash:
            return {'valid': False, 'count': len(rows), 'broken_at': row['id']}
        previous_chain = chain_hash
    return {'valid': True, 'count': len(rows), 'root': previous_chain or sha256_hex(b'')}


def report(db, request=None, **filters):
    """Return evidence rows.

    ``report(db)`` remains the raw chronological report used by the original
    workflow.  Passing a legal order/dictionary performs customer-attributed
    scoping through evidence_delivery; it never rewrites customer labels.
    """
    if request is not None and hasattr(request, 'keys') and not isinstance(request, dict):
        request = dict(request)
    customer_filter = filters.pop('customer', None) or filters.pop('customer_id', None) or filters.pop('target_customer', None)
    if customer_filter:
        from .evidence_delivery import collect_customer_evidence
        service = filters.pop('service', None) or filters.pop('service_id', None)
        start = filters.pop('start', None) or filters.pop('window_start', None) or filters.pop('since', None)
        end = filters.pop('end', None) or filters.pop('window_end', None) or filters.pop('until', None)
        collected = collect_customer_evidence(db, customer_filter, service, start, end)
        return [dict(row) for row in collected['events']]
    if request is not None and not filters:
        if isinstance(request, (str, int)):
            request = {'order_id': str(request)}
        if isinstance(request, dict) and (request.get('order_id') or request.get('target_customer')
                                         or request.get('customer') or request.get('customer_id')):
            from .evidence_delivery import collect_customer_evidence
            order = request
            if request.get('order_id') and not request.get('target_customer'):
                row = db.execute('SELECT * FROM legal_orders WHERE order_id=? OR command_id=?',
                                 (request['order_id'], request['order_id'])).fetchone()
                if row:
                    order = dict(row)
                    order['allowed_fields'] = json.loads(order['allowed_fields'])
            customer = order.get('target_customer') or order.get('customer') or order.get('customer_id')
            service = order.get('service') or order.get('workload')
            start = order.get('window_start', order.get('start'))
            end = order.get('window_end', order.get('end'))
            collected = collect_customer_evidence(db, customer, service, start, end)
            return [dict(row) for row in collected['events']]
        # Deliberately not interpreted as a customer relabelling mechanism.
        start = request.get('window_start', request.get('start')) if isinstance(request, dict) else None
        end = request.get('window_end', request.get('end')) if isinstance(request, dict) else None
        if start is not None:
            filters['since'] = start
        if end is not None:
            filters['until'] = end
    clauses = []
    params = []
    if filters.get('start') is not None:
        filters['since'] = filters['start']
    if filters.get('end') is not None:
        filters['until'] = filters['end']
    if filters.get('subsystem'):
        clauses.append('subsystem=?')
        params.append(filters['subsystem'])
    if filters.get('object_id'):
        clauses.append('object_id=?')
        params.append(filters['object_id'])
    if filters.get('since') is not None:
        clauses.append('occurred_at>=?')
        params.append(filters['since'])
    if filters.get('until') is not None:
        clauses.append('occurred_at<=?')
        params.append(filters['until'])
    sql = 'SELECT * FROM evidence'
    if clauses:
        sql += ' WHERE ' + ' AND '.join(clauses)
    sql += ' ORDER BY id'
    return [dict(row) for row in db.execute(sql, params)]


_AUDIT_DEPTH = threading.local()


def audit_depth():
    return int(getattr(_AUDIT_DEPTH, 'value', 0) or 0)


@contextmanager
def audit_boundary():
    before = audit_depth()
    _AUDIT_DEPTH.value = before + 1
    try:
        yield
    finally:
        _AUDIT_DEPTH.value = before


def _audit_object_id(payload):
    object_id = 'unknown'
    if isinstance(payload, dict):
        for key in ('id', 'order_id', 'mapping_id', 'receipt_id',
                    'artifact_id', 'delivery_id', 'incident_id',
                    'command_id', 'pool', 'service'):
            if payload.get(key):
                return str(payload[key])
    return object_id


def audit_run(subsystem):
    def decorate(fn):
        def wrapped(db, payload):
            with audit_boundary():
                with transaction(db):
                    result = fn(db, payload)
                    object_id = _audit_object_id(payload)
                    version = 0
                    if isinstance(payload, dict):
                        version = int(payload.get('generation', payload.get('revision', 0)) or 0)
                    record(db, subsystem, object_id, 'decision', version,
                           {'input': payload, 'result': result})
            return result
        return wrapped
    return decorate


def standalone_audit(subsystem, operation):
    """Record a decision for direct helper calls unless run() already audits."""
    def decorate(fn):
        def wrapped(db, payload=None, *args, **kwargs):
            if audit_depth() > 0:
                return fn(db, payload, *args, **kwargs)
            with audit_boundary():
                with transaction(db):
                    result = fn(db, payload, *args, **kwargs)
                    audit_payload = dict(payload) if isinstance(payload, dict) else {}
                    audit_payload.update(kwargs)
                    if payload is not None and not isinstance(payload, dict):
                        audit_payload.setdefault('payload', payload)
                    audit_payload.setdefault('op', operation)
                    record(db, subsystem, _audit_object_id(audit_payload), 'decision',
                           int(audit_payload.get('revision', 0) or 0),
                           {'input': audit_payload, 'result': result})
            return result
        return wrapped
    return decorate


def replay(filename, modules=None):
    source = connect(filename)
    if modules is None:
        modules = {}
    # Legal/delivery modules are part of the current write path.  Defaulting
    # them keeps replay(db, {'inventory': ...}) focused on workflow modules
    # without silently skipping newer decision evidence.
    from . import inventory as _inventory
    from . import wave as _wave
    from . import migration as _migration
    from . import legal_request as _legal_request
    from . import evidence_delivery as _evidence_delivery
    modules = {
        'inventory': _inventory,
        'wave': _wave,
        'migration': _migration,
        'legal_request': _legal_request,
        'evidence_delivery': _evidence_delivery,
        **modules,
    }
    decisions = [dict(row) for row in source.execute("SELECT subsystem,detail FROM evidence WHERE event='decision' ORDER BY id")]
    target = connect(':memory:')
    divergences = []
    for index, entry in enumerate(decisions, 1):
        fact = json.loads(entry['detail'])
        module = modules.get(entry['subsystem'])
        if module is None:
            divergences.append({'step': index, 'subsystem': entry['subsystem'], 'reason': 'missing_module'})
            continue
        actual = module.run(target, fact['input'])
        if actual != fact['result']:
            divergences.append({'step': index, 'subsystem': entry['subsystem'], 'expected': fact['result'], 'actual': actual})
    tables = [r[0] for r in source.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    for table in tables:
        if table == 'evidence':
            continue
        if not target.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
            divergences.append({'table': table, 'reason': 'missing_in_replay'})
            continue
        before = [tuple(r) for r in source.execute('SELECT * FROM ' + table + ' ORDER BY rowid')]
        after = [tuple(r) for r in target.execute('SELECT * FROM ' + table + ' ORDER BY rowid')]
        if before != after:
            divergences.append({'table': table, 'reason': 'state_mismatch', 'before': before, 'after': after})
    source.close()
    target.close()
    return {'decision_count': len(decisions), 'verified': not divergences, 'divergences': divergences}
