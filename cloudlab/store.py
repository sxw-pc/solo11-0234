import base64
import json
import sqlite3
from contextlib import contextmanager

_BYTES_TAG = '__cloudlab_bytes_b64__'


def _json_default(value):
    if isinstance(value, (bytes, bytearray)):
        return {_BYTES_TAG: base64.b64encode(bytes(value)).decode('ascii')}
    if isinstance(value, sqlite3.Row):
        return dict(value)
    if hasattr(value, 'isoformat'):
        return value.isoformat()
    return str(value)


def _json_hook(value):
    if isinstance(value, dict) and set(value) == {_BYTES_TAG}:
        return base64.b64decode(value[_BYTES_TAG])
    return value


def _ensure_column(db, table, column, declaration):
    columns = {row[1] for row in db.execute(f'PRAGMA table_info({table})')}
    if column not in columns:
        db.execute(f'ALTER TABLE {table} ADD COLUMN {column} {declaration}')


def connect(filename):
    db = sqlite3.connect(filename, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA busy_timeout=3000')
    db.execute('CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY, subsystem TEXT NOT NULL, object_id TEXT NOT NULL, event TEXT NOT NULL, version INTEGER NOT NULL, detail TEXT NOT NULL)')
    db.executescript("""
CREATE TABLE IF NOT EXISTS nodes(id TEXT PRIMARY KEY, architecture TEXT, features TEXT, generation INTEGER, observed_at INTEGER, version TEXT, verified_at INTEGER, zone TEXT);
CREATE TABLE IF NOT EXISTS api_usage(id TEXT PRIMARY KEY, workload TEXT, api TEXT, generation INTEGER, state TEXT);
CREATE TABLE IF NOT EXISTS waves(id TEXT PRIMARY KEY, target TEXT, parent TEXT, max_unavailable INTEGER, zone_budgets TEXT, state TEXT);
CREATE TABLE IF NOT EXISTS transitions(id TEXT PRIMARY KEY, wave_id TEXT, node_id TEXT, zone TEXT, node_generation INTEGER, released_at INTEGER, state TEXT);
CREATE TABLE IF NOT EXISTS transition_probes(id TEXT PRIMARY KEY, transition_id TEXT, node_generation INTEGER, target TEXT, at INTEGER, healthy INTEGER);
CREATE TABLE IF NOT EXISTS migrations(id TEXT PRIMARY KEY, workload TEXT, old_api TEXT, new_api TEXT, expected TEXT, observed TEXT, baseline_config TEXT, state TEXT);
CREATE TABLE IF NOT EXISTS rollbacks(id TEXT PRIMARY KEY, migration_id TEXT, node_id TEXT, node_version TEXT, config_version TEXT, state TEXT);
CREATE TABLE IF NOT EXISTS workload_configs(workload TEXT PRIMARY KEY, version TEXT, state TEXT);

-- Immutable-enough inventory observations.  The nodes row remains the current
-- fact, while node_scans preserves every accepted generation scan.
CREATE TABLE IF NOT EXISTS node_scans(
    node_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    observed_at INTEGER NOT NULL,
    scan_id TEXT,
    architecture TEXT,
    version TEXT,
    zone TEXT,
    features_json TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    PRIMARY KEY(node_id, generation, observed_at)
);
CREATE VIEW IF NOT EXISTS inventory_scans AS
    SELECT node_id AS id, generation, observed_at, scan_id, architecture,
           version, zone, features_json, detail_json
    FROM node_scans;

-- Upgrade incident scope: version, request, shared proxy, physical response,
-- independent egress evidence and the escrow-held client receipt token.
CREATE TABLE IF NOT EXISTS incident_cases(
    id TEXT PRIMARY KEY,
    fault_version TEXT,
    wave_id TEXT,
    node_id TEXT,
    node_generation INTEGER,
    evidence_at INTEGER NOT NULL,
    legal_clock_started_at INTEGER NOT NULL,
    deadline_at INTEGER,
    earliest_fault_at INTEGER,
    security_officer TEXT,
    authorizer TEXT,
    contract_owner TEXT,
    known_clients_json TEXT NOT NULL,
    approved_modes_json TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at INTEGER,
    detail_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_approvals(
    approval_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    approved_at INTEGER,
    detail_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_fault_samples(
    sample_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    observed_at INTEGER,
    recorded_at INTEGER,
    healthy INTEGER,
    data_returned INTEGER,
    trusted INTEGER NOT NULL DEFAULT 0,
    detail_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_requests(
    request_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    at INTEGER,
    client_hint TEXT,
    detail_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_forward_attempts(
    attempt_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    request_id TEXT,
    proxy_id TEXT,
    nat_address TEXT,
    trace_id TEXT,
    attempt_no INTEGER,
    at INTEGER,
    outcome TEXT,
    detail_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_responses(
    trace_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    request_id TEXT,
    proxy_id TEXT,
    nat_address TEXT,
    at INTEGER,
    fault_version TEXT,
    returned_data INTEGER NOT NULL DEFAULT 1,
    foreign_tenant_leak INTEGER NOT NULL DEFAULT 0,
    diagnostic_fields_json TEXT NOT NULL,
    candidate_clients_json TEXT NOT NULL,
    page_hint TEXT,
    independent_egress_count INTEGER,
    raw_bytes BLOB,
    raw_hash TEXT,
    detail_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_egress_observations(
    observation_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    observer TEXT,
    count INTEGER NOT NULL,
    at INTEGER,
    detail_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_receipts(
    receipt_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    token_hash TEXT,
    signer TEXT,
    signed_at INTEGER,
    terminal INTEGER NOT NULL DEFAULT 0,
    gateway_code TEXT,
    signature_bytes BLOB,
    receipt_hash TEXT,
    detail_json TEXT NOT NULL,
    UNIQUE(trace_id, token_hash)
);
CREATE TABLE IF NOT EXISTS incident_token_bindings(
    binding_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL,
    client_id TEXT NOT NULL,
    state TEXT NOT NULL,
    custodian TEXT,
    authorizer TEXT,
    unsealed_at INTEGER,
    reversed_at INTEGER,
    replaces_binding_id TEXT,
    detail_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_token_bindings_token ON incident_token_bindings(token_hash);
CREATE UNIQUE INDEX IF NOT EXISTS idx_token_active_binding
    ON incident_token_bindings(token_hash) WHERE state='active';
CREATE TABLE IF NOT EXISTS incident_scope_versions(
    scope_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    scope_hash TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    generated_at INTEGER,
    authorizer TEXT,
    reason TEXT,
    UNIQUE(incident_id, version)
);
CREATE TABLE IF NOT EXISTS incident_artifacts(
    artifact_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    name TEXT,
    at INTEGER,
    raw_bytes BLOB,
    raw_hash TEXT,
    detail_json TEXT NOT NULL
);

-- Exact notice originals and their real delivery/receipt history.
CREATE TABLE IF NOT EXISTS notice_documents(
    notice_id TEXT PRIMARY KEY,
    idempotency_key TEXT UNIQUE,
    request_hash TEXT,
    incident_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    notice_role TEXT,
    execution_mode TEXT,
    audience_type TEXT,
    recipient_id TEXT,
    authorizer TEXT NOT NULL,
    authorization_json TEXT NOT NULL,
    approval_id TEXT,
    corrects_notice_id TEXT,
    scope_id TEXT,
    scope_hash TEXT,
    body_format TEXT NOT NULL DEFAULT 'utf-8',
    body_raw BLOB NOT NULL,
    body_hash TEXT NOT NULL,
    state TEXT NOT NULL,
    late INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER,
    first_sent_at INTEGER,
    final_signed_at INTEGER,
    detail_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notice_recipients(
    notice_id TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    address TEXT,
    recipient_kind TEXT NOT NULL DEFAULT 'customer',
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    sent_at INTEGER,
    gateway_code TEXT,
    accepted_at INTEGER,
    delivered_at INTEGER,
    bounced_at INTEGER,
    bounce_code TEXT,
    bounce_reason TEXT,
    signed_at INTEGER,
    signer TEXT,
    receipt_hash TEXT,
    detail_json TEXT NOT NULL,
    PRIMARY KEY(notice_id, recipient_id)
);
CREATE TABLE IF NOT EXISTS notice_events(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE,
    notice_id TEXT NOT NULL,
    recipient_id TEXT,
    event_type TEXT NOT NULL,
    at INTEGER,
    code TEXT,
    detail_json TEXT NOT NULL,
    receipt_bytes BLOB,
    receipt_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_notice_events_notice ON notice_events(notice_id, id);

-- Append-only protections for the decision ledger and exact notice originals.
CREATE TRIGGER IF NOT EXISTS evidence_no_update BEFORE UPDATE ON evidence
BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;
CREATE TRIGGER IF NOT EXISTS evidence_no_delete BEFORE DELETE ON evidence
BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;
CREATE TRIGGER IF NOT EXISTS notice_documents_no_delete BEFORE DELETE ON notice_documents
BEGIN SELECT RAISE(ABORT, 'sent notice originals cannot be deleted; issue a correction'); END;
CREATE TRIGGER IF NOT EXISTS notice_document_identity_immutable
BEFORE UPDATE OF notice_id, incident_id, kind, body_raw, body_hash, idempotency_key ON notice_documents
BEGIN SELECT RAISE(ABORT, 'notice original identity/bytes are immutable; append a correction or event'); END;
CREATE TRIGGER IF NOT EXISTS notice_events_no_update BEFORE UPDATE ON notice_events
BEGIN SELECT RAISE(ABORT, 'delivery events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS notice_events_no_delete BEFORE DELETE ON notice_events
BEGIN SELECT RAISE(ABORT, 'delivery events are append-only'); END;
""")
    # Backfill time columns for databases created before incident delivery.
    _ensure_column(db, 'waves', 'completed_at', 'INTEGER')
    _ensure_column(db, 'waves', 'finished_at', 'INTEGER')
    _ensure_column(db, 'transitions', 'finished_at', 'INTEGER')
    _ensure_column(db, 'transitions', 'completed_at', 'INTEGER')
    return db


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


def record(db, subsystem, object_id, event, version, detail):
    db.execute('INSERT INTO evidence(subsystem,object_id,event,version,detail) VALUES(?,?,?,?,?)',
               (subsystem, object_id, event, version,
                json.dumps(detail, ensure_ascii=False, sort_keys=True, default=_json_default)))


def report(db):
    return [dict(row) for row in db.execute('SELECT * FROM evidence ORDER BY id')]


def audit_run(subsystem):
    def decorate(fn):
        def wrapped(db, payload):
            with transaction(db):
                result = fn(db, payload)
                object_id = str(
                    payload.get('id')
                    or payload.get('incident_id')
                    or payload.get('notice_id')
                    or payload.get('sample_id')
                    or payload.get('trace_id')
                    or payload.get('request_id')
                    or payload.get('pool')
                    or payload.get('service')
                    or 'unknown'
                )
                record(db, subsystem, object_id, 'decision', int(payload.get('generation') or 0),
                       {'input': payload, 'result': result})
            return result
        return wrapped
    return decorate


def replay(filename, modules):
    source = connect(filename)
    decisions = [dict(row) for row in source.execute("SELECT subsystem,detail FROM evidence WHERE event='decision' ORDER BY id")]
    target = connect(':memory:')
    divergences = []
    for index, entry in enumerate(decisions, 1):
        fact = json.loads(entry['detail'], object_hook=_json_hook)
        actual = modules[entry['subsystem']].run(target, fact['input'])
        if actual != fact['result']:
            divergences.append({'step': index, 'subsystem': entry['subsystem'],
                                'expected': fact['result'], 'actual': actual})
    tables = [r[0] for r in source.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('evidence','sqlite_sequence') ORDER BY name")]
    for table in tables:
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
