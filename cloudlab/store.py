import json
import sqlite3
from contextlib import contextmanager

def connect(filename):
    db=sqlite3.connect(filename, isolation_level=None)
    db.row_factory=sqlite3.Row
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

-- Risk requests lock the original instrument (service, base quota version,
-- target quota, zone, maintenance window and benefited customers) plus a
-- digest that every external signature is pinned to.
CREATE TABLE IF NOT EXISTS risk_requests(
    id TEXT PRIMARY KEY, wave_id TEXT, applicant TEXT,
    old_budget INTEGER, new_budget INTEGER, at INTEGER, status TEXT,
    service TEXT, zone TEXT, base_version TEXT,
    window_start INTEGER, window_end INTEGER, customers TEXT,
    digest TEXT, submitted_at INTEGER, activated_revision TEXT, policy TEXT);

-- Append-only external/device signatures. Authority columns are snapshots at
-- ingestion time; qualification is always recomputed against effective-time
-- delegation/revocation facts before activation.
CREATE TABLE IF NOT EXISTS risk_signatures(
    id TEXT PRIMARY KEY, request_id TEXT, seat TEXT, at INTEGER,
    digest TEXT, device_id TEXT, device_signature TEXT,
    principal_id TEXT, controller_id TEXT, role TEXT,
    delegation_id TEXT, received_at INTEGER,
    qualified INTEGER, findings TEXT, extra TEXT);

-- Real natural persons / corporate accounts. controller_id collapses
-- technical accounts and corporate vehicles to one ultimate controller.
CREATE TABLE IF NOT EXISTS principals(
    id TEXT PRIMARY KEY, name TEXT, kind TEXT,
    controller_id TEXT, note TEXT, at INTEGER);

-- Approval seats: tenure window, absolute cap / increase limit and scopes.
CREATE TABLE IF NOT EXISTS seats(
    id TEXT PRIMARY KEY, holder_id TEXT, role TEXT, title TEXT,
    valid_from INTEGER, valid_to INTEGER,
    cap INTEGER, max_increase INTEGER,
    zones TEXT, services TEXT, device_key TEXT,
    active INTEGER DEFAULT 1, at INTEGER);

-- Proxy grants. revoked_at is the EFFECTIVE revocation time while
-- revocation_received_at is when the verifier learned of it (may be late).
CREATE TABLE IF NOT EXISTS delegations(
    id TEXT PRIMARY KEY,
    grantor_seat TEXT, grantor_id TEXT, agent_id TEXT,
    parent_id TEXT,
    scope TEXT,
    granted_at INTEGER, expires_at INTEGER,
    revoked_at INTEGER, revocation_received_at INTEGER, receipt TEXT,
    status TEXT DEFAULT 'active');

CREATE TABLE IF NOT EXISTS incidents(
    id TEXT PRIMARY KEY, kind TEXT, title TEXT,
    service TEXT, zone TEXT,
    opened_at INTEGER, verified_at INTEGER,
    verifier_seat TEXT, state TEXT, detail TEXT);

-- Linear, compare-and-swap budget versions per (service, zone).
CREATE TABLE IF NOT EXISTS budget_revisions(
    id TEXT PRIMARY KEY,
    service TEXT, zone TEXT,
    version INTEGER, base_version INTEGER, quota INTEGER,
    kind TEXT, ref_type TEXT, ref_id TEXT,
    accountable TEXT, at INTEGER, detail TEXT,
    UNIQUE(service, zone, version));

CREATE TABLE IF NOT EXISTS emergency_permits(
    id TEXT PRIMARY KEY,
    incident_id TEXT,
    issuer_seat TEXT, issuer_id TEXT, controller_id TEXT, role TEXT,
    service TEXT, zone TEXT, extra_quota INTEGER,
    issued_at INTEGER, valid_from INTEGER, valid_until INTEGER,
    signature_id TEXT, digest TEXT,
    state TEXT,
    review_state TEXT DEFAULT 'pending',
    reviewed_at INTEGER, reviewer_seat TEXT, reviewer_id TEXT,
    review_outcome TEXT, review_note TEXT,
    remedy TEXT, remedy_at INTEGER, ended_at INTEGER,
    detail TEXT);

CREATE TABLE IF NOT EXISTS wave_authorizations(
    wave_id TEXT PRIMARY KEY,
    kind TEXT, request_id TEXT, revision_id TEXT, version INTEGER,
    permit_id TEXT, service TEXT, zone TEXT,
    bound_at INTEGER, detail TEXT);

-- Which instrument/independent group bears each actual occupancy.
CREATE TABLE IF NOT EXISTS release_attributions(
    transition_id TEXT PRIMARY KEY,
    wave_id TEXT, node_id TEXT, zone TEXT, at INTEGER,
    slot_kind TEXT, cap INTEGER,
    request_id TEXT, revision_id TEXT, version INTEGER, permit_id TEXT,
    accountable TEXT);

-- Immutable approval event stream (signatures, revocations, activations,
-- reviews). Rows are evidence; corrections are new events, never edits.
CREATE TABLE IF NOT EXISTS approval_ledger(
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT, kind TEXT,
    request_id TEXT, signature_id TEXT, seat TEXT,
    at INTEGER, recorded_at INTEGER,
    principal_id TEXT, controller_id TEXT, digest TEXT,
    qualified INTEGER, reasons TEXT, detail TEXT);
""")
    _migrate_columns(db)
    _immutable_triggers(db)
    return db

_ADDED_COLUMNS={
 'risk_requests':[('service','TEXT'),('zone','TEXT'),('base_version','TEXT'),
                  ('window_start','INTEGER'),('window_end','INTEGER'),('customers','TEXT'),
                  ('digest','TEXT'),('submitted_at','INTEGER'),('activated_revision','TEXT'),
                  ('policy','TEXT')],
 'risk_signatures':[('digest','TEXT'),('device_id','TEXT'),('device_signature','TEXT'),
                    ('principal_id','TEXT'),('controller_id','TEXT'),('role','TEXT'),
                    ('delegation_id','TEXT'),('received_at','INTEGER'),
                    ('qualified','INTEGER'),('findings','TEXT'),('extra','TEXT')],
}

def _migrate_columns(db):
    for table,columns in _ADDED_COLUMNS.items():
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone():
            continue
        existing={r[1] for r in db.execute(f'PRAGMA table_info({table})')}
        for name,decl in columns:
            if name not in existing:
                db.execute(f'ALTER TABLE {table} ADD COLUMN {name} {decl}')

def _immutable_triggers(db):
    for table in ('risk_signatures','approval_ledger','budget_revisions'):
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone():
            continue
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS {table}_no_update
            BEFORE UPDATE ON {table}
            BEGIN SELECT RAISE(ABORT, '{table}_is_append_only'); END""")
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS {table}_no_delete
            BEFORE DELETE ON {table}
            BEGIN SELECT RAISE(ABORT, '{table}_is_append_only'); END""")

@contextmanager
def transaction(db):
    nested=db.in_transaction
    db.execute('SAVEPOINT nested_action' if nested else 'BEGIN IMMEDIATE')
    try:
        yield
        db.execute('RELEASE SAVEPOINT nested_action' if nested else 'COMMIT')
    except:
        if nested:
            db.execute('ROLLBACK TO SAVEPOINT nested_action')
            db.execute('RELEASE SAVEPOINT nested_action')
        else: db.execute('ROLLBACK')
        raise

def record(db, subsystem, object_id, event, version, detail):
    db.execute('INSERT INTO evidence(subsystem,object_id,event,version,detail) VALUES(?,?,?,?,?)',
               (subsystem,object_id,event,version,json.dumps(detail,ensure_ascii=False,sort_keys=True)))

def report(db):
    return [dict(row) for row in db.execute('SELECT * FROM evidence ORDER BY id')]

def audit_run(subsystem):
    def decorate(fn):
        def wrapped(db, payload):
            with transaction(db):
                result=fn(db,payload)
                object_id=str(payload.get('id') or payload.get('pool') or payload.get('service') or 'unknown')
                record(db,subsystem,object_id,'decision',int(payload.get('generation',0)),
                       {'input':payload,'result':result})
            return result
        return wrapped
    return decorate

def replay(filename, modules):
    source=connect(filename)
    decisions=[dict(row) for row in source.execute("SELECT subsystem,detail FROM evidence WHERE event='decision' ORDER BY id")]
    target=connect(':memory:')
    divergences=[]
    for index,entry in enumerate(decisions,1):
        fact=json.loads(entry['detail'])
        actual=modules[entry['subsystem']].run(target,fact['input'])
        if actual!=fact['result']:
            divergences.append({'step':index,'subsystem':entry['subsystem'],'expected':fact['result'],'actual':actual})
    tables=[r[0] for r in source.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('evidence','sqlite_sequence') ORDER BY name")]
    for table in tables:
        if not target.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone():
            divergences.append({'table':table,'reason':'missing_in_replay'});continue
        before=[tuple(r) for r in source.execute('SELECT * FROM '+table+' ORDER BY rowid')]
        after=[tuple(r) for r in target.execute('SELECT * FROM '+table+' ORDER BY rowid')]
        if before!=after:divergences.append({'table':table,'reason':'state_mismatch','before':before,'after':after})
    source.close();target.close()
    return {'decision_count':len(decisions),'verified':not divergences,'divergences':divergences}
