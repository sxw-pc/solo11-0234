import json
import sqlite3
from contextlib import contextmanager

FIBER_SCHEMA = """
CREATE TABLE IF NOT EXISTS fiber_branches(
    id TEXT PRIMARY KEY,
    port TEXT NOT NULL,
    length_km REAL NOT NULL,
    shaft TEXT NOT NULL,
    refractive_index REAL,
    drawing_version TEXT,
    status TEXT NOT NULL DEFAULT 'current',
    updated_at INTEGER,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS fiber_drawing_revisions(
    id TEXT PRIMARY KEY,
    branch_id TEXT NOT NULL,
    drawing_version TEXT NOT NULL,
    port TEXT,
    length_km REAL,
    shaft TEXT,
    changed_at INTEGER,
    supersedes TEXT,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS fiber_traces(
    id TEXT PRIMARY KEY,
    port TEXT NOT NULL,
    distance_km REAL NOT NULL,
    loss REAL NOT NULL,
    direction TEXT NOT NULL DEFAULT 'forward',
    splitter_port TEXT,
    refractive_index REAL,
    drawing_version TEXT,
    branch_id TEXT,
    segment_id TEXT,
    incident_id TEXT,
    endpoint TEXT,
    measured_at INTEGER,
    meter_id TEXT,
    calibration_id TEXT,
    calibration_valid INTEGER,
    calibration_due INTEGER,
    independent INTEGER,
    observer TEXT,
    raw_json TEXT
);
CREATE TABLE IF NOT EXISTS fiber_splices(
    id TEXT PRIMARY KEY,
    branch TEXT NOT NULL,
    worker TEXT NOT NULL,
    incident_id TEXT,
    permit_id TEXT,
    work_order_id TEXT,
    segment_id TEXT,
    receipt_at INTEGER,
    authorization_state TEXT,
    payload_json TEXT
);
CREATE TABLE IF NOT EXISTS fiber_incidents(
    id TEXT PRIMARY KEY,
    port TEXT,
    circuit_id TEXT,
    customer_id TEXT,
    trace_id TEXT,
    opened_at INTEGER,
    state TEXT NOT NULL,
    located_branch TEXT,
    route TEXT,
    candidate_ids TEXT NOT NULL,
    customer_state TEXT NOT NULL DEFAULT 'down',
    backup_id TEXT,
    customer_restored_at INTEGER,
    primary_restored_at INTEGER,
    restoration_id TEXT,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS fiber_segments(
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    branch_id TEXT NOT NULL,
    shaft TEXT,
    ordinal INTEGER NOT NULL DEFAULT 1,
    length_km REAL,
    start_km REAL,
    end_km REAL,
    core_id TEXT,
    status TEXT NOT NULL DEFAULT 'identified',
    replacement_id TEXT,
    acceptance_id TEXT,
    accepted_at INTEGER,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS fiber_authorizations(
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    owner TEXT,
    route TEXT,
    max_wells INTEGER,
    scope_json TEXT NOT NULL,
    terms_json TEXT NOT NULL,
    issued_at INTEGER,
    valid_from INTEGER,
    valid_until INTEGER,
    status TEXT NOT NULL DEFAULT 'valid',
    detail TEXT
);
CREATE TABLE IF NOT EXISTS fiber_permits(
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    authorization_id TEXT,
    kind TEXT NOT NULL DEFAULT 'excavation',
    branch_id TEXT,
    shaft TEXT,
    segment_id TEXT,
    scope_json TEXT NOT NULL,
    drawing_version TEXT,
    issued_at INTEGER,
    valid_from INTEGER,
    valid_until INTEGER,
    status TEXT NOT NULL DEFAULT 'valid',
    revoked_at INTEGER,
    revoke_reason TEXT,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS fiber_work_orders(
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    authorization_id TEXT,
    permit_id TEXT,
    branch_id TEXT NOT NULL,
    segment_id TEXT,
    crew TEXT,
    worker TEXT,
    assigned_to TEXT,
    accepted_by TEXT,
    scope_json TEXT NOT NULL,
    dispatched_at INTEGER,
    accept_deadline INTEGER,
    accepted_at INTEGER,
    valid_until INTEGER,
    status TEXT NOT NULL DEFAULT 'dispatched',
    detail TEXT
);
CREATE TABLE IF NOT EXISTS fiber_replacements(
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    branch_id TEXT NOT NULL,
    segment_id TEXT,
    work_order_id TEXT,
    permit_id TEXT,
    splice_id TEXT,
    kind TEXT NOT NULL DEFAULT 'core_replacement',
    old_core_id TEXT,
    new_core_id TEXT,
    extent_km REAL,
    start_km REAL,
    end_km REAL,
    replaced_at INTEGER,
    status TEXT NOT NULL DEFAULT 'installed',
    payload_json TEXT
);
CREATE TABLE IF NOT EXISTS fiber_loopbacks(
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    branch_id TEXT NOT NULL,
    segment_id TEXT,
    replacement_id TEXT,
    endpoint TEXT NOT NULL,
    side TEXT,
    passed INTEGER NOT NULL,
    independent INTEGER NOT NULL DEFAULT 0,
    authentic INTEGER NOT NULL DEFAULT 1,
    observer TEXT,
    tester TEXT,
    meter_id TEXT,
    challenge TEXT,
    response TEXT,
    loss REAL,
    measured_at INTEGER,
    status TEXT NOT NULL,
    payload_json TEXT
);
CREATE TABLE IF NOT EXISTS fiber_remote_measurements(
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    branch_id TEXT,
    segment_id TEXT,
    replacement_id TEXT,
    kind TEXT NOT NULL,
    endpoint TEXT,
    passed INTEGER,
    loss REAL,
    independent INTEGER NOT NULL DEFAULT 0,
    authentic INTEGER NOT NULL DEFAULT 1,
    measured_at INTEGER,
    observer TEXT,
    payload_json TEXT
);
CREATE TABLE IF NOT EXISTS fiber_customer_readings(
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    circuit_id TEXT,
    customer_id TEXT,
    branch_id TEXT,
    segment_id TEXT,
    replacement_id TEXT,
    core_id TEXT,
    up INTEGER NOT NULL,
    loss REAL,
    device TEXT,
    observed_at INTEGER,
    far_measurement_id TEXT,
    payload_json TEXT
);
CREATE TABLE IF NOT EXISTS fiber_acceptances(
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    branch_id TEXT NOT NULL,
    segment_id TEXT,
    replacement_id TEXT,
    forward_trace_id TEXT,
    reverse_trace_id TEXT,
    near_loopback_id TEXT,
    far_loopback_id TEXT,
    customer_reading_id TEXT,
    far_measurement_id TEXT,
    max_loss REAL,
    result TEXT NOT NULL,
    reason TEXT,
    accepted_at INTEGER,
    payload_json TEXT
);
CREATE TABLE IF NOT EXISTS fiber_restorations(
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL UNIQUE,
    circuit_id TEXT,
    customer_id TEXT,
    served_branch_id TEXT,
    branch_ids_json TEXT NOT NULL,
    segment_ids_json TEXT NOT NULL,
    replacement_ids_json TEXT NOT NULL,
    acceptance_ids_json TEXT NOT NULL,
    far_measurement_id TEXT,
    customer_reading_id TEXT,
    primary_uplink INTEGER NOT NULL DEFAULT 1,
    restored_at INTEGER,
    outage_minutes INTEGER,
    customer_restored_minutes INTEGER,
    payload_json TEXT
);
CREATE TABLE IF NOT EXISTS fiber_backups(
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    circuit_id TEXT,
    path_id TEXT,
    state TEXT NOT NULL,
    activated_at INTEGER,
    reading_id TEXT,
    detail TEXT
);
CREATE VIEW IF NOT EXISTS fiber_repairs AS
    SELECT id, incident_id, branch_id, segment_id, work_order_id, permit_id,
           splice_id AS receipt_id, splice_id, kind, old_core_id, new_core_id,
           extent_km, start_km, end_km, replaced_at AS repaired_at,
           replaced_at AS at, replaced_at, status, status AS state, payload_json
    FROM fiber_replacements;
CREATE VIEW IF NOT EXISTS fiber_faults AS
    SELECT *, state AS status FROM fiber_incidents;
CREATE VIEW IF NOT EXISTS fiber_excavation_permits AS
    SELECT * FROM fiber_permits WHERE kind='excavation';
CREATE VIEW IF NOT EXISTS fiber_loopback_tests AS
    SELECT * FROM fiber_loopbacks;
CREATE VIEW IF NOT EXISTS fiber_link_readings AS
    SELECT * FROM fiber_customer_readings;
"""


def _ensure_columns(db, table, columns):
    existing = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
    for name, declaration in columns.items():
        if name not in existing:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")


def ensure_fiber_schema(db):
    """Create fiber tables and upgrade seed-era tables in place.

    ``executescript`` commits any open transaction, so nested calls inside a
    business transaction must be no-ops.  ``connect`` always runs this hook
    before request transactions begin.
    """
    if getattr(db, 'in_transaction', False):
        return
    db.executescript(FIBER_SCHEMA)
    _ensure_columns(db, 'fiber_branches', {
        'refractive_index': 'REAL',
        'drawing_version': 'TEXT',
        'status': "TEXT NOT NULL DEFAULT 'current'",
        'updated_at': 'INTEGER',
        'detail': 'TEXT',
    })
    _ensure_columns(db, 'fiber_traces', {
        'direction': "TEXT NOT NULL DEFAULT 'forward'",
        'splitter_port': 'TEXT',
        'refractive_index': 'REAL',
        'drawing_version': 'TEXT',
        'branch_id': 'TEXT',
        'segment_id': 'TEXT',
        'incident_id': 'TEXT',
        'endpoint': 'TEXT',
        'measured_at': 'INTEGER',
        'meter_id': 'TEXT',
        'calibration_id': 'TEXT',
        'calibration_valid': 'INTEGER',
        'calibration_due': 'INTEGER',
        'independent': 'INTEGER',
        'observer': 'TEXT',
        'raw_json': 'TEXT',
    })
    _ensure_columns(db, 'fiber_splices', {
        'incident_id': 'TEXT',
        'permit_id': 'TEXT',
        'work_order_id': 'TEXT',
        'segment_id': 'TEXT',
        'receipt_at': 'INTEGER',
        'authorization_state': 'TEXT',
        'payload_json': 'TEXT',
    })


# Compatibility alias for modules/tests that expect a generic schema hook.
def ensure_schema(db):
    ensure_fiber_schema(db)


def connect(filename):
    db=sqlite3.connect(filename, isolation_level=None)
    db.row_factory=sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA busy_timeout=3000')
    db.execute('CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY, subsystem TEXT NOT NULL, object_id TEXT NOT NULL, event TEXT NOT NULL, version INTEGER NOT NULL, detail TEXT NOT NULL)')
    db.executescript("\nCREATE TABLE IF NOT EXISTS nodes(id TEXT PRIMARY KEY, architecture TEXT, features TEXT, generation INTEGER, observed_at INTEGER, version TEXT, verified_at INTEGER, zone TEXT);\n    CREATE TABLE IF NOT EXISTS api_usage(id TEXT PRIMARY KEY, workload TEXT, api TEXT, generation INTEGER, state TEXT);\nCREATE TABLE IF NOT EXISTS waves(id TEXT PRIMARY KEY, target TEXT, parent TEXT, max_unavailable INTEGER, zone_budgets TEXT, state TEXT);\n    CREATE TABLE IF NOT EXISTS transitions(id TEXT PRIMARY KEY, wave_id TEXT, node_id TEXT, zone TEXT, node_generation INTEGER, released_at INTEGER, state TEXT);\n    CREATE TABLE IF NOT EXISTS transition_probes(id TEXT PRIMARY KEY, transition_id TEXT, node_generation INTEGER, target TEXT, at INTEGER, healthy INTEGER);\nCREATE TABLE IF NOT EXISTS migrations(id TEXT PRIMARY KEY, workload TEXT, old_api TEXT, new_api TEXT, expected TEXT, observed TEXT, baseline_config TEXT, state TEXT);\n    CREATE TABLE IF NOT EXISTS rollbacks(id TEXT PRIMARY KEY, migration_id TEXT, node_id TEXT, node_version TEXT, config_version TEXT, state TEXT);\n    CREATE TABLE IF NOT EXISTS workload_configs(workload TEXT PRIMARY KEY, version TEXT, state TEXT);")
    ensure_fiber_schema(db)
    return db

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
               (subsystem,object_id,event,version,json.dumps(detail,ensure_ascii=False,sort_keys=True,default=str)))

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
        module=modules.get(entry['subsystem'])
        if module is None:
            try:
                import importlib
                module=importlib.import_module(f'cloudlab.{entry["subsystem"]}')
            except (ImportError, ValueError):
                divergences.append({'step':index,'subsystem':entry['subsystem'],
                                   'reason':'missing_replay_module'})
                continue
        actual=module.run(target,fact['input'])
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
