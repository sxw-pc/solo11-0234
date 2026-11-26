import base64
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

-- Customer-object custody and loss-aware recovery.  These tables are deliberately
-- separate from the wave gate: preservation of confirmed customer writes is not
-- equivalent to release eligibility.
CREATE TABLE IF NOT EXISTS custody_contracts(
    migration_id TEXT PRIMARY KEY, workload TEXT NOT NULL, old_api TEXT NOT NULL, new_api TEXT NOT NULL,
    old_config_bytes BLOB NOT NULL, old_config_hash TEXT NOT NULL,
    old_manifest_json TEXT NOT NULL, new_manifest_json TEXT NOT NULL,
    contract_json TEXT NOT NULL, rules_json TEXT NOT NULL, state TEXT NOT NULL, at INTEGER
);
CREATE TABLE IF NOT EXISTS custody_anchors(
    anchor_id TEXT PRIMARY KEY, migration_id TEXT NOT NULL, workload TEXT NOT NULL, node_id TEXT NOT NULL,
    node_version TEXT NOT NULL, node_generation INTEGER NOT NULL, config_version TEXT NOT NULL,
    old_config_hash TEXT NOT NULL, old_config_bytes BLOB NOT NULL, object_version INTEGER NOT NULL,
    baseline_hash TEXT NOT NULL, contract_json TEXT NOT NULL, rules_json TEXT NOT NULL,
    authorization_json TEXT NOT NULL, state TEXT NOT NULL, at INTEGER
);
CREATE TABLE IF NOT EXISTS custody_fences(
    workload TEXT PRIMARY KEY, epoch INTEGER NOT NULL, state TEXT NOT NULL,
    committer_role TEXT NOT NULL, committer_id TEXT NOT NULL, token TEXT NOT NULL,
    new_ingress TEXT NOT NULL, head_version INTEGER NOT NULL,
    frozen_at INTEGER, handoff_at INTEGER, updated_at INTEGER
);
CREATE TABLE IF NOT EXISTS custody_handoffs(
    workload TEXT NOT NULL, epoch INTEGER NOT NULL, anchor_id TEXT,
    from_role TEXT, from_committer TEXT, to_role TEXT NOT NULL, to_committer TEXT NOT NULL,
    token TEXT NOT NULL, at INTEGER, PRIMARY KEY(workload, epoch)
);
CREATE TABLE IF NOT EXISTS custody_commands(
    workload TEXT NOT NULL, command_id TEXT NOT NULL, client_request_id TEXT, seq INTEGER NOT NULL,
    op TEXT NOT NULL, api TEXT NOT NULL, source TEXT NOT NULL, object_type TEXT NOT NULL,
    object_uid TEXT NOT NULL, object_name TEXT NOT NULL, payload_json TEXT NOT NULL, payload_hash TEXT NOT NULL,
    fence_epoch INTEGER NOT NULL, fence_token_hash TEXT NOT NULL, at INTEGER, status TEXT NOT NULL,
    PRIMARY KEY(workload, command_id), UNIQUE(workload, seq), UNIQUE(workload, client_request_id)
);
CREATE TABLE IF NOT EXISTS custody_acks(
    ack_id TEXT PRIMARY KEY, workload TEXT NOT NULL, command_id TEXT NOT NULL, seq INTEGER NOT NULL,
    object_uid TEXT NOT NULL, object_version INTEGER NOT NULL, decision TEXT NOT NULL,
    receipt_json TEXT NOT NULL, notification_ids_json TEXT NOT NULL, at INTEGER,
    UNIQUE(workload, command_id)
);
CREATE TABLE IF NOT EXISTS custody_objects(
    workload TEXT NOT NULL, object_uid TEXT NOT NULL, name TEXT NOT NULL, object_type TEXT NOT NULL,
    api_format TEXT NOT NULL, state TEXT NOT NULL, current_version INTEGER NOT NULL,
    bytes BLOB NOT NULL, payload_hash TEXT NOT NULL, reversible INTEGER NOT NULL,
    classification_json TEXT NOT NULL, updated_at INTEGER, PRIMARY KEY(workload, object_uid)
);
CREATE UNIQUE INDEX IF NOT EXISTS custody_objects_alive_name
    ON custody_objects(workload, name) WHERE state='alive';
CREATE TABLE IF NOT EXISTS custody_object_versions(
    workload TEXT NOT NULL, object_uid TEXT NOT NULL, version INTEGER NOT NULL, command_id TEXT NOT NULL,
    op TEXT NOT NULL, api_format TEXT NOT NULL, bytes BLOB NOT NULL, payload_hash TEXT NOT NULL,
    reversible INTEGER NOT NULL, classification_json TEXT NOT NULL, at INTEGER,
    PRIMARY KEY(workload, object_uid, version)
);
CREATE TABLE IF NOT EXISTS custody_notifications(
    notification_id TEXT PRIMARY KEY, workload TEXT NOT NULL, command_id TEXT, object_uid TEXT,
    kind TEXT NOT NULL, destination TEXT, payload_json TEXT NOT NULL, state TEXT NOT NULL,
    sent_at INTEGER, corrects_notification_id TEXT, correction_id TEXT
);
CREATE TABLE IF NOT EXISTS custody_baseline_objects(
    anchor_id TEXT NOT NULL, workload TEXT NOT NULL, object_uid TEXT NOT NULL, name TEXT NOT NULL,
    object_version INTEGER NOT NULL, old_bytes BLOB NOT NULL, old_hash TEXT NOT NULL,
    PRIMARY KEY(anchor_id, object_uid)
);
CREATE TABLE IF NOT EXISTS custody_old_objects(
    workload TEXT NOT NULL, name TEXT NOT NULL, object_uid TEXT NOT NULL, object_version INTEGER NOT NULL,
    bytes BLOB NOT NULL, hash TEXT NOT NULL, state TEXT NOT NULL, updated_at INTEGER,
    PRIMARY KEY(workload, name)
);
CREATE TABLE IF NOT EXISTS custody_recoveries(
    anchor_id TEXT PRIMARY KEY, migration_id TEXT NOT NULL, workload TEXT NOT NULL,
    requested_path TEXT NOT NULL, actual_path TEXT, decision TEXT NOT NULL, state TEXT NOT NULL,
    lossless INTEGER, assessment_json TEXT NOT NULL, plan_json TEXT NOT NULL,
    checkpoint_seq INTEGER NOT NULL, approval_json TEXT NOT NULL, result_json TEXT NOT NULL,
    started_at INTEGER, updated_at INTEGER, completed_at INTEGER
);
CREATE TABLE IF NOT EXISTS custody_recovery_items(
    anchor_id TEXT NOT NULL, seq INTEGER NOT NULL, command_id TEXT NOT NULL, stage TEXT NOT NULL,
    state TEXT NOT NULL, attempts INTEGER NOT NULL, detail_json TEXT NOT NULL, updated_at INTEGER,
    PRIMARY KEY(anchor_id, seq, stage)
);
CREATE TABLE IF NOT EXISTS custody_compat_repairs(
    anchor_id TEXT PRIMARY KEY, migration_id TEXT NOT NULL, workload TEXT NOT NULL,
    old_api TEXT NOT NULL, new_api TEXT NOT NULL, state TEXT NOT NULL,
    view_contract_json TEXT NOT NULL, preserved_json TEXT NOT NULL, approval_json TEXT NOT NULL,
    correction_ids_json TEXT NOT NULL, token TEXT NOT NULL, epoch INTEGER NOT NULL, at INTEGER
);
CREATE TABLE IF NOT EXISTS custody_corrections(
    correction_id TEXT PRIMARY KEY, anchor_id TEXT NOT NULL, migration_id TEXT NOT NULL,
    workload TEXT NOT NULL, object_uid TEXT, field_path TEXT, kind TEXT NOT NULL,
    summary TEXT NOT NULL, detail_json TEXT NOT NULL, notification_id TEXT, at INTEGER
);
""")
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

def _json_default(value):
    if isinstance(value, (bytes, bytearray)):
        return {'__bytes_b64__': base64.b64encode(bytes(value)).decode('ascii')}
    if isinstance(value, sqlite3.Row):
        return dict(value)
    if hasattr(value, 'isoformat'):
        return value.isoformat()
    return str(value)

def record(db, subsystem, object_id, event, version, detail):
    db.execute('INSERT INTO evidence(subsystem,object_id,event,version,detail) VALUES(?,?,?,?,?)',
               (subsystem,object_id,event,version,json.dumps(detail,ensure_ascii=False,sort_keys=True,default=_json_default)))

def report(db):
    return [dict(row) for row in db.execute('SELECT * FROM evidence ORDER BY id')]

def audit_run(subsystem):
    def decorate(fn):
        def wrapped(db, payload):
            with transaction(db):
                result=fn(db,payload)
                object_id=str(payload.get('id') or payload.get('anchor_id') or payload.get('command_id') or payload.get('pool') or payload.get('service') or 'unknown')
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
