import json
import sqlite3
from contextlib import contextmanager

def connect(filename):
    db=sqlite3.connect(filename, isolation_level=None)
    db.row_factory=sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA busy_timeout=3000')
    db.execute('CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY, subsystem TEXT NOT NULL, object_id TEXT NOT NULL, event TEXT NOT NULL, version INTEGER NOT NULL, detail TEXT NOT NULL)')
    db.executescript("\nCREATE TABLE IF NOT EXISTS nodes(id TEXT PRIMARY KEY, architecture TEXT, features TEXT, generation INTEGER, observed_at INTEGER, version TEXT, verified_at INTEGER, zone TEXT);\n    CREATE TABLE IF NOT EXISTS api_usage(id TEXT PRIMARY KEY, workload TEXT, api TEXT, generation INTEGER, state TEXT);\nCREATE TABLE IF NOT EXISTS waves(id TEXT PRIMARY KEY, target TEXT, parent TEXT, max_unavailable INTEGER, zone_budgets TEXT, state TEXT);\n    CREATE TABLE IF NOT EXISTS transitions(id TEXT PRIMARY KEY, wave_id TEXT, node_id TEXT, zone TEXT, node_generation INTEGER, released_at INTEGER, state TEXT, artifact_id TEXT);\n    CREATE TABLE IF NOT EXISTS transition_probes(id TEXT PRIMARY KEY, transition_id TEXT, node_generation INTEGER, target TEXT, at INTEGER, healthy INTEGER);\nCREATE TABLE IF NOT EXISTS migrations(id TEXT PRIMARY KEY, workload TEXT, old_api TEXT, new_api TEXT, expected TEXT, observed TEXT, baseline_config TEXT, state TEXT);\n    CREATE TABLE IF NOT EXISTS rollbacks(id TEXT PRIMARY KEY, migration_id TEXT, node_id TEXT, node_version TEXT, config_version TEXT, state TEXT);\n    CREATE TABLE IF NOT EXISTS workload_configs(workload TEXT PRIMARY KEY, version TEXT, state TEXT);\nCREATE TABLE IF NOT EXISTS artifacts(id TEXT PRIMARY KEY, target TEXT, architecture TEXT, binary_digest TEXT UNIQUE, build_inputs_digest TEXT, compiler TEXT, generated_code_digest TEXT, embedded_resources_digest TEXT, rebuild_digest TEXT, rebuild_verified INTEGER, state TEXT);\nCREATE TABLE IF NOT EXISTS artifact_components(artifact_id TEXT, component TEXT, stage TEXT, source_revision TEXT, component_digest TEXT, license TEXT, origin TEXT, parent_component TEXT, layer_digest TEXT, signature TEXT, PRIMARY KEY(artifact_id, component, component_digest));\nCREATE TABLE IF NOT EXISTS runtime_attestations(node_id TEXT, generation INTEGER, attested_at INTEGER, PRIMARY KEY(node_id, generation));\nCREATE TABLE IF NOT EXISTS runtime_loads(node_id TEXT, generation INTEGER, component TEXT, source_revision TEXT, component_digest TEXT, layer_digest TEXT, signature TEXT, observed_at INTEGER, PRIMARY KEY(node_id, generation, component));\nCREATE TABLE IF NOT EXISTS source_archives(id TEXT PRIMARY KEY, component TEXT, source_revision TEXT, component_digest TEXT, source_digest TEXT, license TEXT, build_instructions_digest TEXT, contents_digest TEXT, complete INTEGER, state TEXT, superseded_by TEXT, created_at INTEGER);\nCREATE TABLE IF NOT EXISTS source_bundles(id TEXT PRIMARY KEY, artifact_id TEXT, node_id TEXT, manifest_digest TEXT, bundle_digest TEXT, state TEXT, reason TEXT, supersedes TEXT, created_at INTEGER);\nCREATE TABLE IF NOT EXISTS bundle_archives(bundle_id TEXT, archive_id TEXT, component TEXT, component_digest TEXT, PRIMARY KEY(bundle_id, component, component_digest));\nCREATE TABLE IF NOT EXISTS delivery_approvals(id TEXT PRIMARY KEY, artifact_id TEXT, methods TEXT, recipients TEXT, valid_until INTEGER, state TEXT);\nCREATE TABLE IF NOT EXISTS custodians(id TEXT PRIMARY KEY, name TEXT, independent INTEGER, state TEXT);\nCREATE TABLE IF NOT EXISTS escrows(id TEXT PRIMARY KEY, custodian_id TEXT, bundle_id TEXT, bundle_digest TEXT, state TEXT, replaced_by TEXT, created_at INTEGER);\nCREATE TABLE IF NOT EXISTS distributions(id TEXT PRIMARY KEY, customer TEXT, node_id TEXT, artifact_id TEXT, bundle_id TEXT, at INTEGER, state TEXT);\nCREATE TABLE IF NOT EXISTS delivery_obligations(distribution_id TEXT PRIMARY KEY, customer TEXT, artifact_id TEXT, method TEXT, state TEXT, bundle_id TEXT, created_at INTEGER, updated_at INTEGER);\nCREATE TABLE IF NOT EXISTS delivery_receipts(id TEXT PRIMARY KEY, distribution_id TEXT, method TEXT, bundle_id TEXT, bundle_digest TEXT, customer TEXT, received_at INTEGER, state TEXT, superseded INTEGER);\nCREATE TABLE IF NOT EXISTS offer_letters(id TEXT PRIMARY KEY, distribution_id TEXT, escrow_id TEXT, custodian_id TEXT, valid_until INTEGER, signature TEXT, state TEXT, issued_at INTEGER);\nCREATE TABLE IF NOT EXISTS source_requests(id TEXT PRIMARY KEY, offer_id TEXT, distribution_id TEXT, customer TEXT, requested_at INTEGER, state TEXT, credential TEXT);\nCREATE TABLE IF NOT EXISTS fulfillments(id TEXT PRIMARY KEY, request_id TEXT, distribution_id TEXT, custodian_id TEXT, bundle_digest TEXT, fulfilled_at INTEGER, state TEXT);\nCREATE TABLE IF NOT EXISTS customer_flags(distribution_id TEXT, customer TEXT, reason TEXT, bundle_id TEXT, flagged_at INTEGER, PRIMARY KEY(distribution_id, reason));")
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
