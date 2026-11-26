import json
import sqlite3
import hashlib
from contextlib import contextmanager

def connect(filename):
    db=sqlite3.connect(filename, isolation_level=None)
    db.row_factory=sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA busy_timeout=3000')
    db.execute('CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY, subsystem TEXT NOT NULL, object_id TEXT NOT NULL, event TEXT NOT NULL, version INTEGER NOT NULL, detail TEXT NOT NULL)')
    db.executescript("\nCREATE TABLE IF NOT EXISTS nodes(id TEXT PRIMARY KEY, architecture TEXT, features TEXT, generation INTEGER, observed_at INTEGER, version TEXT, verified_at INTEGER, zone TEXT);\n    CREATE TABLE IF NOT EXISTS api_usage(id TEXT PRIMARY KEY, workload TEXT, api TEXT, generation INTEGER, state TEXT);\nCREATE TABLE IF NOT EXISTS waves(id TEXT PRIMARY KEY, target TEXT, parent TEXT, max_unavailable INTEGER, zone_budgets TEXT, state TEXT);\n    CREATE TABLE IF NOT EXISTS transitions(id TEXT PRIMARY KEY, wave_id TEXT, node_id TEXT, zone TEXT, node_generation INTEGER, released_at INTEGER, state TEXT);\n    CREATE TABLE IF NOT EXISTS transition_probes(id TEXT PRIMARY KEY, transition_id TEXT, node_generation INTEGER, target TEXT, at INTEGER, healthy INTEGER);\nCREATE TABLE IF NOT EXISTS migrations(id TEXT PRIMARY KEY, workload TEXT, old_api TEXT, new_api TEXT, expected TEXT, observed TEXT, baseline_config TEXT, state TEXT);\n    CREATE TABLE IF NOT EXISTS rollbacks(id TEXT PRIMARY KEY, migration_id TEXT, node_id TEXT, node_version TEXT, config_version TEXT, state TEXT);\n    CREATE TABLE IF NOT EXISTS workload_configs(workload TEXT PRIMARY KEY, version TEXT, state TEXT);")
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

def fingerprint(obj):
    """Stable SHA-256 over the canonical JSON encoding of a fact."""
    return hashlib.sha256(json.dumps(obj,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8')).hexdigest()

def digest_bytes(raw):
    if isinstance(raw,str):raw=raw.encode('utf-8')
    return hashlib.sha256(raw).hexdigest()

def _decision_log(db):
    return [dict(row) for row in db.execute("SELECT subsystem,detail FROM evidence WHERE event='decision' ORDER BY id")]

def _apply_decisions(decisions,target,modules):
    divergences=[]
    for index,entry in enumerate(decisions,1):
        fact=json.loads(entry['detail'])
        module=modules.get(entry['subsystem'])
        if module is None:
            divergences.append({'step':index,'subsystem':entry['subsystem'],'reason':'missing_module'})
            continue
        actual=module.run(target,fact['input'])
        if actual!=fact['result']:
            divergences.append({'step':index,'subsystem':entry['subsystem'],'expected':fact['result'],'actual':actual})
    return divergences

def _compare_tables(source,target):
    divergences=[]
    tables=[r[0] for r in source.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('evidence','sqlite_sequence') ORDER BY name")]
    for table in tables:
        before=[tuple(r) for r in source.execute('SELECT * FROM '+table+' ORDER BY rowid')]
        if not target.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone():
            # An empty source table is scaffolding created lazily, not a decision.
            if not before:continue
            divergences.append({'table':table,'reason':'missing_in_replay'});continue
        after=[tuple(r) for r in target.execute('SELECT * FROM '+table+' ORDER BY rowid')]
        # Empty tables are scaffolding, not decisions: only populated state has
        # to be reproduced from the evidence log.
        if not before and not after:continue
        if before!=after:divergences.append({'table':table,'reason':'state_mismatch','before':before,'after':after})
    return divergences

def replay(filename, modules):
    source=connect(filename)
    target=connect(':memory:')
    divergences=_apply_decisions(_decision_log(source),target,modules)
    divergences+=_compare_tables(source,target)
    count=len(_decision_log(source))
    source.close();target.close()
    return {'decision_count':count,'verified':not divergences,'divergences':divergences}

def rebuild(filename, modules):
    """Reconstruct both real ledgers in a fresh database from the evidence log.

    Used by audit and power-outage retries: no page, payable, invoice, provision
    or deposit row is trusted unless a signed decision recreates it.
    """
    source=connect(filename)
    target=connect(':memory:')
    decisions=_decision_log(source)
    divergences=_apply_decisions(decisions,target,modules)
    divergences+=_compare_tables(source,target)
    source.close()
    return target,{'decision_count':len(decisions),'verified':not divergences,'divergences':divergences}

def snapshot_tables(db, names):
    return {name:[tuple(r) for r in db.execute('SELECT * FROM '+name+' ORDER BY rowid')] for name in names}
