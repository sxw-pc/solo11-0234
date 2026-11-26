import json
import sqlite3
from contextlib import contextmanager


def ensure_schema(db):
    db.execute('CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY, subsystem TEXT NOT NULL, object_id TEXT NOT NULL, event TEXT NOT NULL, version INTEGER NOT NULL, detail TEXT NOT NULL)')
    db.executescript("""
CREATE TABLE IF NOT EXISTS nodes(
    id TEXT PRIMARY KEY, architecture TEXT, features TEXT, generation INTEGER,
    observed_at INTEGER, version TEXT, verified_at INTEGER, zone TEXT
);
CREATE TABLE IF NOT EXISTS api_usage(
    id TEXT PRIMARY KEY, workload TEXT, api TEXT, generation INTEGER, state TEXT
);
CREATE TABLE IF NOT EXISTS waves(
    id TEXT PRIMARY KEY, target TEXT, parent TEXT, max_unavailable INTEGER,
    zone_budgets TEXT, state TEXT
);
CREATE TABLE IF NOT EXISTS transitions(
    id TEXT PRIMARY KEY, wave_id TEXT, node_id TEXT, zone TEXT,
    node_generation INTEGER, released_at INTEGER, state TEXT
);
CREATE TABLE IF NOT EXISTS transition_probes(
    id TEXT PRIMARY KEY, transition_id TEXT, node_generation INTEGER,
    target TEXT, at INTEGER, healthy INTEGER,
    fault_category TEXT, detail_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS migrations(
    id TEXT PRIMARY KEY, workload TEXT, old_api TEXT, new_api TEXT,
    expected TEXT, observed TEXT, baseline_config TEXT, state TEXT
);
CREATE TABLE IF NOT EXISTS rollbacks(
    id TEXT PRIMARY KEY, migration_id TEXT, node_id TEXT, node_version TEXT,
    config_version TEXT, state TEXT
);
CREATE TABLE IF NOT EXISTS workload_configs(
    workload TEXT PRIMARY KEY, version TEXT, state TEXT
);

CREATE TABLE IF NOT EXISTS warranty_contracts(
    id TEXT PRIMARY KEY,
    vendor TEXT NOT NULL,
    entitlement_id TEXT NOT NULL,
    device_id TEXT,
    buyer TEXT,
    bank_account_id TEXT,
    account_owner TEXT,
    active_from INTEGER NOT NULL,
    active_to INTEGER NOT NULL,
    categories_json TEXT NOT NULL,
    replacement_model TEXT,
    replacement_capacity TEXT,
    replacement_warranty_days INTEGER,
    cash_amount NUMERIC,
    currency TEXT NOT NULL DEFAULT 'CNY',
    core_disposition TEXT NOT NULL DEFAULT 'return_vendor',
    terms_json TEXT NOT NULL DEFAULT '{}',
    state TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS warranty_claims(
    id TEXT PRIMARY KEY,
    transition_id TEXT NOT NULL,
    vendor TEXT NOT NULL,
    state TEXT NOT NULL,
    fault_key TEXT,
    contract_id TEXT,
    entitlement_id TEXT,
    device_id TEXT,
    buyer TEXT,
    fault_category TEXT,
    fault_at INTEGER,
    selected_remedy TEXT,
    completion_boundary TEXT,
    required_cash NUMERIC NOT NULL DEFAULT 0,
    cash_gross NUMERIC NOT NULL DEFAULT 0,
    cash_reversed NUMERIC NOT NULL DEFAULT 0,
    required_quantity NUMERIC NOT NULL DEFAULT 1,
    accepted_quantity NUMERIC NOT NULL DEFAULT 0,
    restored_quantity NUMERIC NOT NULL DEFAULT 0,
    core_state TEXT NOT NULL DEFAULT 'pending',
    spec_json TEXT NOT NULL DEFAULT '{}',
    obligations_json TEXT NOT NULL DEFAULT '[]',
    created_at INTEGER
);

CREATE TABLE IF NOT EXISTS warranty_documents(
    id TEXT PRIMARY KEY,
    logical_id TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    claim_id TEXT,
    kind TEXT NOT NULL,
    external_ref TEXT,
    occurred_at INTEGER,
    payload_json TEXT NOT NULL,
    UNIQUE(logical_id, version)
);

CREATE TABLE IF NOT EXISTS warranty_quotes(
    id TEXT PRIMARY KEY,
    claim_id TEXT NOT NULL,
    vendor TEXT,
    at INTEGER,
    covered INTEGER NOT NULL DEFAULT 1,
    category TEXT,
    scope_json TEXT,
    replacement_model TEXT,
    replacement_capacity TEXT,
    replacement_warranty_days INTEGER,
    cash_amount NUMERIC,
    currency TEXT,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS warranty_shipments(
    id TEXT PRIMARY KEY,
    claim_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    direction TEXT NOT NULL,
    carrier TEXT,
    tracking_ref TEXT,
    status TEXT NOT NULL,
    model TEXT,
    capacity TEXT,
    warranty_days INTEGER,
    quantity NUMERIC,
    link_id TEXT,
    occurred_at INTEGER,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS warehouse_receipts(
    id TEXT PRIMARY KEY,
    claim_id TEXT,
    shipment_id TEXT,
    source_type TEXT NOT NULL,
    source_id TEXT,
    supplier TEXT,
    payer TEXT,
    model TEXT,
    capacity TEXT,
    warranty_days INTEGER,
    delivered_quantity NUMERIC NOT NULL DEFAULT 0,
    accepted_quantity NUMERIC NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    reason TEXT,
    signed_at INTEGER,
    inspected_at INTEGER,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS warehouse_stock(
    id TEXT PRIMARY KEY,
    receipt_id TEXT,
    claim_id TEXT,
    source_type TEXT NOT NULL,
    source_id TEXT,
    supplier TEXT,
    payer TEXT,
    model TEXT,
    capacity TEXT,
    warranty_days INTEGER,
    quantity NUMERIC NOT NULL,
    available_quantity NUMERIC NOT NULL,
    state TEXT NOT NULL DEFAULT 'available',
    received_at INTEGER,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS warehouse_movements(
    id TEXT PRIMARY KEY,
    stock_id TEXT,
    claim_id TEXT,
    kind TEXT NOT NULL,
    quantity NUMERIC NOT NULL,
    at INTEGER,
    source_type TEXT,
    source_id TEXT,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bank_receipts(
    id TEXT PRIMARY KEY,
    claim_id TEXT NOT NULL,
    amount NUMERIC NOT NULL,
    currency TEXT,
    account_id TEXT,
    account_owner TEXT,
    reference TEXT,
    received_at INTEGER,
    status TEXT NOT NULL,
    attribution TEXT,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bank_reversals(
    id TEXT PRIMARY KEY,
    receipt_id TEXT NOT NULL,
    claim_id TEXT NOT NULL,
    amount NUMERIC NOT NULL,
    at INTEGER,
    reason TEXT,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS purchase_orders(
    id TEXT PRIMARY KEY,
    claim_id TEXT NOT NULL,
    supplier TEXT NOT NULL,
    payer TEXT,
    model TEXT,
    capacity TEXT,
    warranty_days INTEGER,
    quantity NUMERIC NOT NULL,
    amount NUMERIC,
    currency TEXT,
    state TEXT NOT NULL,
    paid_amount NUMERIC NOT NULL DEFAULT 0,
    created_at INTEGER,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS purchase_payments(
    id TEXT PRIMARY KEY,
    purchase_order_id TEXT NOT NULL,
    amount NUMERIC NOT NULL,
    at INTEGER,
    payer TEXT,
    reference TEXT,
    payload_json TEXT NOT NULL
);

CREATE VIEW IF NOT EXISTS warehouse_inventory AS
    SELECT * FROM warehouse_stock;
CREATE VIEW IF NOT EXISTS bank_settlements AS
    SELECT * FROM bank_receipts;
""")

    # Lightweight migrations for databases created by the initial seed.
    def columns(table):
        return {row[1] for row in db.execute(f'PRAGMA table_info({table})')}

    probe_columns = columns('transition_probes')
    if 'fault_category' not in probe_columns:
        db.execute('ALTER TABLE transition_probes ADD COLUMN fault_category TEXT')
    if 'detail_json' not in probe_columns:
        db.execute("ALTER TABLE transition_probes ADD COLUMN detail_json TEXT NOT NULL DEFAULT '{}'")

    claim_columns = columns('warranty_claims')
    claim_additions = {
        'fault_key': 'TEXT',
        'contract_id': 'TEXT',
        'entitlement_id': 'TEXT',
        'device_id': 'TEXT',
        'buyer': 'TEXT',
        'fault_category': 'TEXT',
        'fault_at': 'INTEGER',
        'selected_remedy': 'TEXT',
        'completion_boundary': 'TEXT',
        'required_cash': "NUMERIC NOT NULL DEFAULT 0",
        'cash_gross': "NUMERIC NOT NULL DEFAULT 0",
        'cash_reversed': "NUMERIC NOT NULL DEFAULT 0",
        'required_quantity': "NUMERIC NOT NULL DEFAULT 1",
        'accepted_quantity': "NUMERIC NOT NULL DEFAULT 0",
        'restored_quantity': "NUMERIC NOT NULL DEFAULT 0",
        'core_state': "TEXT NOT NULL DEFAULT 'pending'",
        'spec_json': "TEXT NOT NULL DEFAULT '{}'",
        'obligations_json': "TEXT NOT NULL DEFAULT '[]'",
        'created_at': 'INTEGER',
    }
    for name, declaration in claim_additions.items():
        if name not in claim_columns:
            db.execute(f'ALTER TABLE warranty_claims ADD COLUMN {name} {declaration}')

    db.execute("UPDATE warranty_claims SET fault_key=transition_id WHERE fault_key IS NULL OR fault_key=''")
    # Fresh databases get hard uniqueness. Legacy databases with accidental
    # duplicate rows must still open; new writes are guarded in warranty code
    # and receive a non-unique lookup index until operators clean the history.
    try:
        db.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_warranty_claims_fault ON warranty_claims(fault_key)')
        db.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_warranty_claims_transition ON warranty_claims(transition_id)')
    except sqlite3.IntegrityError:
        db.execute('CREATE INDEX IF NOT EXISTS idx_warranty_claims_fault_lookup ON warranty_claims(fault_key)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_warranty_claims_transition_lookup ON warranty_claims(transition_id)')


def connect(filename):
    db = sqlite3.connect(filename, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA busy_timeout=3000')
    ensure_schema(db)
    return db


@contextmanager
def transaction(db):
    nested = db.in_transaction
    db.execute('SAVEPOINT nested_action' if nested else 'BEGIN IMMEDIATE')
    try:
        yield
        db.execute('RELEASE SAVEPOINT nested_action' if nested else 'COMMIT')
    except BaseException:
        if nested:
            db.execute('ROLLBACK TO SAVEPOINT nested_action')
            db.execute('RELEASE SAVEPOINT nested_action')
        else:
            db.execute('ROLLBACK')
        raise


def record(db, subsystem, object_id, event, version, detail):
    db.execute('INSERT INTO evidence(subsystem,object_id,event,version,detail) VALUES(?,?,?,?,?)',
               (subsystem, object_id, event, version,
                json.dumps(detail, ensure_ascii=False, sort_keys=True, default=str)))


def report(db):
    return [dict(row) for row in db.execute('SELECT * FROM evidence ORDER BY id')]


def audit_run(subsystem):
    def decorate(fn):
        def wrapped(db, payload):
            with transaction(db):
                result = fn(db, payload)
                object_id = str(payload.get('id') or payload.get('pool') or payload.get('service') or 'unknown')
                record(db, subsystem, object_id, 'decision', int(payload.get('generation', 0)),
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
        fact = json.loads(entry['detail'])
        subsystem = entry['subsystem']
        module = modules.get(subsystem)
        if module is None:
            # Tolerate local import aliases in the replay module mapping.
            for candidate in modules.values():
                module_name = getattr(candidate, '__name__', '').rsplit('.', 1)[-1]
                if module_name == subsystem or getattr(candidate, 'AUDIT_SUBSYSTEM', None) == subsystem:
                    module = candidate
                    break
        actual = module.run(target, fact['input'])
        if actual != fact['result']:
            divergences.append({'step': index, 'subsystem': entry['subsystem'], 'expected': fact['result'], 'actual': actual})
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
