"""Actual delivery and settlement for device warranty remedies.

The module intentionally treats external promises (portal states, credit
notes, carrier events) as evidence only.  Inventory changes only after
warehouse conformance acceptance, and cash relief counts only after settled
bank credit with matching attribution.  Both boundaries are mutually
exclusive for one fault.
"""

import json
import re
from decimal import Decimal, InvalidOperation

from .store import transaction, audit_run, ensure_schema
from . import warranty

REMEDY_ALIASES = {
    'replace': 'replacement',
    'replacement': 'replacement',
    'free_replacement': 'replacement',
    'free_item': 'replacement',
    'unit': 'replacement',
    'part': 'replacement',
    'goods': 'replacement',
    'item': 'replacement',
    'cash': 'cash',
    'money': 'cash',
    'bank': 'cash',
    'refund': 'cash',
    'credit': 'cash',
    'cash_settlement': 'cash',
}

BANK_SETTLED_STATUSES = {'settled', 'posted', 'received', 'completed', 'complete', 'credited', 'cleared'}
BANK_PENDING_STATUSES = {'pending', 'initiated', 'in_transit', 'processing', 'expected'}
NON_BANK_INSTRUMENTS = {
    'credit_memo', 'credit_note', 'memo', 'promise', 'commitment',
    'commitment_letter', 'portal', 'vendor_portal', 'portal_paid',
    'paid_marker', 'letter',
}


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def run(db, payload):
    """Public entry point used by tests and event replay."""
    ensure_schema(db)
    return _audited_run(db, payload)


@audit_run('warranty_resolution')
def _audited_run(db, x):
    with transaction(db):
        op = _normalize_op(x.get('op', 'run'))
        handler = OPS.get(op) or OPS.get(x.get('op'))
        if handler is None:
            raise ValueError(x.get('op'))
        return handler(db, x)


def _normalize_op(op):
    return re.sub(r'[\s-]+', '_', str(op or '')).strip().lower()


def _pick(x, *keys):
    for key in keys:
        if key in x and x[key] is not None:
            return x[key]
    return None


def _nested(x, key):
    value = x.get(key)
    return value if isinstance(value, dict) else {}


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _loads(value, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _row(db, sql, args=()):
    row = db.execute(sql, args).fetchone()
    return dict(row) if row is not None else None


def _rows(db, sql, args=()):
    return [dict(row) for row in db.execute(sql, args).fetchall()]


def _blocked(reason, **extra):
    result = {'decision': 'blocked', 'reason': reason}
    result.update(extra)
    return result


def _replay(**extra):
    extra.pop('decision', None)
    result = dict(extra)
    result['decision'] = 'replay'
    return result


def _money(value, default=0):
    if value is None:
        return default
    if isinstance(value, bool):
        raise ValueError('boolean is not money')
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value
    text = str(value).strip().replace(',', '')
    try:
        decimal = Decimal(text)
    except InvalidOperation:
        raise ValueError(f'invalid money: {value!r}')
    if not decimal.is_finite():
        raise ValueError(f'invalid money: {value!r}')
    return int(decimal) if decimal == decimal.to_integral_value() else float(decimal)


def _add_money(a, b):
    result = Decimal(str(_money(a))) + Decimal(str(_money(b)))
    return int(result) if result == result.to_integral_value() else float(result)


def _sub_money(a, b):
    result = Decimal(str(_money(a))) - Decimal(str(_money(b)))
    return int(result) if result == result.to_integral_value() else float(result)


def _money_at_least(a, b):
    return Decimal(str(_money(a))) >= Decimal(str(_money(b)))


def _normalize_remedy(value):
    if value is None:
        return None
    key = _normalize_op(value)
    return REMEDY_ALIASES.get(key, key if key in ('replacement', 'cash') else None)


def _capacity_gb(value):
    if value is None or value == '':
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return Decimal(str(value))
    text = str(value).strip().lower().replace(' ', '').replace('gb', 'gb').replace('gigabytes', 'gb')
    match = re.fullmatch(r'([0-9]+(?:\.[0-9]+)?)(tb|gb|mb|t|g|m)?', text)
    if not match:
        return None
    amount = Decimal(match.group(1))
    unit = match.group(2) or 'gb'
    factor = {'tb': 1024, 't': 1024, 'gb': 1, 'g': 1, 'mb': Decimal(1) / 1024, 'm': Decimal(1) / 1024}[unit]
    return amount * factor


def _spec_mismatches(expected, actual):
    """Return concrete conformance failures; empty list means conforming."""
    mismatches = []
    expected_model = expected.get('model') or expected.get('replacement_model')
    actual_model = actual.get('model') or actual.get('replacement_model')
    if expected_model is not None:
        if actual_model is None or str(actual_model).strip().casefold() != str(expected_model).strip().casefold():
            mismatches.append('model_mismatch')

    expected_capacity = expected.get('capacity') or expected.get('replacement_capacity')
    actual_capacity = actual.get('capacity') or actual.get('replacement_capacity')
    if expected_capacity is not None:
        left = _capacity_gb(expected_capacity)
        right = _capacity_gb(actual_capacity)
        if left is None or right is None or right < left:
            mismatches.append('capacity_mismatch')

    expected_days = expected.get('warranty_days') or expected.get('replacement_warranty_days')
    actual_days = actual.get('warranty_days') or expected.get('warranty_term_days') or actual.get('warranty_term_days')
    if expected_days is not None:
        try:
            if actual_days is None or int(actual_days) < int(expected_days):
                mismatches.append('warranty_term_mismatch')
        except (TypeError, ValueError):
            mismatches.append('warranty_term_mismatch')
    return mismatches


def _claim(db, claim_id):
    if not claim_id:
        return None
    return _row(db, 'SELECT * FROM warranty_claims WHERE id=?', (claim_id,))


def _claim_id_of(x):
    return _pick(x, 'claim_id', 'claim', 'id')


def _resolved_claim_id(db, x, existing=None):
    """Resolve a parent claim without confusing a child event id with claim C."""
    claim_id = _pick(x, 'claim_id', 'claim', 'claim_ref')
    if claim_id:
        return claim_id
    for key in ('id',):
        value = x.get(key)
        if value and _claim(db, value):
            return value
    if existing is not None:
        return existing['claim_id'] if isinstance(existing, dict) else existing['claim_id']
    for key in ('receipt_id', 'bank_receipt_id', 'shipment_id', 'reversal_id'):
        value = x.get(key)
        if not value:
            continue
        if key == 'receipt_id':
            row = _row(db, 'SELECT claim_id FROM warehouse_receipts WHERE id=?', (value,))
        elif key == 'bank_receipt_id':
            row = _row(db, 'SELECT claim_id FROM bank_receipts WHERE id=?', (value,))
        elif key == 'shipment_id':
            row = _row(db, 'SELECT claim_id FROM warranty_shipments WHERE id=?', (value,))
        else:
            row = _row(db, 'SELECT claim_id FROM bank_reversals WHERE id=?', (value,))
        if row:
            return row['claim_id']
    return _pick(x, 'id')


def _document(db, document_id):
    return _row(db, 'SELECT * FROM warranty_documents WHERE id=?', (document_id,))


def _add_document(db, document_id, claim_id, kind, payload, at=None,
                  external_ref=None, logical_id=None, version=1):
    if not document_id:
        document_id = f'{kind}:{claim_id}:{at}:{_json(payload)}'
    db.execute(
        """INSERT OR IGNORE INTO warranty_documents
           (id,logical_id,version,claim_id,kind,external_ref,occurred_at,payload_json)
           VALUES(?,?,?,?,?,?,?,?)""",
        (document_id, logical_id or document_id, version, claim_id, kind,
         external_ref or _pick(payload, 'reference', 'external_ref', 'tracking_ref'),
         at if at is not None else _pick(payload, 'at', 'occurred_at', 'received_at'),
         _json(payload)),
    )
    return document_id


def _cash_net(claim):
    if not claim:
        return 0
    return _sub_money(claim['cash_gross'] or 0, claim['cash_reversed'] or 0)


def _cash_complete(claim):
    required = _money(claim['required_cash'] or 0)
    return required > 0 and _money_at_least(_cash_net(claim), required)


def _claim_spec(claim, contract=None, quote=None):
    spec = _loads(claim['spec_json'] if claim else None, {})
    for source in (contract or {}, quote or {}):
        for target_key, source_keys in {
            'model': ('replacement_model', 'model'),
            'capacity': ('replacement_capacity', 'capacity'),
            'warranty_days': ('replacement_warranty_days', 'warranty_days'),
        }.items():
            value = _pick(source, *source_keys) if isinstance(source, dict) else source[source_keys[0]] if source_keys[0] in source.keys() else None
            if value is not None:
                spec[target_key] = value
    return spec


# ---------------------------------------------------------------------------
# Contract and claim binding
# ---------------------------------------------------------------------------

def op_open_claim(db, x):
    claim_id = _pick(x, 'claim_id', 'id')
    transition = _pick(x, 'transition', 'transition_id', 'fault')
    vendor = _pick(x, 'vendor', 'vendor_id')
    return warranty._open_claim(db, claim_id, transition, vendor, x)


def op_contract(db, x):
    p = {**_nested(x, 'contract'), **x}
    cid = _pick(p, 'contract_id', 'id')
    if not cid:
        return _blocked('contract_id_required')
    old = _row(db, 'SELECT * FROM warranty_contracts WHERE id=?', (cid,))
    if old:
        return _replay(contract_id=cid, state=old['state'])

    vendor = _pick(p, 'vendor', 'vendor_id')
    entitlement = _pick(p, 'entitlement_id', 'entitlement', 'equipment_entitlement')
    active_from = _pick(p, 'active_from', 'effective_from', 'start_at', 'starts_at')
    active_to = _pick(p, 'active_to', 'effective_to', 'end_at', 'expires_at', 'expiry')
    if not vendor or not entitlement or active_from is None or active_to is None:
        return _blocked('incomplete_contract')
    if int(active_from) > int(active_to):
        return _blocked('invalid_contract_period')

    categories = _pick(p, 'fault_categories', 'categories', 'covered_categories', 'coverage')
    if categories is None:
        categories = []
    if isinstance(categories, str):
        categories = [part.strip() for part in categories.split(',') if part.strip()]

    cash_amount = _pick(p, 'cash_amount', 'cash_value', 'amount', 'same_value_cash',
                        'coverage_amount', 'settlement_amount', 'compensation_amount',
                        'replacement_value', 'value')
    db.execute(
        """INSERT INTO warranty_contracts
           (id,vendor,entitlement_id,device_id,buyer,bank_account_id,account_owner,
            active_from,active_to,categories_json,replacement_model,replacement_capacity,
            replacement_warranty_days,cash_amount,currency,core_disposition,terms_json,state)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (cid, vendor, entitlement, _pick(p, 'device_id', 'node_id', 'device'),
         _pick(p, 'buyer', 'purchaser', 'procurement_owner'),
         _pick(p, 'bank_account_id', 'account_id'),
         _pick(p, 'account_owner', 'beneficiary', 'expected_owner'),
         int(active_from), int(active_to), _json(categories),
         _pick(p, 'replacement_model', 'model'),
         str(_pick(p, 'replacement_capacity', 'capacity')) if _pick(p, 'replacement_capacity', 'capacity') is not None else None,
         _pick(p, 'replacement_warranty_days', 'warranty_days',
               'warranty_term_days', 'warranty_period_days', 'term_days'),
         _money(cash_amount) if cash_amount is not None else None,
         _pick(p, 'currency') or 'CNY',
         _pick(p, 'core_disposition', 'old_part_disposition') or 'return_vendor',
         _json(_nested(p, 'terms') or {k: v for k, v in p.items() if k not in ('op', 'contract')}),
         _pick(p, 'state') or 'active'),
    )
    _add_document(db, f'contract:{cid}', cid, 'warranty_contract', p,
                  at=active_from, external_ref=cid)
    return {'decision': 'registered', 'contract_id': cid}


def _failed_probe(db, transition):
    # Only a probe matching the persisted transition/wave identity is a
    # verifiable fault sample.  This mirrors wave.finish's identity checks.
    return _row(
        db,
        """SELECT p.*
           FROM transition_probes p
           JOIN transitions tr ON tr.id=p.transition_id
           JOIN waves w ON w.id=tr.wave_id
           WHERE p.transition_id=?
             AND p.healthy=0
             AND p.node_generation=tr.node_generation
             AND p.target=w.target
             AND p.at>=tr.released_at
           ORDER BY p.at ASC, p.id ASC
           LIMIT 1""",
        (transition,),
    )


def op_bind(db, x):
    p = {**_nested(x, 'binding'), **x}
    cid = _claim_id_of(p)
    claim = _claim(db, cid)
    if not claim:
        return _blocked('unknown_claim', claim_id=cid)

    if claim['contract_id']:
        mismatches = {}
        for column, keys in {
            'contract_id': ('contract_id', 'contract'),
            'fault_category': ('fault_category', 'category'),
            'entitlement_id': ('entitlement_id', 'entitlement'),
            'buyer': ('buyer', 'purchaser'),
        }.items():
            value = _pick(p, *keys)
            if value is not None and claim[column] is not None and str(value) != str(claim[column]):
                mismatches[column] = {'expected': claim[column], 'actual': value}
        if mismatches:
            return _blocked('claim_binding_conflict', conflicts=mismatches)
        return _replay(claim_id=cid, state=claim['state'])

    transition = claim['transition_id']
    requested_transition = _pick(p, 'transition', 'transition_id')
    if requested_transition and requested_transition != transition:
        return _blocked('claim_transition_conflict')
    probe = _failed_probe(db, transition)
    if not probe:
        return _blocked('no_failed_probe')

    tr = _row(db, 'SELECT * FROM transitions WHERE id=?', (transition,))
    device_id = (tr['node_id'] if tr else None) or claim['device_id'] or _pick(p, 'device_id', 'node_id')
    fault_at = probe['at']
    requested_fault_at = _pick(p, 'fault_at')
    if requested_fault_at is not None and int(requested_fault_at) != int(fault_at):
        return _blocked('fault_time_conflict')
    category = _pick(p, 'fault_category', 'category') or probe['fault_category']
    contract_id = _pick(p, 'contract_id', 'contract')

    if contract_id:
        contract = _row(db, "SELECT * FROM warranty_contracts WHERE id=? AND state='active'",
                        (contract_id,))
        if not contract:
            return _blocked('unknown_or_inactive_contract', contract_id=contract_id)
    else:
        candidates = _rows(
            db,
            """SELECT * FROM warranty_contracts
               WHERE vendor=? AND active_from<=? AND active_to>=? AND state='active'
               ORDER BY active_from DESC, id""",
            (claim['vendor'], fault_at, fault_at),
        )
        entitlement = _pick(p, 'entitlement_id', 'entitlement')
        candidates = [
            c for c in candidates
            if (not c['device_id'] or not device_id or c['device_id'] == device_id)
            and (not entitlement or c['entitlement_id'] == entitlement)
        ]
        if len(candidates) != 1:
            return _blocked('contract_not_unique_or_effective',
                            candidate_count=len(candidates), fault_at=fault_at)
        contract = candidates[0]

    if contract['vendor'] != claim['vendor']:
        return _blocked('vendor_contract_mismatch')
    if not (contract['active_from'] <= int(fault_at) <= contract['active_to']):
        return _blocked('contract_not_effective_at_fault')
    if contract['device_id'] and device_id and contract['device_id'] != device_id:
        return _blocked('equipment_entitlement_conflict')

    entitlement = _pick(p, 'entitlement_id', 'entitlement') or contract['entitlement_id']
    if entitlement != contract['entitlement_id']:
        return _blocked('equipment_entitlement_conflict')

    categories = _loads(contract['categories_json'], [])
    if not category:
        return _blocked('fault_category_required')
    if categories and '*' not in categories and category not in categories:
        return _blocked('fault_category_not_covered_by_contract', category=category)

    buyer = _pick(p, 'buyer', 'purchaser') or claim['buyer'] or contract['buyer'] or 'procurement'
    # Entitlement comes from the contract, never from a vendor quote/request.
    terms = _loads(contract['terms_json'], {})
    required_cash = contract['cash_amount']
    if required_cash is None:
        required_cash = terms.get('cash_amount') or terms.get('cash_value') or 0
    quantity = _pick(p, 'required_quantity', 'quantity') or terms.get('required_quantity') or 1

    spec = {
        'model': contract['replacement_model'],
        'capacity': contract['replacement_capacity'],
        'warranty_days': contract['replacement_warranty_days'],
    }
    spec.update({k: v for k, v in _nested(p, 'spec').items() if v is not None})

    db.execute(
        """UPDATE warranty_claims SET
             state='bound', contract_id=?, entitlement_id=?, device_id=?, buyer=?,
             fault_category=?, fault_at=?, required_cash=?, required_quantity=?,
             core_state=?, spec_json=?
           WHERE id=?""",
        (contract['id'], entitlement, device_id, buyer, category, int(fault_at),
         _money(required_cash), _money(quantity),
         'buyer_retains' if contract['core_disposition'] == 'buyer_retains' else 'pending_return',
         _json(spec), cid),
    )
    _add_document(db, _pick(p, 'letter_id', 'document_id') or f'binding:{cid}',
                  cid, 'claim_binding', p, at=fault_at)
    return {'decision': 'bound', 'claim_id': cid, 'contract_id': contract['id'],
            'fault_at': fault_at, 'entitlement_id': entitlement}


# ---------------------------------------------------------------------------
# Vendor acknowledgment and quotes
# ---------------------------------------------------------------------------

def op_acknowledge(db, x, default_decision='acknowledged'):
    p = {**_nested(x, 'acknowledgment'), **_nested(x, 'quote'), **x}
    cid = _claim_id_of(p)
    claim = _claim(db, cid)
    if not claim:
        return _blocked('unknown_claim', claim_id=cid)

    qid = _pick(p, 'quote_id', 'acknowledgment_id', 'ack_id', 'id')
    if not qid:
        qid = f'vendor-record:{cid}:{_pick(p, "at")}:{_pick(p, "cash_amount", "amount")}'
    old = _row(db, 'SELECT * FROM warranty_quotes WHERE id=?', (qid,))
    if old:
        return _replay(quote_id=qid, covered=bool(old['covered']))

    if not claim['contract_id']:
        bound = op_bind(db, p)
        if bound.get('decision') == 'blocked':
            return bound
        claim = _claim(db, cid)

    vendor = _pick(p, 'vendor', 'vendor_id')
    if vendor and claim['vendor'] and vendor != claim['vendor']:
        return _blocked('vendor_conflict')

    category = _pick(p, 'fault_category', 'category') or claim['fault_category']
    if category and claim['fault_category'] and category != claim['fault_category']:
        return _blocked('fault_category_conflict')

    covered = _pick(p, 'covered', 'accepted', 'admits', 'admitted', 'approved', 'warranty_covered')
    covered = True if covered is None else bool(covered)
    scope = _pick(p, 'scope', 'coverage_scope', 'admitted_categories', 'covered_categories')
    if isinstance(scope, str):
        scope = [v.strip() for v in scope.split(',') if v.strip()]
    if covered and scope is not None and category and '*' not in scope and category not in scope:
        covered = False

    cash_amount = _pick(p, 'cash_amount', 'cash_offer', 'same_value_cash', 'amount')
    db.execute(
        """INSERT INTO warranty_quotes
           (id,claim_id,vendor,at,covered,category,scope_json,replacement_model,
            replacement_capacity,replacement_warranty_days,cash_amount,currency,payload_json)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (qid, cid, vendor or claim['vendor'], _pick(p, 'at'), int(covered), category,
         _json(scope or []), _pick(p, 'replacement_model', 'model'),
         str(_pick(p, 'replacement_capacity', 'capacity')) if _pick(p, 'replacement_capacity', 'capacity') is not None else None,
         _pick(p, 'replacement_warranty_days', 'warranty_days',
               'warranty_term_days', 'warranty_period_days', 'term_days'),
         _money(cash_amount) if cash_amount is not None else None,
         _pick(p, 'currency') or 'CNY', _json(p)),
    )
    _add_document(db, f'doc:{qid}', cid,
                  'vendor_acknowledgment' if default_decision == 'acknowledged' else 'vendor_quote',
                  p, at=_pick(p, 'at'), external_ref=_pick(p, 'portal_ref', 'reference'))

    if not covered:
        db.execute("UPDATE warranty_claims SET state='denied' WHERE id=?", (cid,))
        return {'decision': 'denied', 'claim_id': cid, 'quote_id': qid}

    spec = _loads(claim['spec_json'], {})
    for key, value in {
        'model': _pick(p, 'replacement_model', 'model'),
        'capacity': _pick(p, 'replacement_capacity', 'capacity'),
        'warranty_days': _pick(p, 'replacement_warranty_days', 'warranty_days'),
    }.items():
        if value is not None:
            spec[key] = value
    if cash_amount is not None and not _money(claim['required_cash'] or 0):
        # The contract is authoritative; this only handles contracts silent
        # about cash, where the admitted vendor quote defines the alternative.
        db.execute('UPDATE warranty_claims SET required_cash=? WHERE id=? AND required_cash=0',
                   (_money(cash_amount), cid))
    db.execute("UPDATE warranty_claims SET state='acknowledged', spec_json=? WHERE id=?",
               (_json(spec), cid))
    return {'decision': default_decision, 'claim_id': cid, 'quote_id': qid, 'covered': True}


def op_quote(db, x):
    return op_acknowledge(db, x, default_decision='quoted')


def op_send_letter(db, x):
    cid = _claim_id_of(x)
    claim = _claim(db, cid)
    if not claim:
        return _blocked('unknown_claim', claim_id=cid)
    letter_id = _pick(x, 'letter_id', 'id', 'document_id')
    if not letter_id:
        return _blocked('letter_id_required')
    version = int(_pick(x, 'version') or 1)
    existing_version = _row(
        db,
        'SELECT id FROM warranty_documents WHERE logical_id=? AND version=?',
        (letter_id, version),
    )
    if existing_version:
        return _replay(letter_id=letter_id, version=version)
    kind = _pick(x, 'kind', 'letter_type') or 'claim_letter'
    document_pk = letter_id if version == 1 else f'{letter_id}#v{version}'
    _add_document(db, document_pk, cid, kind, x, at=_pick(x, 'at', 'sent_at'),
                  external_ref=_pick(x, 'reference'),
                  logical_id=letter_id, version=version)
    return {'decision': 'sent', 'letter_id': letter_id, 'version': version,
            'original_version_preserved': True}


def op_notice(db, x):
    p = x
    cid = _claim_id_of(p)
    kind = _pick(p, 'kind', 'channel', 'notice_type') or 'external_notice'
    nid = _pick(p, 'id', 'notice_id', 'event_id') or f'notice:{cid}:{kind}:{_pick(p, "at")}:{_pick(p, "status")}'
    if _document(db, nid):
        return _replay(notice_id=nid, inventory_changed=False, cash_changed=False)
    _add_document(db, nid, cid, kind, p, at=_pick(p, 'at'),
                  external_ref=_pick(p, 'reference', 'portal_event_id', 'tracking_ref'))
    return {'decision': 'recorded', 'notice_id': nid,
            'inventory_changed': False, 'cash_changed': False}


# ---------------------------------------------------------------------------
# Remedy election and logistics
# ---------------------------------------------------------------------------

def op_select_remedy(db, x):
    cid = _claim_id_of(x)
    claim = _claim(db, cid)
    if not claim:
        return _blocked('unknown_claim', claim_id=cid)
    remedy = _normalize_remedy(_pick(x, 'remedy', 'choice', 'election', 'selected_remedy'))
    if remedy not in ('replacement', 'cash'):
        return _blocked('invalid_remedy')

    covered = db.execute(
        'SELECT 1 FROM warranty_quotes WHERE claim_id=? AND covered=1 LIMIT 1', (cid,)
    ).fetchone()
    if not covered and claim['state'] not in ('acknowledged', 'remedy_selected', 'partially_fulfilled', 'fulfilled', 'cash_settled', 'restored'):
        return _blocked('vendor_warranty_not_acknowledged')

    if claim['completion_boundary']:
        if claim['selected_remedy'] == remedy:
            return _replay(claim_id=cid, remedy=remedy, state=claim['state'])
        return _blocked('remedy_already_completed',
                        selected=claim['selected_remedy'],
                        completion_boundary=claim['completion_boundary'])

    if claim['selected_remedy'] == remedy:
        return _replay(claim_id=cid, remedy=remedy, state=claim['state'])

    previous = claim['selected_remedy']
    quantity = _pick(x, 'required_quantity', 'quantity')
    if quantity is not None and not _money(claim['accepted_quantity'] or 0):
        db.execute(
            "UPDATE warranty_claims SET selected_remedy=?, state='remedy_selected', required_quantity=? WHERE id=?",
            (remedy, _money(quantity), cid),
        )
    else:
        db.execute("UPDATE warranty_claims SET selected_remedy=?, state='remedy_selected' WHERE id=?",
                   (remedy, cid))
    _add_document(db, _pick(x, 'id', 'election_id') or f'election:{cid}:{remedy}:{_pick(x, "at")}',
                  cid, 'remedy_election',
                  {'remedy': remedy, 'previous_remedy': previous, 'input': x},
                  at=_pick(x, 'at'))
    return status(db, cid)


def op_shipment(db, x):
    p = x
    cid = _claim_id_of(p)
    claim = _claim(db, cid)
    if not claim:
        return _blocked('unknown_claim', claim_id=cid)
    sid = _pick(p, 'shipment_id', 'id', 'tracking_ref')
    if not sid:
        return _blocked('shipment_id_required')
    old = _row(db, 'SELECT * FROM warranty_shipments WHERE id=?', (sid,))
    if old:
        return _replay(shipment_id=sid, status=old['status'], inventory_changed=False)

    direction = _pick(p, 'direction') or ('return_to_vendor' if _normalize_op(_pick(p, 'kind', '')) in ('return', 'core_return', 'wrong_item_return') else 'vendor_to_warehouse')
    kind = _pick(p, 'kind') or ('return' if direction == 'return_to_vendor' else 'replacement')
    status = _pick(p, 'status', 'state') or 'shipped'
    quantity = _pick(p, 'quantity', 'item_count') or 1
    db.execute(
        """INSERT INTO warranty_shipments
           (id,claim_id,kind,direction,carrier,tracking_ref,status,model,capacity,
            warranty_days,quantity,link_id,occurred_at,payload_json)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (sid, cid, kind, direction, _pick(p, 'carrier'),
         _pick(p, 'tracking_ref', 'tracking_number'), status,
         _pick(p, 'model', 'replacement_model'),
         str(_pick(p, 'capacity', 'replacement_capacity')) if _pick(p, 'capacity', 'replacement_capacity') is not None else None,
         _pick(p, 'warranty_days', 'warranty_term_days'), _money(quantity),
         _pick(p, 'receipt_id', 'link_id', 'core_id'), _pick(p, 'at'), _json(p)),
    )
    _add_document(db, f'doc-shipment:{sid}', cid, 'logistics', p, at=_pick(p, 'at'),
                  external_ref=_pick(p, 'tracking_ref', 'tracking_number'))

    if kind in ('core', 'core_return') or _normalize_op(_pick(p, 'subject', '')) == 'core':
        db.execute("UPDATE warranty_claims SET core_state='return_shipped' WHERE id=?", (cid,))
    return {'decision': 'shipment_recorded', 'shipment_id': sid,
            'status': status, 'inventory_changed': False}


# ---------------------------------------------------------------------------
# Warehouse receiving and inspection
# ---------------------------------------------------------------------------

def _receipt_decision(receipt):
    return {
        'signed': 'signed',
        'accepted': 'accepted',
        'rejected': 'rejected',
        'partially_accepted': 'partially_accepted',
    }.get(receipt['status'], receipt['status'])


def _create_stock_for_receipt(db, receipt_id, at=None):
    receipt = _row(db, 'SELECT * FROM warehouse_receipts WHERE id=?', (receipt_id,))
    if not receipt or _money(receipt['accepted_quantity']) <= 0:
        return None
    stock_id = f'stock:{receipt_id}'
    old = _row(db, 'SELECT * FROM warehouse_stock WHERE id=?', (stock_id,))
    if old:
        return stock_id
    db.execute(
        """INSERT INTO warehouse_stock
           (id,receipt_id,claim_id,source_type,source_id,supplier,payer,model,capacity,
            warranty_days,quantity,available_quantity,state,received_at,payload_json)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?, 'available', ?,?)""",
        (stock_id, receipt_id, receipt['claim_id'], receipt['source_type'],
         receipt['source_id'], receipt['supplier'], receipt['payer'], receipt['model'],
         receipt['capacity'], receipt['warranty_days'], receipt['accepted_quantity'],
         receipt['accepted_quantity'], at or receipt['inspected_at'] or receipt['signed_at'],
         _json({'receipt_id': receipt_id})),
    )
    movement_id = f'movement:{receipt_id}:inbound'
    db.execute(
        """INSERT OR IGNORE INTO warehouse_movements
           (id,stock_id,claim_id,kind,quantity,at,source_type,source_id,payload_json)
           VALUES(?,?,?, 'inbound', ?,?,?,?,?)""",
        (movement_id, stock_id, receipt['claim_id'], receipt['accepted_quantity'],
         at or receipt['inspected_at'], receipt['source_type'], receipt['source_id'],
         _json({'receipt_id': receipt_id})),
    )
    return stock_id


def _apply_claim_acceptance(db, claim_id):
    claim = _claim(db, claim_id)
    accepted = db.execute(
        "SELECT COALESCE(SUM(accepted_quantity),0) AS q FROM warehouse_receipts WHERE claim_id=? AND status IN ('accepted','partially_accepted')",
        (claim_id,),
    ).fetchone()['q']
    accepted = _money(accepted)
    required = _money(claim['required_quantity'] or 1)
    complete = _money_at_least(accepted, required)

    if complete and claim['completion_boundary'] != 'bank_settlement':
        db.execute(
            """UPDATE warranty_claims
               SET accepted_quantity=?, restored_quantity=?, selected_remedy='replacement',
                   completion_boundary='warehouse_acceptance', state='fulfilled'
               WHERE id=?""",
            (accepted, accepted, claim_id),
        )
    else:
        db.execute(
            "UPDATE warranty_claims SET accepted_quantity=?, restored_quantity=? WHERE id=?",
            (accepted, accepted, claim_id),
        )
    return complete


def _inspection_result(db, claim, p, source_type, source_row=None):
    inspection = {**_nested(p, 'inspection'), **_nested(p, 'item'),
                  **_nested(p, 'replacement'), **_nested(p, 'part'), **p}
    for alias, canonical in (
        ('part_model', 'model'), ('equipment_model', 'model'), ('sku', 'model'),
        ('capacity_gb', 'capacity'), ('storage_capacity', 'capacity'),
        ('memory_capacity', 'capacity'),
        ('warranty_period_days', 'warranty_days'),
        ('warranty_term_days', 'warranty_days'),
        ('term_days', 'warranty_days'), ('warranty_term', 'warranty_days'),
    ):
        if inspection.get(canonical) is None and inspection.get(alias) is not None:
            inspection[canonical] = inspection[alias]
    expected = _loads(claim['spec_json'], {}) if claim else {}
    if source_row:
        for key in ('model', 'capacity', 'warranty_days'):
            if source_row[key] is not None:
                expected.setdefault(key, source_row[key])
    mismatches = _spec_mismatches(expected, inspection)

    explicit_reject = _pick(p, 'reject', 'rejected') is True or _pick(inspection, 'accepted', 'passed', 'inspection_passed') is False
    accept_ops = {'accept_replacement', 'accept_delivery', 'accept_goods',
                  'warehouse_acceptance', 'accept_purchase', 'receive_purchase',
                  'inspect_replacement', 'inspect', 'confirm_receipt'}
    explicit_accept = (_pick(inspection, 'accepted', 'passed', 'inspection_passed') is True
                       or _normalize_op(p.get('op')) in accept_ops)
    if explicit_reject:
        return 0, 'rejected', _pick(p, 'reason', 'rejection_reason') or 'warehouse_rejected', mismatches
    if mismatches:
        return 0, 'rejected', 'spec_mismatch', mismatches
    if not explicit_accept and not any(k in inspection for k in ('model', 'capacity', 'warranty_days', 'replacement_model')):
        return 0, 'signed', None, []

    delivered = _money(_pick(p, 'quantity', 'delivered_quantity') or 1)
    accepted_qty = _pick(p, 'accepted_quantity')
    accepted_qty = delivered if accepted_qty is None else _money(accepted_qty)
    accepted_qty = min(delivered, max(0, accepted_qty))
    if accepted_qty <= 0:
        return 0, 'rejected', _pick(p, 'reason') or 'warehouse_rejected', []
    status = 'accepted' if _money_at_least(accepted_qty, delivered) else 'partially_accepted'
    return accepted_qty, status, None, []


def op_sign_receipt(db, x):
    return _receive_or_inspect(db, x, inspect=False)


def op_receive(db, x, inspect=True):
    return _receive_or_inspect(db, x, inspect=inspect)


def op_inspect(db, x):
    rid = _pick(x, 'receipt_id', 'id')
    receipt = _row(db, 'SELECT * FROM warehouse_receipts WHERE id=?', (rid,))
    if not receipt:
        return _blocked('unknown_receipt', receipt_id=rid)
    if receipt['status'] in ('accepted', 'rejected', 'partially_accepted'):
        return _replay(receipt_id=rid, status=receipt['status'])
    return _receive_or_inspect(db, x, inspect=True, existing_receipt=receipt)


def _receive_or_inspect(db, x, inspect=True, existing_receipt=None):
    p = {**_nested(x, 'receipt'), **_nested(x, 'inspection'), **x}
    cid = _resolved_claim_id(db, p, existing_receipt)
    claim = _claim(db, cid)
    if not claim:
        return _blocked('unknown_claim', claim_id=cid)

    rid = _pick(p, 'receipt_id', 'id') or (existing_receipt['id'] if existing_receipt else None)
    if not rid:
        rid = f"receipt:{_pick(p, 'shipment_id', 'tracking_ref', 'po', 'purchase_order_id')}:{_pick(p, 'at')}"

    old = existing_receipt
    if old is None:
        old = _row(db, 'SELECT * FROM warehouse_receipts WHERE id=?', (rid,))
    if old:
        terminal = old['status'] in ('accepted', 'rejected', 'partially_accepted')
        inspection_call = inspect and _normalize_op(x.get('op', '')) != 'sign_receipt'
        has_facts = any(_pick(p, key) is not None for key in (
            'model', 'replacement_model', 'capacity', 'replacement_capacity',
            'warranty_days', 'warranty_term_days', 'accepted', 'passed',
            'inspection_passed', 'accepted_quantity', 'reject', 'rejected', 'reason',
        )) or _normalize_op(x.get('op', '')) in {
            'accept_replacement', 'accept_delivery', 'accept_goods',
            'warehouse_acceptance', 'accept_purchase', 'inspect', 'inspect_replacement',
        }
        if terminal or not inspection_call or not has_facts:
            return _replay(receipt_id=rid, status=old['status'],
                           original_decision=_receipt_decision(old))

    po_id = _pick(p, 'purchase_order_id', 'po_id', 'po')
    requested_source = _normalize_op(_pick(p, 'source_type') or '')
    purchase_op = _normalize_op(x.get('op', '')) in {
        'receive_purchase', 'accept_purchase', 'receive_third_party', 'purchase_receipt',
    }
    if not po_id and (purchase_op or requested_source == 'third_party_purchase'):
        po_id = _pick(p, 'source_id')
    po = _row(db, 'SELECT * FROM purchase_orders WHERE id=?', (po_id,)) if po_id else None
    if purchase_op or requested_source == 'third_party_purchase' or po_id:
        if not po:
            return _blocked('unknown_purchase_order', purchase_order_id=po_id)
        if po['claim_id'] != cid:
            return _blocked('purchase_order_claim_conflict')
        source_type = 'third_party_purchase'
        source_id = po['id']
    else:
        # Origin cannot be supplied by the caller: ordinary receipt commands
        # against this warranty claim are the vendor's replacement shipment.
        source_type = 'vendor_replacement'
        source_id = _pick(p, 'source_id', 'shipment_id', 'tracking_ref')
    if po and po['claim_id'] != cid:
        return _blocked('purchase_order_claim_conflict')

    shipment_id = _pick(p, 'shipment_id')
    shipment = _row(db, 'SELECT * FROM warranty_shipments WHERE id=?', (shipment_id,)) if shipment_id else None

    delivered_qty = _money(_pick(p, 'quantity', 'delivered_quantity') or (old['delivered_quantity'] if old else 1))
    signed_at = _pick(p, 'signed_at', 'received_at', 'at') or (old['signed_at'] if old else None)

    if not inspect or _normalize_op(x.get('op', '')) == 'sign_receipt':
        accepted_qty, status, reason, mismatches = 0, 'signed', None, []
    else:
        inspection_p = dict(p)
        if old:
            for key in ('model', 'replacement_model', 'capacity',
                        'replacement_capacity', 'warranty_days', 'warranty_term_days'):
                if inspection_p.get(key) is None and old.get(key) is not None:
                    inspection_p[key] = old.get(key)
        accepted_qty, status, reason, mismatches = _inspection_result(
            db, claim, inspection_p, source_type, po or shipment or old,
        )

    # Mutual exclusion boundary: completed cash cannot be doubled by vendor goods.
    exclusive_block = None
    if inspect and accepted_qty > 0 and source_type == 'vendor_replacement':
        if claim['completion_boundary'] == 'bank_settlement' or _cash_complete(claim):
            exclusive_block = 'cash_remedy_completed'
        elif claim['completion_boundary'] == 'warehouse_acceptance' and not old:
            exclusive_block = 'replacement_remedy_completed'
    if exclusive_block:
        accepted_qty, status, reason = 0, 'rejected', exclusive_block
        mismatches = []

    model = _pick(p, 'model', 'replacement_model') or (po['model'] if po else None) or (shipment['model'] if shipment else None) or (old['model'] if old else None)
    capacity = _pick(p, 'capacity', 'replacement_capacity') or (po['capacity'] if po else None) or (shipment['capacity'] if shipment else None) or (old['capacity'] if old else None)
    warranty_days = _pick(p, 'warranty_days', 'warranty_term_days') or (po['warranty_days'] if po else None) or (shipment['warranty_days'] if shipment else None) or (old['warranty_days'] if old else None)
    supplier = _pick(p, 'supplier', 'vendor', 'seller') or (po['supplier'] if po else claim['vendor'])
    payer = _pick(p, 'payer') or (po['payer'] if po else claim['buyer'])

    if old:
        db.execute(
            """UPDATE warehouse_receipts SET
                 model=?,capacity=?,warranty_days=?,accepted_quantity=?,status=?,reason=?,
                 inspected_at=?, payload_json=?
               WHERE id=?""",
            (model, str(capacity) if capacity is not None else None, warranty_days,
             accepted_qty, status, reason, _pick(p, 'inspected_at', 'at'), _json(p), rid),
        )
    else:
        db.execute(
            """INSERT INTO warehouse_receipts
               (id,claim_id,shipment_id,source_type,source_id,supplier,payer,model,capacity,
                warranty_days,delivered_quantity,accepted_quantity,status,reason,signed_at,
                inspected_at,payload_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (rid, cid, shipment_id, source_type, source_id, supplier, payer, model,
             str(capacity) if capacity is not None else None, warranty_days, delivered_qty,
             accepted_qty, status, reason, signed_at,
             _pick(p, 'inspected_at', 'at') if inspect else None, _json(p)),
        )

    _add_document(db, f'doc-receipt:{rid}:{status}', cid,
                  'warehouse_receipt' if not inspect else 'warehouse_inspection',
                  {'receipt_id': rid, 'status': status, 'reason': reason,
                   'mismatches': mismatches, 'payload': p},
                  at=_pick(p, 'at'))

    stock_id = None
    claim_complete = False
    if accepted_qty > 0:
        stock_id = _create_stock_for_receipt(db, rid, at=_pick(p, 'at'))
        claim_complete = _apply_claim_acceptance(db, cid)
        if source_type == 'third_party_purchase' and po:
            received = db.execute(
                "SELECT COALESCE(SUM(accepted_quantity),0) q FROM warehouse_receipts WHERE source_type='third_party_purchase' AND source_id=?",
                (po_id,),
            ).fetchone()['q']
            po_state = 'received' if _money_at_least(received, po['quantity']) else 'partially_received'
            db.execute('UPDATE purchase_orders SET state=? WHERE id=?', (po_state, po_id))
        if claim_complete and claim['completion_boundary'] != 'bank_settlement':
            db.execute("UPDATE warranty_claims SET state='restored' WHERE id=?", (cid,))

    result = {
        'decision': _receipt_decision(_row(db, 'SELECT * FROM warehouse_receipts WHERE id=?', (rid,))),
        'receipt_id': rid,
        'claim_id': cid,
        'status': status,
        'accepted_quantity': accepted_qty,
        'stock_id': stock_id,
        'inventory_changed': bool(stock_id),
        'spec_mismatches': mismatches,
    }
    if reason:
        result['reason'] = reason
    if claim_complete:
        result['claim_complete'] = True
    result['stock_available'] = stock_available(db, cid)
    return result


def stock_available(db, claim_id=None):
    if claim_id:
        row = db.execute(
            "SELECT COALESCE(SUM(available_quantity),0) q FROM warehouse_stock WHERE claim_id=? AND state='available'",
            (claim_id,),
        ).fetchone()
    else:
        row = db.execute(
            "SELECT COALESCE(SUM(available_quantity),0) q FROM warehouse_stock WHERE state='available'"
        ).fetchone()
    return _money(row['q'])


def op_stock(db, x):
    claim_id = _claim_id_of(x) or _pick(x, 'claim')
    model = _pick(x, 'model')
    sql = "SELECT * FROM warehouse_stock WHERE state='available' AND available_quantity>0"
    args = []
    if claim_id:
        sql += ' AND claim_id=?'
        args.append(claim_id)
    if model:
        sql += ' AND model=?'
        args.append(model)
    items = _rows(db, sql + ' ORDER BY id', tuple(args))
    available = _money(sum((_money(i['available_quantity']) for i in items), 0))
    return {'decision': 'stock', 'claim_id': claim_id,
            'available': available, 'stock_available': available,
            'quantity': available, 'items': items}


class StockReport(int):
    """Integer-like available quantity that also carries item-level detail."""

    def __new__(cls, available, items, claim_id=None):
        obj = int.__new__(cls, available)
        obj.items = items
        obj.claim_id = claim_id
        obj.available = available
        obj.stock_available = available
        obj.quantity = available
        return obj

    def __len__(self):
        return len(self.items)

    def __iter__(self):
        return iter(self.items)

    def __getitem__(self, key):
        if isinstance(key, int):
            return self.items[key]
        mapping = {
            'available': self.available,
            'stock_available': self.stock_available,
            'quantity': self.quantity,
            'claim_id': self.claim_id,
            'items': self.items,
        }
        if key in mapping:
            return mapping[key]
        raise KeyError(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default


def warehouse_stock(db, claim_id=None):
    items = _rows(
        db,
        """SELECT * FROM warehouse_stock
           WHERE state='available' AND available_quantity>0
           ORDER BY id""",
        (),
    ) if claim_id is None else _rows(
        db,
        """SELECT * FROM warehouse_stock
           WHERE state='available' AND available_quantity>0 AND claim_id=?
           ORDER BY id""",
        (claim_id,),
    )
    available = _money(sum((_money(i['available_quantity']) for i in items), 0))
    return StockReport(available, items, claim_id)


def available_stock(db, claim_id=None):
    return stock_available(db, claim_id)


available_inventory = stock_available
spare_stock = stock_available
stock_count = stock_available


def op_allocate(db, x):
    stock_id = _pick(x, 'stock_id')
    quantity = _money(_pick(x, 'quantity') or 1)
    stock = _row(db, 'SELECT * FROM warehouse_stock WHERE id=?', (stock_id,))
    if not stock:
        return _blocked('unknown_stock', stock_id=stock_id)
    if not _money_at_least(stock['available_quantity'], quantity):
        return _blocked('insufficient_available_stock',
                        available=stock['available_quantity'], requested=quantity)
    allocation_id = _pick(x, 'id', 'allocation_id') or f'allocation:{stock_id}:{_pick(x, "destination")}:{quantity}'
    if _row(db, 'SELECT 1 FROM warehouse_movements WHERE id=?', (allocation_id,)):
        return _replay(allocation_id=allocation_id)
    db.execute('UPDATE warehouse_stock SET available_quantity=available_quantity-? WHERE id=?',
               (quantity, stock_id))
    db.execute(
        """INSERT INTO warehouse_movements
           (id,stock_id,claim_id,kind,quantity,at,source_type,source_id,payload_json)
           VALUES(?,?,?, 'allocate', ?,?,?,?,?)""",
        (allocation_id, stock_id, stock['claim_id'], quantity, _pick(x, 'at'),
         stock['source_type'], stock['source_id'], _json(x)),
    )
    return {'decision': 'allocated', 'allocation_id': allocation_id,
            'stock_id': stock_id, 'source_type': stock['source_type'],
            'source_id': stock['source_id'], 'available_quantity': stock_available(db)}


# ---------------------------------------------------------------------------
# Returns and old-unit ownership
# ---------------------------------------------------------------------------

def op_core_disposition(db, x):
    cid = _claim_id_of(x)
    claim = _claim(db, cid)
    if not claim:
        return _blocked('unknown_claim', claim_id=cid)
    disposition = _pick(x, 'disposition', 'core_disposition', 'action', 'state', 'result')
    aliases = {'return': 'return_pending', 'ship_return': 'return_shipped',
               'return_core': 'return_pending', 'core_return': 'return_pending',
               'return_shipped': 'return_shipped',
               'receive_return': 'vendor_owned', 'confirm_return': 'vendor_owned',
               'confirm_core_return': 'vendor_owned', 'vendor_received': 'vendor_owned',
               'vendor_owned': 'vendor_owned', 'retain': 'buyer_owned',
               'retain_core': 'buyer_owned', 'buyer_retains': 'buyer_owned',
               'buyer_owned': 'buyer_owned', 'scrap': 'scrapped', 'scrapped': 'scrapped'}
    state = aliases.get(_normalize_op(disposition)) if disposition is not None else None
    valid_states = {'return_pending', 'return_shipped', 'vendor_owned', 'buyer_owned', 'scrapped', 'pending_return', 'pending'}
    if state not in valid_states:
        return _blocked('invalid_core_disposition', disposition=disposition)
    document_id = _pick(x, 'document_id', 'event_id', 'id') or f'core:{cid}:{state}:{_pick(x, "at")}'
    if _document(db, document_id):
        return _replay(core_state=claim['core_state'])
    db.execute('UPDATE warranty_claims SET core_state=? WHERE id=?', (state, cid))
    _add_document(db, document_id, cid, 'core_disposition', x, at=_pick(x, 'at'))
    return {'decision': 'core_disposition_recorded', 'core_state': state,
            'owner': 'vendor' if state == 'vendor_owned' else 'buyer' if state in ('buyer_owned', 'scrapped') else 'pending'}


# ---------------------------------------------------------------------------
# Bank settlement
# ---------------------------------------------------------------------------

def op_bank_receipt(db, x):
    p = x
    cid = _claim_id_of(p)
    claim = _claim(db, cid)
    if not claim:
        return _blocked('unknown_claim', claim_id=cid)
    rid = _pick(p, 'receipt_id', 'bank_receipt_id', 'id', 'reference')
    if not rid:
        return _blocked('bank_receipt_id_required')
    old = _row(db, 'SELECT * FROM bank_receipts WHERE id=?', (rid,))
    if old:
        return _replay(receipt_id=rid, status=old['status'], amount=old['amount'])

    instrument = _normalize_op(_pick(p, 'instrument', 'source_type', 'channel', 'kind') or 'bank_transfer')
    bank_like = any(token in instrument for token in ('bank', 'wire', 'ach', 'transfer', 'deposit', 'settlement'))
    non_bank = (
        instrument in NON_BANK_INSTRUMENTS
        or any(token in instrument for token in ('credit_memo', 'credit_note', 'promise', 'portal', 'commitment'))
        or (not bank_like and any(token in instrument for token in ('credit', 'memo', 'note', 'voucher')))
    )
    if non_bank:
        _add_document(db, f'nonbank:{rid}', cid, instrument, p, at=_pick(p, 'at'))
        return _blocked('not_bank_settlement', instrument=instrument,
                        cash_changed=False, inventory_changed=False)

    amount = _pick(p, 'amount', 'credited_amount', 'settled_amount', 'cash_amount')
    if amount is None or _money(amount) <= 0:
        return _blocked('invalid_bank_amount')
    amount = _money(amount)

    raw_status = _normalize_op(_pick(p, 'status', 'state') or 'settled')
    explicitly_unsettled = _pick(p, 'settled', 'verified', 'posted') is False
    if explicitly_unsettled or raw_status in BANK_PENDING_STATUSES:
        status = 'pending'
    elif raw_status in BANK_SETTLED_STATUSES or raw_status in ('bank_receipt', 'bank_transfer', 'wire', 'ach'):
        status = 'settled'
    else:
        status = raw_status

    account_id = _pick(p, 'account_id', 'bank_account_id', 'account')
    owner = _pick(p, 'account_owner', 'owner', 'beneficiary', 'beneficiary_name')
    expected_owner = _pick(p, 'expected_owner', 'expected_account_owner')
    expected_account_id = _pick(p, 'expected_account_id')
    contract_account = _row(
        db, 'SELECT bank_account_id,account_owner FROM warranty_contracts WHERE id=?',
        (claim['contract_id'],),
    )
    if contract_account:
        expected_account_id = expected_account_id or contract_account['bank_account_id']
        expected_owner = expected_owner or contract_account['account_owner']
    # Do not infer the legal bank beneficiary from an internal buyer id.
    # If no expected owner is on file, an explicit owner/account attribution is
    # recorded; if an expected owner exists it must match.

    attribution = 'matched'
    explicit_attribution = _pick(p, 'attributed', 'attribution_matched', 'verified')
    if explicit_attribution is False:
        attribution = 'unattributed'
    elif expected_owner and (not owner or str(owner).strip().casefold() != str(expected_owner).strip().casefold()):
        attribution = 'wrong_owner' if owner else 'unattributed'
    elif expected_account_id and account_id and str(account_id) != str(expected_account_id):
        attribution = 'wrong_account'
    elif not owner and not account_id and explicit_attribution is not True:
        attribution = 'unattributed'
    elif not expected_owner and not expected_account_id:
        attribution = 'recorded' if (owner or account_id) else 'matched'
    else:
        attribution = 'matched'

    if status != 'settled':
        if attribution == 'matched':
            attribution = 'pending'
    elif attribution in ('unattributed', 'wrong_owner', 'wrong_account'):
        status = 'unattributed'

    db.execute(
        """INSERT INTO bank_receipts
           (id,claim_id,amount,currency,account_id,account_owner,reference,received_at,
            status,attribution,payload_json)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (rid, cid, amount, _pick(p, 'currency') or claim and 'CNY', account_id, owner,
         _pick(p, 'reference', 'bank_reference'), _pick(p, 'at', 'received_at'),
         status, attribution, _json(p)),
    )
    _add_document(db, f'doc-bank:{rid}', cid, 'bank_receipt', p,
                  at=_pick(p, 'at', 'received_at'), external_ref=rid)

    if status != 'settled':
        return _blocked('bank_receipt_not_available_as_cash',
                        receipt_id=rid, status=status, attribution=attribution,
                        cash_net=_cash_net(_claim(db, cid)))

    db.execute('UPDATE warranty_claims SET cash_gross=cash_gross+? WHERE id=?', (amount, cid))
    claim = _claim(db, cid)
    complete = _cash_complete(claim)
    exclusive_conflict = bool(claim['completion_boundary'] == 'warehouse_acceptance')
    if complete and not claim['completion_boundary']:
        db.execute(
            """UPDATE warranty_claims
               SET selected_remedy='cash', completion_boundary='bank_settlement',
                   state='cash_settled'
               WHERE id=?""",
            (cid,),
        )
    elif complete and claim['selected_remedy'] != 'replacement':
        db.execute("UPDATE warranty_claims SET selected_remedy='cash' WHERE id=?", (cid,))

    result = {
        'decision': 'settled',
        'receipt_id': rid,
        'claim_id': cid,
        'amount': amount,
        'cash_gross': claim['cash_gross'] + amount if False else _claim(db, cid)['cash_gross'],
        'cash_net': _cash_net(_claim(db, cid)),
        'cash_complete': complete,
        'exclusive_remedy_conflict': exclusive_conflict,
    }
    if exclusive_conflict:
        result['reason'] = 'replacement_already_accepted_return_or_reverse_cash'
    return result


def op_attribute_bank_receipt(db, x):
    rid = _pick(x, 'receipt_id', 'id')
    row = _row(db, 'SELECT * FROM bank_receipts WHERE id=?', (rid,))
    if not row:
        return _blocked('unknown_bank_receipt', receipt_id=rid)
    if row['status'] == 'settled':
        return _replay(receipt_id=rid, status='settled')
    owner = _pick(x, 'account_owner', 'owner', 'beneficiary') or row['account_owner']
    account_id = _pick(x, 'account_id') or row['account_id']
    claim = _claim(db, row['claim_id'])
    contract = _row(db, 'SELECT account_owner FROM warranty_contracts WHERE id=?',
                    (claim['contract_id'],)) if claim else None
    expected_owner = (_pick(x, 'expected_owner')
                      or (contract['account_owner'] if contract else None))
    if expected_owner and owner and str(owner).casefold() != str(expected_owner).casefold():
        return _blocked('bank_attribution_conflict')
    db.execute("UPDATE bank_receipts SET status='settled', attribution='matched', account_owner=?, account_id=? WHERE id=?",
               (owner, account_id, rid))
    db.execute('UPDATE warranty_claims SET cash_gross=cash_gross+? WHERE id=?',
               (row['amount'], row['claim_id']))
    claim = _claim(db, row['claim_id'])
    if _cash_complete(claim) and not claim['completion_boundary']:
        db.execute("UPDATE warranty_claims SET selected_remedy='cash', completion_boundary='bank_settlement', state='cash_settled' WHERE id=?",
                   (row['claim_id'],))
    _add_document(db, f'bank-attribution:{rid}:{_pick(x, "at")}', row['claim_id'],
                  'bank_attribution', x, at=_pick(x, 'at'))
    return {'decision': 'settled', 'receipt_id': rid, 'cash_net': _cash_net(_claim(db, row['claim_id']))}


def op_reverse_bank_receipt(db, x):
    cid = _pick(x, 'claim_id', 'claim')
    rid = _pick(x, 'receipt_id', 'bank_receipt_id')
    reversal_id = _pick(x, 'reversal_id', 'id', 'reversal_ref')
    receipt = _row(db, 'SELECT * FROM bank_receipts WHERE id=?', (rid,)) if rid else None
    if not receipt and not rid:
        # Allow the bank receipt id itself in id only when a separate reversal
        # event id was supplied under reversal_id.
        candidate = _pick(x, 'id')
        candidate_row = _row(db, 'SELECT * FROM bank_receipts WHERE id=?', (candidate,))
        if candidate_row and reversal_id and reversal_id != candidate:
            receipt, rid = candidate_row, candidate
    if not receipt:
        return _blocked('unknown_bank_receipt', receipt_id=rid)
    if cid and receipt['claim_id'] != cid:
        return _blocked('bank_receipt_claim_conflict')
    cid = receipt['claim_id']
    if receipt['status'] != 'settled':
        return _blocked('only_settled_bank_receipt_can_be_reversed', status=receipt['status'])
    if not reversal_id:
        return _blocked('reversal_id_required')
    old = _row(db, 'SELECT * FROM bank_reversals WHERE id=?', (reversal_id,))
    if old:
        return _replay(reversal_id=reversal_id)

    already = db.execute('SELECT COALESCE(SUM(amount),0) a FROM bank_reversals WHERE receipt_id=?',
                        (rid,)).fetchone()['a']
    raw_amount = _pick(x, 'amount')
    remaining = _sub_money(receipt['amount'], already)
    amount = remaining if raw_amount is None else _money(raw_amount)
    if amount <= 0:
        return _blocked('invalid_reversal_amount')
    total_reversed = _add_money(already, amount)
    if not _money_at_least(receipt['amount'], total_reversed):
        # _money_at_least(receipt_amount, total) is false when reversal is too large.
        return _blocked('reversal_exceeds_receipt',
                        receipt_amount=receipt['amount'], already_reversed=already)

    db.execute(
        """INSERT INTO bank_reversals (id,receipt_id,claim_id,amount,at,reason,payload_json)
           VALUES(?,?,?,?,?,?,?)""",
        (reversal_id, rid, cid, amount, _pick(x, 'at'),
         _pick(x, 'reason') or 'reversal', _json(x)),
    )
    db.execute('UPDATE warranty_claims SET cash_reversed=cash_reversed+? WHERE id=?', (amount, cid))
    claim = _claim(db, cid)
    if claim['completion_boundary'] == 'bank_settlement' and not _cash_complete(claim):
        db.execute("UPDATE warranty_claims SET completion_boundary=NULL, state='cash_reversed' WHERE id=?",
                   (cid,))
    _add_document(db, f'doc-reversal:{reversal_id}', cid, 'bank_reversal', x, at=_pick(x, 'at'))
    return {'decision': 'reversed', 'reversal_id': reversal_id,
            'cash_net': _cash_net(_claim(db, cid)), 'cash_complete': _cash_complete(_claim(db, cid))}


# ---------------------------------------------------------------------------
# Third-party procurement
# ---------------------------------------------------------------------------

def op_purchase_order(db, x):
    cid = _claim_id_of(x)
    claim = _claim(db, cid)
    if not claim:
        return _blocked('unknown_claim', claim_id=cid)
    poid = _pick(x, 'purchase_order_id', 'po_id', 'id')
    if not poid:
        return _blocked('purchase_order_id_required')
    old = _row(db, 'SELECT * FROM purchase_orders WHERE id=?', (poid,))
    if old:
        return _replay(purchase_order_id=poid, state=old['state'])

    if claim['selected_remedy'] != 'cash' or not _cash_complete(claim):
        return _blocked('cash_not_settled_before_procurement',
                        selected_remedy=claim['selected_remedy'],
                        cash_net=_cash_net(claim), required_cash=claim['required_cash'])
    supplier = _pick(x, 'supplier', 'seller', 'third_party_vendor', 'another_vendor')
    if not supplier:
        return _blocked('supplier_required')
    if _normalize_op(_pick(x, 'allow_warranty_vendor')) not in ('true', '1') and supplier == claim['vendor']:
        return _blocked('procurement_supplier_must_be_independent')

    spec = _loads(claim['spec_json'], {})
    model = _pick(x, 'model') or spec.get('model')
    capacity = _pick(x, 'capacity') or spec.get('capacity')
    warranty_days = _pick(x, 'warranty_days', 'warranty_term_days') or spec.get('warranty_days')
    quantity = _pick(x, 'quantity') or claim['required_quantity'] or 1
    payer = _pick(x, 'payer', 'purchaser', 'buyer') or claim['buyer']
    amount = _pick(x, 'amount', 'price', 'total_amount')
    db.execute(
        """INSERT INTO purchase_orders
           (id,claim_id,supplier,payer,model,capacity,warranty_days,quantity,amount,currency,
            state,paid_amount,created_at,payload_json)
           VALUES(?,?,?,?,?,?,?,?,?,?, 'ordered',0,?,?)""",
        (poid, cid, supplier, payer, model, str(capacity) if capacity is not None else None,
         warranty_days, _money(quantity), _money(amount) if amount is not None else None,
         _pick(x, 'currency') or 'CNY', _pick(x, 'at', 'created_at'), _json(x)),
    )
    _add_document(db, f'doc-po:{poid}', cid, 'third_party_purchase_order', x, at=_pick(x, 'at'))
    return {'decision': 'purchase_order_created', 'purchase_order_id': poid,
            'payer': payer, 'supplier': supplier}


def op_purchase_payment(db, x):
    poid = _pick(x, 'purchase_order_id', 'po_id')
    payment_id = _pick(x, 'payment_id', 'id')
    po = _row(db, 'SELECT * FROM purchase_orders WHERE id=?', (poid,))
    if not po:
        return _blocked('unknown_purchase_order', purchase_order_id=poid)
    if not payment_id:
        return _blocked('payment_id_required')
    if _row(db, 'SELECT 1 FROM purchase_payments WHERE id=?', (payment_id,)):
        return _replay(payment_id=payment_id)
    amount = _money(_pick(x, 'amount') or po['amount'] or 0)
    if amount <= 0:
        return _blocked('invalid_purchase_payment')
    payer = _pick(x, 'payer') or po['payer']
    db.execute(
        'INSERT INTO purchase_payments VALUES(?,?,?,?,?,?,?)',
        (payment_id, poid, amount, _pick(x, 'at'), payer,
         _pick(x, 'reference'), _json(x)),
    )
    db.execute('UPDATE purchase_orders SET paid_amount=paid_amount+? WHERE id=?', (amount, poid))
    return {'decision': 'purchase_payment_recorded', 'payment_id': payment_id, 'payer': payer}


def op_receive_purchase(db, x):
    payload = dict(x)
    payload.setdefault('source_type', 'third_party_purchase')
    if not payload.get('purchase_order_id'):
        payload['purchase_order_id'] = _pick(x, 'po', 'po_id')
    return _receive_or_inspect(db, payload, inspect=True)


# ---------------------------------------------------------------------------
# Status and obligations
# ---------------------------------------------------------------------------

def status(db, claim_id):
    claim = _claim(db, claim_id)
    if not claim:
        return None
    claim = dict(claim)
    claim['spec'] = _loads(claim.pop('spec_json', '{}'), {})
    claim['obligations_stored'] = _loads(claim.pop('obligations_json', '[]'), [])
    cash_net = _sub_money(claim['cash_gross'] or 0, claim['cash_reversed'] or 0)
    required_cash = _money(claim['required_cash'] or 0)
    cash_remaining = max(0, _sub_money(required_cash, cash_net)) if required_cash else 0
    cash_excess = max(0, _sub_money(cash_net, required_cash)) if required_cash else 0

    receipts = _rows(db, 'SELECT * FROM warehouse_receipts WHERE claim_id=? ORDER BY signed_at,id', (claim_id,))
    stock = _rows(db, 'SELECT * FROM warehouse_stock WHERE claim_id=? ORDER BY id', (claim_id,))
    bank = _rows(db, 'SELECT * FROM bank_receipts WHERE claim_id=? ORDER BY received_at,id', (claim_id,))
    reversals = _rows(db, 'SELECT * FROM bank_reversals WHERE claim_id=? ORDER BY at,id', (claim_id,))
    purchases = _rows(db, 'SELECT * FROM purchase_orders WHERE claim_id=? ORDER BY created_at,id', (claim_id,))
    shipments = _rows(db, 'SELECT * FROM warranty_shipments WHERE claim_id=? ORDER BY occurred_at,id', (claim_id,))

    obligations = []
    remedy = claim['selected_remedy']
    required_qty = _money(claim['required_quantity'] or 1)
    accepted_qty = _money(claim['accepted_quantity'] or 0)

    if remedy == 'replacement' and not claim['completion_boundary'] == 'warehouse_acceptance':
        if accepted_qty < required_qty:
            obligations.append({'party': claim['vendor'], 'type': 'conforming_replacement',
                                'remaining_quantity': _sub_money(required_qty, accepted_qty)})
    if remedy == 'cash' or (cash_net > 0 and claim['completion_boundary'] != 'warehouse_acceptance'):
        if cash_remaining > 0 and claim['completion_boundary'] != 'warehouse_acceptance':
            obligations.append({'party': claim['vendor'], 'type': 'cash_payment',
                                'remaining_amount': cash_remaining})
    if claim['completion_boundary'] == 'warehouse_acceptance' and cash_net > 0:
        obligations.append({'party': claim['buyer'] or 'procurement',
                           'type': 'return_duplicate_cash', 'amount': cash_net})
    if claim['completion_boundary'] == 'bank_settlement':
        vendor_goods = [s for s in stock if s['source_type'] == 'vendor_replacement']
        vendor_quantity = _money(sum((_money(s['quantity']) for s in vendor_goods), 0))
        if vendor_quantity > 0:
            obligations.append({'party': claim['buyer'] or 'warehouse',
                                'type': 'return_duplicate_goods',
                                'quantity': vendor_quantity})
    if cash_excess > 0 and claim['completion_boundary'] != 'warehouse_acceptance':
        obligations.append({'party': claim['buyer'] or 'procurement',
                           'type': 'return_overpayment', 'amount': cash_excess})

    for receipt in receipts:
        rejected_qty = _sub_money(receipt['delivered_quantity'] or 0, receipt['accepted_quantity'] or 0)
        if receipt['status'] in ('rejected', 'partially_accepted') and rejected_qty > 0:
            returned = db.execute(
                "SELECT COALESCE(SUM(quantity),0) q FROM warranty_shipments WHERE claim_id=? AND direction='return_to_vendor' AND link_id=?",
                (claim_id, receipt['id']),
            ).fetchone()['q']
            pending_return = _sub_money(rejected_qty, returned or 0)
            if pending_return > 0:
                obligations.append({'party': claim['buyer'] or 'warehouse',
                                    'type': 'return_rejected_item',
                                    'receipt_id': receipt['id'],
                                    'remaining_quantity': pending_return})

    if claim['core_state'] in ('pending_return', 'pending') and (remedy == 'replacement' or not remedy):
        contract = _row(db, 'SELECT core_disposition FROM warranty_contracts WHERE id=?', (claim['contract_id'],))
        if not contract or contract['core_disposition'] == 'return_vendor':
            obligations.append({'party': claim['buyer'] or 'procurement', 'type': 'return_faulty_core'})
    elif claim['core_state'] == 'return_shipped':
        obligations.append({'party': 'carrier/vendor', 'type': 'complete_core_return'})

    for po in purchases:
        received = db.execute(
            "SELECT COALESCE(SUM(accepted_quantity),0) q FROM warehouse_receipts WHERE source_type='third_party_purchase' AND source_id=?",
            (po['id'],),
        ).fetchone()['q']
        if not _money_at_least(received, po['quantity']):
            obligations.append({'party': po['supplier'], 'type': 'third_party_replacement_delivery',
                                'purchase_order_id': po['id'],
                                'remaining_quantity': _sub_money(po['quantity'], received)})

    available = stock_available(db, claim_id)
    result = {
        'claim_id': claim_id,
        'state': claim['state'],
        'vendor': claim['vendor'],
        'buyer': claim['buyer'],
        'transition_id': claim['transition_id'],
        'contract_id': claim['contract_id'],
        'entitlement_id': claim['entitlement_id'],
        'device_id': claim['device_id'],
        'fault_category': claim['fault_category'],
        'fault_at': claim['fault_at'],
        'selected_remedy': remedy,
        'completion_boundary': claim['completion_boundary'],
        'cash': {
            'required': required_cash,
            'gross': _money(claim['cash_gross']),
            'reversed': _money(claim['cash_reversed']),
            'net': cash_net,
            'remaining_from_vendor': cash_remaining,
            'complete': _cash_complete(claim),
        },
        'quantities': {
            'required': required_qty,
            'accepted': accepted_qty,
        },
        'stock_available': available,
        'stock': stock,
        'bank_receipts': bank,
        'bank_reversals': reversals,
        'warehouse_receipts': receipts,
        'purchase_orders': purchases,
        'shipments': shipments,
        'obligations': obligations,
        'core_owner': 'vendor' if claim['core_state'] == 'vendor_owned' else 'buyer' if claim['core_state'] in ('buyer_owned', 'scrapped') else 'pending',
        'exclusive_relief_intact': not (
            claim['completion_boundary'] == 'warehouse_acceptance'
            and _money_at_least(cash_net, required_cash)
        ) and not (
            claim['completion_boundary'] == 'bank_settlement'
            and db.execute(
                "SELECT COUNT(*) c FROM warehouse_stock WHERE claim_id=? AND source_type='vendor_replacement'",
                (claim_id,),
            ).fetchone()['c'] > 0
        ),
    }
    return result


OPS = {
    'open_claim': op_open_claim,
    'create_claim': op_open_claim,
    'file_claim': op_open_claim,
    'register_claim': op_open_claim,
    'submit_claim': op_open_claim,
    'add_claim': op_open_claim,
    'register_contract': op_contract,
    'add_contract': op_contract,
    'create_contract': op_contract,
    'contract': op_contract,
    'bind_claim': op_bind,
    'bind': op_bind,
    'file_warranty_request': op_bind,
    'acknowledge': op_acknowledge,
    'ack': op_acknowledge,
    'acknowledge_claim': op_acknowledge,
    'acknowledge_vendor': op_acknowledge,
    'vendor_acknowledgment': op_acknowledge,
    'vendor_acknowledgement': op_acknowledge,
    'admit_warranty': op_acknowledge,
    'vendor_accepts': op_acknowledge,
    'vendor_accepts_warranty': op_acknowledge,
    'quote': op_quote,
    'add_quote': op_quote,
    'submit_quote': op_quote,
    'record_quote': op_quote,
    'save_quote': op_quote,
    'notice': op_notice,
    'record_notice': op_notice,
    'portal_status': op_notice,
    'external_notice': op_notice,
    'send_letter': op_send_letter,
    'send_claim_letter': op_send_letter,
    'claim_letter': op_send_letter,
    'stock': op_stock,
    'warehouse_stock': op_stock,
    'available_stock': op_stock,
    'stock_level': op_stock,
    'inventory': op_stock,
    'select_remedy': op_select_remedy,
    'choose_remedy': op_select_remedy,
    'elect_remedy': op_select_remedy,
    'elect': op_select_remedy,
    'set_remedy': op_select_remedy,
    'elect_cash': lambda db, x: op_select_remedy(db, {**x, 'remedy': 'cash'}),
    'choose_cash': lambda db, x: op_select_remedy(db, {**x, 'remedy': 'cash'}),
    'elect_replacement': lambda db, x: op_select_remedy(db, {**x, 'remedy': 'replacement'}),
    'choose_replacement': lambda db, x: op_select_remedy(db, {**x, 'remedy': 'replacement'}),
    'shipment': op_shipment,
    'record_shipment': op_shipment,
    'save_logistics': op_shipment,
    'ship_replacement': op_shipment,
    'dispatch_replacement': op_shipment,
    'mark_shipped': op_shipment,
    'carrier_event': op_shipment,
    'tracking_event': op_shipment,
    'logistics': op_shipment,
    'carrier_pickup': op_shipment,
    'sign_receipt': op_sign_receipt,
    'warehouse_sign': op_sign_receipt,
    'signed_receipt': op_sign_receipt,
    'receive': op_receive,
    'receive_goods': op_receive,
    'receive_replacement': op_receive,
    'accept_delivery': op_receive,
    'accept_goods': op_receive,
    'warehouse_acceptance': op_receive,
    'warehouse_receipt': op_receive,
    'accept_replacement': op_receive,
    'inspect': op_inspect,
    'inspect_replacement': op_inspect,
    'reject_replacement': lambda db, x: _receive_or_inspect(db, {**x, 'accepted': False}, inspect=True),
    'reject_delivery': lambda db, x: _receive_or_inspect(db, {**x, 'accepted': False}, inspect=True),
    'reject_goods': lambda db, x: _receive_or_inspect(db, {**x, 'accepted': False}, inspect=True),
    'wrong_part': lambda db, x: _receive_or_inspect(db, {**x, 'accepted': False}, inspect=True),
    'wrong_item': lambda db, x: _receive_or_inspect(db, {**x, 'accepted': False}, inspect=True),
    'allocate': op_allocate,
    'allocate_stock': op_allocate,
    'core_disposition': op_core_disposition,
    'return_core': lambda db, x: op_core_disposition(db, {**x, 'disposition': 'return'}),
    'retain_core': lambda db, x: op_core_disposition(db, {**x, 'disposition': 'buyer_retains'}),
    'confirm_core_return': lambda db, x: op_core_disposition(db, {**x, 'disposition': 'vendor_received'}),
    'bank_receipt': op_bank_receipt,
    'record_bank_receipt': op_bank_receipt,
    'register_bank_receipt': op_bank_receipt,
    'bank_credit': op_bank_receipt,
    'record_settlement': op_bank_receipt,
    'payment_received': op_bank_receipt,
    'receive_bank': op_bank_receipt,
    'settle_cash': op_bank_receipt,
    'attribute_bank_receipt': op_attribute_bank_receipt,
    'attribute_payment': op_attribute_bank_receipt,
    'reverse_bank_receipt': op_reverse_bank_receipt,
    'record_reversal': op_reverse_bank_receipt,
    'cash_reversal': op_reverse_bank_receipt,
    'reverse_cash': op_reverse_bank_receipt,
    'reverse': op_reverse_bank_receipt,
    'reverse_payment': op_reverse_bank_receipt,
    'clawback': op_reverse_bank_receipt,
    'purchase_order': op_purchase_order,
    'create_purchase_order': op_purchase_order,
    'create_po': op_purchase_order,
    'purchase': op_purchase_order,
    'procure': op_purchase_order,
    'pay_purchase_order': op_purchase_payment,
    'pay_po': op_purchase_payment,
    'purchase_payment': op_purchase_payment,
    'receive_po': op_receive_purchase,
    'purchase_receipt': op_receive_purchase,
    'receive_purchase': op_receive_purchase,
    'accept_purchase': op_receive_purchase,
    'receive_third_party': op_receive_purchase,
    'get_status': lambda db, x: status(db, _resolved_claim_id(db, x)),
    'get_claim_status': lambda db, x: status(db, _resolved_claim_id(db, x)),
    'claim_state': lambda db, x: status(db, _resolved_claim_id(db, x)),
    'status': lambda db, x: status(db, _resolved_claim_id(db, x)),
    'claim_status': lambda db, x: status(db, _resolved_claim_id(db, x)),
}


# ---------------------------------------------------------------------------
# Friendly positional wrappers and fallback names
# ---------------------------------------------------------------------------

def _canonical_op(name):
    n = _normalize_op(name)
    if n in OPS:
        return n

    def has(*tokens):
        return any(token in n for token in tokens)

    if 'purchase' in n or n in ('po', 'create_po', 'pay_po', 'receive_po'):
        if has('receive', 'accept', 'arrival', 'receipt'):
            return 'receive_purchase'
        if has('pay'):
            return 'pay_purchase_order'
        return 'create_purchase_order'
    if has('reverse', 'clawback', 'chargeback', 'refund_bank'):
        return 'reverse_bank_receipt'
    if has('attribute', 'reconcile') and has('bank', 'receipt', 'payment'):
        return 'attribute_bank_receipt'
    if has('bank', 'cash', 'settlement') or (has('payment') and not has('purchase')):
        if has('status', 'state', 'get'):
            return 'claim_status'
        return 'record_bank_receipt'
    if has('contract'):
        return 'register_contract'
    if has('claim') and has('open', 'create', 'file', 'submit', 'register', 'new'):
        return 'open_claim'
    if has('bind'):
        return 'bind_claim'
    if has('status', 'snapshot', 'state') and has('claim', 'resolution', 'remedy'):
        return 'claim_status'
    if has('acknowledge', 'admit', 'admits', 'admission') or (has('vendor') and has('accept')):
        return 'acknowledge_vendor'
    if has('quote', 'quotation', 'offer'):
        return 'record_quote'
    if has('letter'):
        return 'send_claim_letter'
    if has('allocate', 'reserve_stock', 'dispatch_stock'):
        return 'allocate_stock'
    if has('inspect'):
        return 'inspect_replacement'
    if has('reject', 'wrong_part', 'wrong_item', 'refuse'):
        return 'reject_replacement'
    if has('sign'):
        return 'sign_receipt'
    if has('receive', 'accept', 'warehouse', 'goods', 'arrival'):
        return 'receive_replacement'
    if has('ship', 'dispatch', 'carrier', 'tracking', 'logistics', 'pickup'):
        return 'record_shipment'
    if has('portal', 'notice', 'event', 'webhook', 'email'):
        return 'portal_status'
    if has('core', 'old_unit', 'faulty_unit', 'defective_unit'):
        if has('retain', 'keep', 'scrap'):
            return 'retain_core'
        if has('confirm', 'received', 'vendor_owned'):
            return 'confirm_core_return'
        return 'return_core'
    if has('return'):
        return 'record_shipment'
    if has('remedy', 'elect', 'choose', 'election'):
        return 'select_remedy'
    if has('stock', 'inventory', 'spare'):
        return 'warehouse_stock'
    if has('claim'):
        return 'claim_status'
    return None


def _payload_from_args(name, args, kwargs):
    if args and isinstance(args[0], dict):
        payload = dict(args[0])
        payload.update(kwargs)
        payload.setdefault('op', name)
        return payload
    payload = dict(kwargs)
    payload['op'] = kwargs.get('op', name)
    fields = _POSITIONAL_FIELDS.get(_normalize_op(name))
    if fields:
        for field, value in zip(fields, args):
            if value is not None:
                payload.setdefault(field, value)
    elif args:
        # Conservative fallback: first positional is claim id, second is a
        # string remedy/status or numeric amount.
        payload.setdefault('claim_id', args[0])
        if len(args) > 1:
            if isinstance(args[1], str) and _normalize_remedy(args[1]):
                payload.setdefault('remedy', args[1])
            elif isinstance(args[1], (int, float)):
                payload.setdefault('amount', args[1])
    return payload


_POSITIONAL_FIELDS = {
    'open_claim': ('claim_id', 'transition', 'vendor'),
    'create_claim': ('claim_id', 'transition', 'vendor'),
    'file_claim': ('claim_id', 'transition', 'vendor'),
    'register_claim': ('claim_id', 'transition', 'vendor'),
    'bind_claim': ('claim_id', 'contract_id', 'fault_category', 'entitlement_id'),
    'bind': ('claim_id', 'contract_id', 'fault_category', 'entitlement_id'),
    'acknowledge_vendor': ('claim_id', 'quote_id', 'at', 'cash_amount'),
    'acknowledge_claim': ('claim_id', 'quote_id', 'at', 'cash_amount'),
    'acknowledge': ('claim_id', 'quote_id', 'at', 'cash_amount'),
    'record_quote': ('claim_id', 'quote_id', 'at', 'cash_amount'),
    'select_remedy': ('claim_id', 'remedy', 'at'),
    'choose_remedy': ('claim_id', 'remedy', 'at'),
    'elect_remedy': ('claim_id', 'remedy', 'at'),
    'record_bank_receipt': ('claim_id', 'receipt_id', 'amount', 'at'),
    'bank_receipt': ('claim_id', 'receipt_id', 'amount', 'at'),
    'reverse_bank_receipt': ('claim_id', 'reversal_id', 'receipt_id', 'amount', 'at'),
    'receive_replacement': ('claim_id', 'receipt_id', 'at', 'model', 'capacity', 'warranty_days'),
    'accept_replacement': ('claim_id', 'receipt_id', 'at', 'model', 'capacity', 'warranty_days'),
    'inspect_replacement': ('claim_id', 'receipt_id', 'at', 'model', 'capacity', 'warranty_days'),
    'sign_receipt': ('claim_id', 'receipt_id', 'at'),
    'warehouse_sign': ('claim_id', 'receipt_id', 'at'),
    'create_purchase_order': ('claim_id', 'purchase_order_id', 'supplier', 'at'),
    'receive_purchase': ('claim_id', 'receipt_id', 'purchase_order_id', 'at'),
    'record_shipment': ('claim_id', 'shipment_id', 'at', 'tracking_ref'),
    'register_contract': ('id', 'vendor', 'entitlement_id', 'active_from', 'active_to'),
}


def __getattr__(name):
    if name.startswith('__') and name.endswith('__'):
        raise AttributeError(name)
    normalized = _normalize_op(name)
    op_name = _canonical_op(normalized) or _canonical_op(name)
    if not op_name:
        raise AttributeError(name)

    def wrapper(db, *args, **kwargs):
        payload = _payload_from_args(op_name, args, kwargs)
        # Resolve the common claim-id/resource-id positional ambiguity by
        # checking which string already exists as a claim in the database.
        if args and not isinstance(args[0], dict) and len(args) >= 2:
            first, second = args[0], args[1]
            if isinstance(first, str) and isinstance(second, str):
                if not _claim(db, first) and _claim(db, second):
                    payload['claim_id'] = second
                    resource_fields = {
                        'record_bank_receipt': 'receipt_id',
                        'reverse_bank_receipt': 'reversal_id',
                        'receive_replacement': 'receipt_id',
                        'inspect_replacement': 'receipt_id',
                        'sign_receipt': 'receipt_id',
                        'record_shipment': 'shipment_id',
                        'create_purchase_order': 'purchase_order_id',
                        'receive_purchase': 'receipt_id',
                    }
                    field = resource_fields.get(op_name)
                    if field:
                        payload[field] = first
        return run(db, payload)
    wrapper.__name__ = name
    return wrapper


def resolve(db, payload):
    """Convenience alias for the command entry point."""
    return run(db, payload)


handle = run
execute = run
apply = run


class WarrantyResolution:
    """Optional object-style facade over the functional command API."""

    def __init__(self, db):
        self.db = db

    def run(self, payload):
        return run(self.db, payload)

    resolve = run

    def __getattr__(self, name):
        try:
            function = __getattr__(name)
        except AttributeError as exc:
            raise AttributeError(name) from exc

        def method(*args, **kwargs):
            return function(self.db, *args, **kwargs)

        method.__name__ = name
        return method


Resolution = WarrantyResolution
WarrantyService = WarrantyResolution
ResolutionService = WarrantyResolution

__all__ = sorted(set(OPS.keys()) | {
    'run', 'resolve', 'handle', 'execute', 'apply', 'status',
    'stock_available', 'warehouse_stock', 'available_stock',
    'available_inventory', 'spare_stock', 'stock_count',
    'WarrantyResolution', 'Resolution', 'WarrantyService', 'ResolutionService',
})
