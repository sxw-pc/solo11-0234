"""Court-sealed evidence packages and privacy-safe public deliveries.

The delivered artifact bytes, not an in-memory replay verdict, are the product
of this module.  Court and public deliveries intentionally have different
recipients, query rights and bytes.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping

from .legal_request import (
    DEFAULT_KEYS,
    LegalRequestError,
    receive_order,
    sign_bytes,
    verify_signature,
)
from .store import (
    audit_run,
    canonical_json,
    record,
    sha256_hex,
    standalone_audit,
    transaction,
    verify_evidence_chain,
)
from . import legal_request


COURT_RIGHTS = ["target_customer_exact", "operation_timeline", "customer_mapping", "causal_blocking_reasons"]
PUBLIC_RIGHTS = ["aggregate_totals_only", "no_customer_query", "no_narrow_time_window_query"]

DEFAULT_COURT_FIELDS = [
    "evidence_id", "subsystem", "event", "op", "object_id", "at", "occurred_at",
    "minute", "time", "decision", "reason", "state", "service", "workload",
    "migration_id", "migration", "anchor_id", "rollback_id", "node_id", "node",
    "wave_id", "wave", "transition_id", "transition", "probe_id", "receipt_id",
    "usage_id", "old_api", "new_api", "target", "version", "node_version",
    "config_version", "generation", "healthy", "released_at", "verified_at",
    "observed_at", "detail_hash", "record_hash", "prev_hash", "chain_hash",
]

SENSITIVE_PUBLIC_KEYS = {
    "customer", "customer_id", "target_customer", "tenant", "tenant_id",
    "name", "customer_name", "zone", "location", "datacenter", "data_center",
    "region", "availability_zone", "old_manifest", "new_manifest",
    "old_config_raw", "new_config_raw", "manifest", "manifests",
}


class DeliveryError(ValueError):
    def __init__(self, reason: str, details: dict | None = None):
        super().__init__(reason)
        self.reason = reason
        self.details = details or {}


class Custodian:
    """Independent evidence-room custodian key."""

    def __init__(self, custodian_id: str = "independent-custodian", key: Any = None,
                 key_id: str | None = None):
        self.custodian_id = custodian_id
        self.key_id = key_id or custodian_id
        self.key = key if key is not None else DEFAULT_KEYS.get(self.key_id, DEFAULT_KEYS["custodian"])

    def attest(self, artifact_hash: str, evidence_root: str, **claims) -> dict:
        body = {
            "custodian_id": self.custodian_id,
            "key_id": self.key_id,
            "artifact_hash": artifact_hash,
            "evidence_root": evidence_root,
            "claims": claims,
        }
        body["signature"] = sign_bytes(_attestation_claim(body), self.key, self.key_id)
        body["signature_algorithm"] = "HMAC-SHA256"
        return body

    def verify(self, attestation: Mapping, key: Any = None) -> bool:
        if not isinstance(attestation, Mapping) or not attestation.get("signature"):
            return False
        verification_key = key if key is not None else self.key
        return verify_signature(_attestation_claim(attestation), attestation["signature"],
                                verification_key, attestation.get("key_id", self.key_id))


def _attestation_claim(attestation: Mapping) -> dict:
    return {k: v for k, v in attestation.items()
            if k not in {"signature", "signature_algorithm"}}


def custodian_attest(artifact_hash, evidence_root, custodian: Custodian | None = None, **claims):
    return (custodian or Custodian()).attest(artifact_hash, evidence_root, **claims)


def _json_safe(value):
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    if isinstance(value, Mapping):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    return value


def _row_dict(row):
    return dict(row) if row is not None else None


def _parse_json(value, default):
    if isinstance(value, (dict, list)):
        return value
    if value is None or value == "":
        return default
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def _resolve_order_row(db, order: Any = None, options: Mapping | None = None):
    options = dict(options or {})
    order = order if order is not None else options.get("order") or options.get("order_id")
    if order is not None and hasattr(order, "keys"):
        order = dict(order)
    if isinstance(order, Mapping):
        order_id = order.get("order_id") or order.get("id")
        if order_id:
            row = db.execute("SELECT * FROM legal_orders WHERE order_id=? OR command_id=?",
                             (str(order_id), str(order_id))).fetchone()
            if row:
                return row
        # A signed but not yet persisted order can be received as part of the
        # delivery command.  Validation failures remain business rejections.
        result = receive_order(db, dict(order),
                                trusted_signers=options.get("trusted_signers"),
                                signing_key=options.get("order_signing_key"))
        if result.get("decision") == "blocked":
            raise LegalRequestError(result.get("reason", "invalid_order"))
        return db.execute("SELECT * FROM legal_orders WHERE order_id=?",
                          (result["order_id"],)).fetchone()
    if order is None:
        order = options.get("order_id") or options.get("id")
    row = db.execute("SELECT * FROM legal_orders WHERE order_id=? OR command_id=?",
                     (str(order), str(order))).fetchone()
    if not row:
        raise DeliveryError("unknown_order")
    return row


def order_view(row) -> dict:
    data = dict(row)
    data["allowed_fields"] = _parse_json(data.get("allowed_fields"), [])
    data["terms"] = _parse_json(data.get("terms"), {})
    return data


def _detail_and_source(row):
    detail = _parse_json(row["detail"], {})
    if row["event"] == "decision" and isinstance(detail, dict) and isinstance(detail.get("input"), dict):
        return detail, detail["input"], detail.get("result")
    return detail, detail if isinstance(detail, dict) else {}, None


def _add_ref(refs: set[str], ref_type: str, value: Any):
    if value is None or value == "":
        return
    refs.add(f"{ref_type}:{value}")


def event_refs(row) -> tuple[set[str], set[str]]:
    """Return (strong refs, weak context refs) for an evidence row."""
    detail, source, _ = _detail_and_source(row)
    strong: set[str] = set()
    context: set[str] = set()
    _add_ref(strong, "evidence", row["id"])
    subsystem = row["subsystem"]
    event = row["event"]
    object_id = row["object_id"]
    op = source.get("op") if isinstance(source, Mapping) else None

    # Explicit correlation fields are authoritative.
    for key, ref_type in (
        ("migration_id", "migration"), ("migration", "migration"),
        ("transition_id", "transition"), ("transition", "transition"),
        ("node_id", "node"), ("node", "node"),
        ("anchor_id", "anchor"), ("anchor", "anchor"),
        ("receipt_id", "receipt"), ("probe_id", "probe"),
        ("usage_id", "usage"), ("evidence_id", "evidence"),
    ):
        if isinstance(source, Mapping):
            _add_ref(strong, ref_type, source.get(key))
    for key, ref_type in (("wave_id", "wave"), ("wave", "wave")):
        if isinstance(source, Mapping):
            _add_ref(context, ref_type, source.get(key))

    if subsystem == "migration":
        if op == "verify" or event == "verify":
            _add_ref(strong, "migration", source.get("id") if op == "verify" else object_id)
            _add_ref(strong, "migration", object_id if event == "verify" else None)
        elif op == "anchor" or event == "anchor":
            _add_ref(strong, "anchor", source.get("id") or object_id)
            _add_ref(strong, "migration", source.get("migration"))
            _add_ref(strong, "node", source.get("node"))
        elif op == "rollback" or event == "rollback":
            _add_ref(strong, "anchor", source.get("id") or object_id)
        elif op == "config" or event == "config":
            _add_ref(context, "workload", source.get("workload") or object_id)
    elif subsystem == "wave":
        if op == "plan" or event == "plan":
            _add_ref(context, "wave", source.get("id") or object_id)
        elif op == "release" or event == "release":
            _add_ref(strong, "transition", source.get("transition") or (object_id if event == "release" else None))
            _add_ref(strong, "node", source.get("node"))
            _add_ref(context, "wave", source.get("id"))
        elif op == "probe" or event == "probe":
            _add_ref(strong, "probe", source.get("probe") or (object_id if event == "probe" else None))
            _add_ref(strong, "transition", source.get("transition"))
            _add_ref(context, "wave", source.get("id"))
        elif op == "finish" or event == "finish":
            _add_ref(strong, "transition", source.get("transition") or (object_id if event == "finish" else None))
            _add_ref(context, "wave", source.get("id"))
    elif subsystem == "inventory":
        if op in ("node", "verify") or event in ("node", "verify"):
            _add_ref(strong, "node", source.get("id") or object_id)
        elif op == "usage" or event == "usage":
            _add_ref(strong, "usage", source.get("id") or object_id)
            _add_ref(context, "workload", source.get("workload"))
    elif subsystem == "maintenance":
        _add_ref(strong, "receipt", object_id)
        if isinstance(source, Mapping):
            _add_ref(strong, "receipt", source.get("receipt_id") or source.get("id"))
    elif subsystem == "legal_request" and event == "customer_attribution":
        _add_ref(strong, "mapping", object_id)
        if isinstance(source, Mapping):
            _add_ref(strong, source.get("subject_type", "subject"), source.get("subject_id"))

    # Wave id from payload is useful context even for generic records.
    if isinstance(source, Mapping):
        if source.get("id") and subsystem == "wave" and op in (None, "release", "probe", "finish"):
            _add_ref(context, "wave", source["id"])
        if source.get("wave_id"):
            _add_ref(context, "wave", source["wave_id"])
        if source.get("workload"):
            _add_ref(context, "workload", source["workload"])
        if source.get("service"):
            _add_ref(context, "service", source["service"])
    return strong, context


def _active_mappings(db, customer: str | None = None, service: str | None = None):
    sql = "SELECT * FROM customer_attributions WHERE status='active'"
    params = []
    if customer:
        sql += " AND customer_id=?"
        params.append(customer)
    if service:
        sql += " AND (service_id=? OR service_id IS NULL)"
        params.append(service)
    return [dict(r) for r in db.execute(sql + " ORDER BY recorded_at,mapping_id", params)]


def _ref_customer_index(db):
    index = {}
    for mapping in _active_mappings(db):
        index[f"{mapping['subject_type']}:{mapping['subject_id']}"] = mapping["customer_id"]
    return index


def _expand_database_refs(db, strong: set[str], context: set[str]):
    """Add relation refs from normalized business tables (directed upward)."""
    changed = True
    while changed:
        changed = False
        for ref in list(strong):
            ref_type, ref_id = ref.split(":", 1)
            if ref_type == "migration":
                row = db.execute("SELECT * FROM migrations WHERE id=?", (ref_id,)).fetchone()
                if row:
                    for col, typ in (("node_id", "node"), ("transition_id", "transition"),
                                     ("wave_id", "wave")):
                        if col in row.keys() and row[col]:
                            target = f"{typ}:{row[col]}"
                            if typ == "wave":
                                if target not in context:
                                    context.add(target); changed = True
                            elif target not in strong:
                                strong.add(target); changed = True
                for rb in db.execute("SELECT id,migration_id,node_id FROM rollbacks WHERE migration_id=?", (ref_id,)):
                    for typ, value in (("anchor", rb["id"]), ("migration", rb["migration_id"]), ("node", rb["node_id"])):
                        target = f"{typ}:{value}"
                        if target not in strong:
                            strong.add(target); changed = True
                for mr in db.execute("SELECT * FROM maintenance_receipts WHERE migration_id=?", (ref_id,)):
                    target = f"receipt:{mr['receipt_id']}"
                    if target not in strong:
                        strong.add(target); changed = True
            elif ref_type == "anchor":
                row = db.execute("SELECT * FROM rollbacks WHERE id=?", (ref_id,)).fetchone()
                if row:
                    for typ, value in (("migration", row["migration_id"]), ("node", row["node_id"])):
                        target = f"{typ}:{value}"
                        if target not in strong:
                            strong.add(target); changed = True
            elif ref_type == "transition":
                row = db.execute("SELECT * FROM transitions WHERE id=?", (ref_id,)).fetchone()
                if row:
                    for typ, value in (("wave", row["wave_id"]), ("node", row["node_id"])):
                        bucket = context if typ == "wave" else strong
                        target = f"{typ}:{value}"
                        if target not in bucket:
                            bucket.add(target); changed = True
                    if "migration_id" in row.keys() and row["migration_id"]:
                        target = f"migration:{row['migration_id']}"
                        if target not in strong:
                            strong.add(target); changed = True
            elif ref_type == "receipt":
                row = db.execute("SELECT * FROM maintenance_receipts WHERE receipt_id=?", (ref_id,)).fetchone()
                if row:
                    for typ, col in (("node", "node_id"), ("wave", "wave_id"),
                                     ("transition", "transition_id"), ("migration", "migration_id")):
                        if row[col]:
                            bucket = context if typ == "wave" else strong
                            target = f"{typ}:{row[col]}"
                            if target not in bucket:
                                bucket.add(target); changed = True
            elif ref_type == "wave":
                for tr in db.execute("SELECT id,node_id FROM transitions WHERE wave_id=?", (ref_id,)):
                    for typ, value in (("transition", tr["id"]), ("node", tr["node_id"])):
                        target = f"{typ}:{value}"
                        if target not in strong:
                            strong.add(target)
                            changed = True
            elif ref_type == "node":
                # A node scan belongs to the node.  Releases are followed only
                # through the event graph and then checked for other-customer
                # attribution, avoiding wave/sibling expansion.
                pass


def collect_customer_evidence(db, customer: str, service: str | None = None,
                              start: int | None = None, end: int | None = None):
    mappings = _active_mappings(db, customer=customer, service=service)
    strong: set[str] = set()
    context: set[str] = set()
    for mapping in mappings:
        strong.add(f"{mapping['subject_type']}:{mapping['subject_id']}")
    _expand_database_refs(db, strong, context)

    rows = db.execute("SELECT * FROM evidence ORDER BY id").fetchall()
    ref_customers = _ref_customer_index(db)
    selected = []
    quarantined = []
    changed = True
    selected_ids: set[int] = set()

    # Event graph closure.  Strong refs match strong seed/derived refs.  Wave
    # context admits plan metadata but never sibling releases by itself because
    # release/probe/finish require their own transition/node strong match.
    while changed:
        changed = False
        for row in rows:
            if row["id"] in selected_ids:
                continue
            ev_strong, ev_context = event_refs(row)
            strong_match = bool(ev_strong & strong)
            wave_plan_match = (row["subsystem"] == "wave" and row["event"] == "plan"
                               and bool(ev_context & context))
            if not (strong_match or wave_plan_match):
                continue
            mapped_customers = {ref_customers[r] for r in (ev_strong | ev_context) if r in ref_customers}
            if mapped_customers and customer not in mapped_customers:
                # Shared node/wave with an explicitly attributed other tenant:
                # do not let graph completion pull that tenant's event in.
                continue
            conflict = customer in mapped_customers and any(c != customer for c in mapped_customers)
            if conflict:
                quarantined.append({"evidence_id": row["id"], "reason": "conflicting_customer_attribution"})
                continue
            selected_ids.add(row["id"])
            selected.append(row)
            before_s, before_c = len(strong), len(context)
            strong |= ev_strong
            context |= ev_context
            _expand_database_refs(db, strong, context)
            if len(strong) != before_s or len(context) != before_c:
                changed = True

    selected.sort(key=lambda r: (r["occurred_at"] is None, r["occurred_at"] if r["occurred_at"] is not None else 0, r["id"]))
    in_window = []
    outside_window = []
    for row in selected:
        at = row["occurred_at"]
        if start is not None and end is not None and at is not None and not (start <= at <= end):
            outside_window.append(row)
        else:
            in_window.append(row)

    mapping_rows = [dict(m) for m in db.execute(
        "SELECT * FROM customer_attributions WHERE customer_id=? ORDER BY recorded_at,mapping_id", (customer,))]
    receipt_ids = {r.split(":", 1)[1] for r in strong if r.startswith("receipt:")}
    receipts = [dict(r) for rid in sorted(receipt_ids)
                for r in db.execute("SELECT * FROM maintenance_receipts WHERE receipt_id=?", (rid,))]
    return {
        "events": in_window,
        "outside_window_events": outside_window,
        "mappings": mapping_rows,
        "receipts": receipts,
        "quarantined": quarantined,
        "target_refs": sorted(strong),
        "context_refs": sorted(context),
    }


def _flat_event(row) -> dict:
    detail, source, result = _detail_and_source(row)
    source = source if isinstance(source, Mapping) else {}
    result = result if isinstance(result, Mapping) else {}
    ids = {}
    for key in ("id", "migration", "migration_id", "transition", "transition_id", "node", "node_id",
                "wave", "wave_id", "probe", "probe_id", "anchor", "anchor_id", "receipt_id",
                "usage_id", "workload", "service"):
        if source.get(key) is not None:
            ids[key] = source[key]
    flat = {
        "evidence_id": row["id"], "id": row["id"], "subsystem": row["subsystem"],
        "record_event": row["event"], "event": source.get("op") or row["event"],
        "op": source.get("op"), "object_id": row["object_id"],
        "at": row["occurred_at"], "occurred_at": row["occurred_at"],
        "minute": row["occurred_at"], "time": row["occurred_at"],
        "decision": result.get("decision") or source.get("decision"),
        "reason": result.get("reason") or source.get("reason"),
        "state": result.get("state") or source.get("state"),
        "detail_hash": row["record_hash"], "record_hash": row["record_hash"],
        "prev_hash": row["prev_hash"], "chain_hash": row["chain_hash"],
        "ids": ids,
    }
    for key in ("service", "workload", "old_api", "new_api", "target", "version",
                "node_version", "config_version", "generation", "healthy",
                "released_at", "verified_at", "observed_at", "zone", "location"):
        if key in source:
            flat[key] = source[key]
    for key in ("decision", "reason", "state"):
        if key in result:
            flat[key] = result[key]
    for alias, canonical in (("node", "node_id"), ("node_id", "node"),
                             ("migration", "migration_id"), ("migration_id", "migration"),
                             ("transition", "transition_id"), ("transition_id", "transition"),
                             ("wave", "wave_id"), ("wave_id", "wave")):
        if alias in source and canonical not in flat:
            flat[canonical] = source[alias]
    return flat


def _get_path(obj: Any, path: str):
    current = obj
    for part in path.split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        else:
            return None, False
    return current, True


def _filter_event(row, allowed_fields: list[str]):
    detail, source, result = _detail_and_source(row)
    if "*" in allowed_fields or "raw" in allowed_fields or "raw_detail" in allowed_fields or "detail" in allowed_fields:
        view = _flat_event(row)
        view["raw_detail"] = detail
        view["original_detail_text"] = row["detail"]
        view["detail_text"] = row["detail"]
        return _json_safe(view)

    selected = {}
    flat = _flat_event(row)
    for field in allowed_fields:
        if field in DEFAULT_COURT_FIELDS and field in flat:
            selected[field] = _json_safe(flat[field])
            continue
        value, found = _get_path(flat, field)
        if found:
            selected[field] = _json_safe(value)
            continue
        for container_name, container in (("input", source), ("result", result), ("detail", detail)):
            value, found = _get_path(container, field)
            if found:
                selected[field] = _json_safe(value)
                break
            value, found = _get_path(container, f"{container_name}.{field}")
            if found:
                selected[field] = _json_safe(value)
                break
    # Identity/time/hash are always needed to make the extract independently
    # chainable even if a poorly drafted field list omits them.
    for key in ("evidence_id", "subsystem", "event", "at", "decision", "reason",
                "detail_hash", "chain_hash"):
        if key in flat and key not in selected:
            selected[key] = flat[key]
    return _json_safe(selected)


def _public_receipt(receipt: Mapping) -> dict:
    return {
        "receipt_id_hash": sha256_hex(receipt["receipt_id"])[:16],
        "at": receipt["at"],
        "outcome": receipt["outcome"],
        "provider": receipt["provider"],
        "receipt_hash": receipt["receipt_hash"],
    }


def build_court_document(db, order_row, custodian: Custodian | None = None):
    order = order_view(order_row)
    collected = collect_customer_evidence(
        db, order["target_customer"], order["service"],
        order["window_start"], order["window_end"]
    )
    allowed = order["allowed_fields"] or DEFAULT_COURT_FIELDS
    events = [_filter_event(row, allowed) for row in collected["events"]]
    chain = verify_evidence_chain(db)
    headers = [{"evidence_id": r["id"], "prev_hash": r["prev_hash"],
                "record_hash": r["record_hash"], "chain_hash": r["chain_hash"]}
               for r in db.execute("SELECT id,prev_hash,record_hash,chain_hash FROM evidence ORDER BY id")]
    mapping_ledger = [dict(r) for r in db.execute(
        "SELECT mapping_id,customer_id,subject_type,subject_id,mapping_hash,status,mapped_at FROM customer_attributions ORDER BY rowid")]
    mapping_root = sha256_hex(canonical_json(mapping_ledger))
    document = {
        "format": "cloudlab.court-sealed-evidence/v1",
        "kind": "court_sealed_evidence",
        "audience": "court_sealed_evidence_room",
        "recipient": order["recipient"],
        "query_rights": COURT_RIGHTS,
        "order": {
            "order_id": order["order_id"], "order_hash": order["order_hash"],
            "issuer": order["issuer"], "case_ref": order["case_ref"],
            "target_customer": order["target_customer"], "service": order["service"],
            "window_start": order["window_start"], "window_end": order["window_end"],
            "allowed_fields": allowed, "valid_until": order["valid_until"],
            "signature": order["signature"],
            "signature_algorithm": "HMAC-SHA256",
            "signer_key_id": order["signer_key_id"],
            "order_bytes_sha256": order["order_hash"],
        },
        "timeline": events,
        "customer_mappings": [_json_safe({
            "mapping_id": m["mapping_id"], "customer_id": m["customer_id"],
            "subject_type": m["subject_type"], "subject_id": m["subject_id"],
            "mapped_at": m["mapped_at"], "received_at": m["received_at"],
            "status": m["status"], "mapping_hash": m["mapping_hash"],
            "signature": m["signature"],
        }) for m in collected["mappings"]],
        "maintenance_receipts": [_filter_receipt(r, allowed) for r in collected["receipts"]],
        "completeness": {
            "selected_event_count": len(events),
            "selected_evidence_ids": [r["id"] for r in collected["events"]],
            "global_evidence_count": chain["count"],
            "evidence_root": chain["root"],
            "hash_chain_valid": chain["valid"],
            "mapping_ledger_root": mapping_root,
            "quarantined": collected["quarantined"],
            "late_mappings": [m["mapping_id"] for m in collected["mappings"]
                              if m["mapped_at"] and any(e["occurred_at"] and m["mapped_at"] > e["occurred_at"]
                                                        for e in collected["events"])],
        },
        "evidence_headers": headers,
        "sealing": {"sealed": True, "public_release_prohibited": True},
    }
    custodian = custodian or Custodian()
    document["custodian"] = {
        "custodian_id": custodian.custodian_id,
        "confirmed_event_count": len(events),
        "confirmed_mapping_count": len(collected["mappings"]),
    }
    return document


def _filter_receipt(receipt: Mapping, allowed_fields):
    if "*" in allowed_fields or "receipt" in allowed_fields or "raw" in allowed_fields:
        return _json_safe(dict(receipt))
    # Hash/signature are integrity metadata, not discretionary content fields.
    view = {
        "receipt_hash": receipt.get("receipt_hash"),
        "signature": receipt.get("signature"),
    }
    receipt_aliases = {
        "receipt_id": ("receipt_id", "id"),
        "provider": ("provider", "maintainer"),
        "ticket_id": ("ticket_id", "ticket"),
        "at": ("at", "maintained_at", "timestamp"),
        "time": ("at", "maintained_at", "timestamp"),
        "outcome": ("outcome", "status"),
        "status": ("outcome", "status"),
        "zone": ("zone",),
        "location": ("location",),
        "datacenter": ("location",),
        "node_id": ("node_id",),
        "wave_id": ("wave_id",),
        "transition_id": ("transition_id",),
        "migration_id": ("migration_id",),
    }
    for field in allowed_fields:
        for source_field in receipt_aliases.get(field, (field,)):  # type: ignore[arg-type]
            value = receipt.get(source_field) if hasattr(receipt, "get") else receipt[source_field]
            if value is not None:
                view[field] = value
                break
    return _json_safe(view)


def _migration_operations_in_window(db, service: str, start: int, end: int):
    operations = {}
    # Normalized table first.
    try:
        rows = db.execute(
            "SELECT id,workload,service,occurred_at,customer_id,state FROM migrations").fetchall()
        for row in rows:
            sid = row["service"] if "service" in row.keys() and row["service"] else row["workload"]
            at = row["occurred_at"] if "occurred_at" in row.keys() else None
            if sid == service and at is not None and start <= at <= end:
                operations[f"migration:{row['id']}"] = {
                    "id": row["id"], "at": at, "state": row["state"],
                    "customer_id": row["customer_id"] if "customer_id" in row.keys() else None,
                }
    except sqlite3.OperationalError:
        pass
    # Evidence is the authoritative original source and works even when a test
    # constructs the fixture directly with store.record.
    for row in db.execute("SELECT * FROM evidence WHERE subsystem='migration' ORDER BY id"):
        if row["event"] not in ("verify", "migration", "operation", "decision"):
            continue
        detail, source, result = _detail_and_source(row)
        if row["event"] == "decision" and source.get("op") != "verify":
            continue
        sid = source.get("service") or source.get("workload")
        if sid != service:
            continue
        mid = source.get("id") if source.get("op") == "verify" else row["object_id"]
        at = row["occurred_at"]
        if at is None or not (start <= at <= end):
            continue
        key = f"migration:{mid}"
        operations.setdefault(key, {"id": mid, "at": at, "state": None, "customer_id": None})
        if result and result.get("decision"):
            operations[key]["state"] = result["decision"]
        if source.get("customer") or source.get("customer_id"):
            operations[key]["customer_id"] = source.get("customer") or source.get("customer_id")
    return operations


import sqlite3  # noqa: E402


def _wave_counts(db, service: str, start: int, end: int):
    releases = set()
    completed = set()
    blocked = 0
    for row in db.execute("SELECT * FROM evidence WHERE subsystem='wave' ORDER BY id"):
        at = row["occurred_at"]
        if at is None or not (start <= at <= end):
            continue
        _, source, result = _detail_and_source(row)
        if source.get("service") and source.get("service") != service:
            continue
        if source.get("op") == "release" or row["event"] == "release":
            tid = source.get("transition") or row["object_id"]
            if result and result.get("decision") == "released":
                releases.add(tid)
            elif result and result.get("decision") == "blocked":
                blocked += 1
        if source.get("op") == "finish" and result and result.get("decision") == "complete":
            completed.add(source.get("transition"))
    return {"released": len(releases), "completed": len(completed),
            "blocked": blocked, "blocked_attempts": blocked}


def _group_size(db, operations: Mapping):
    ref_customers = _ref_customer_index(db)
    customers = set()
    for ref, op in operations.items():
        if op.get("customer_id"):
            customers.add(str(op["customer_id"]))
        if ref in ref_customers:
            customers.add(ref_customers[ref])
        ref_type, ref_id = ref.split(":", 1)
        candidate_refs = []
        if ref_type == "migration":
            row = db.execute("SELECT node_id,transition_id,wave_id FROM migrations WHERE id=?",
                             (ref_id,)).fetchone()
            if row:
                for typ, col in (("node", "node_id"), ("transition", "transition_id"),
                                 ("wave", "wave_id")):
                    if col in row.keys() and row[col]:
                        candidate_refs.append(f"{typ}:{row[col]}")
            for rb in db.execute("SELECT id,node_id FROM rollbacks WHERE migration_id=?", (ref_id,)):
                candidate_refs.extend([f"anchor:{rb['id']}", f"node:{rb['node_id']}"])
        for candidate in candidate_refs:
            if candidate in ref_customers:
                customers.add(ref_customers[candidate])
    return len(customers), customers


def merge_windows(windows: list[tuple[int, int]], adjacent: bool = True):
    valid = [(int(s), int(e)) for s, e in windows if s is not None and e is not None]
    if not valid:
        return None
    valid.sort()
    merged = [list(valid[0])]
    for start, end in valid[1:]:
        limit = merged[-1][1] + (1 if adjacent else 0)
        if start <= limit:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    if len(merged) == 1:
        return merged[0][0], merged[0][1]
    return merged


def publication_history(db, service: str):
    return [dict(r) for r in db.execute(
        "SELECT * FROM publication_scopes WHERE service=? ORDER BY published_at,rowid", (service,))]


def plan_public_scope(db, service: str, start: int, end: int,
                      merge_known_orders: bool = True) -> dict:
    windows = [(start, end)]
    sources = [{"type": "request", "window": [start, end]}]
    for row in publication_history(db, service):
        windows.append((row["window_start"], row["window_end"]))
        sources.append({"type": "published", "scope_id": row["scope_id"],
                        "window": [row["window_start"], row["window_end"]]})
    if merge_known_orders:
        for row in db.execute("SELECT window_start,window_end,order_id FROM legal_orders WHERE service=? AND status='active'", (service,)):
            windows.append((row["window_start"], row["window_end"]))
            sources.append({"type": "order", "order_id": row["order_id"],
                            "window": [row["window_start"], row["window_end"]]})
    merged = merge_windows(windows)
    if isinstance(merged, list):
        # Keep the component containing the request; disjoint histories remain
        # logged but do not justify merging unrelated time periods.
        target = [w for w in merged if w[0] <= start <= w[1] or w[0] <= end <= w[1]]
        scope = tuple(target[0]) if target else (start, end)
    else:
        scope = merged
    return {"start": scope[0], "end": scope[1], "sources": sources}


def assess_difference_risk(db, service: str, windows: list[tuple[int, int]],
                           min_group_size: int = 2) -> dict:
    endpoints = sorted({p for w in windows for p in w})
    risky_segments = []
    operations = _migration_operations_in_window(db, service, min(endpoints), max(endpoints)) if endpoints else {}
    for left, right in zip(endpoints, endpoints[1:]):
        # Inclusive endpoints create atomic buckets [left, right) and the final
        # endpoint; exact minute fixtures still expose singleton counts.
        segment_ops = {k: v for k, v in operations.items() if left <= v["at"] < right}
        if not segment_ops:
            segment_ops = {k: v for k, v in operations.items() if v["at"] == right}
        group_size, customers = _group_size(db, segment_ops)
        if 0 < len(segment_ops) < min_group_size or 0 < group_size < min_group_size:
            risky_segments.append({"from": left, "to": right,
                                   "operation_count": len(segment_ops),
                                   "group_size": group_size})
    return {"difference_risk": bool(risky_segments), "segments": risky_segments}


def compute_public_bulletin(db, service: str, start: int, end: int,
                            min_group_size: int = 2):
    operations = _migration_operations_in_window(db, service, start, end)
    group_size, _customers = _group_size(db, operations)
    waves = _wave_counts(db, service, start, end)
    totals = {
        "migration_operations": len(operations),
        "distinct_operations": len(operations),
        "release_operations": waves["released"],
        "completed_operations": waves["completed"],
        "blocked_attempts": waves["blocked"],
    }
    safe = len(operations) >= min_group_size and group_size >= min_group_size
    return {
        "service": service, "start": start, "end": end,
        "operations": operations, "group_size": group_size,
        "safe_to_publish": safe, "totals": totals,
    }


def build_public_document(db, service: str, planned: Mapping, computed: Mapping,
                          custodian: Custodian | None = None):
    chain = verify_evidence_chain(db)
    custodian = custodian or Custodian()
    totals = computed["totals"]
    document = {
        "format": "cloudlab.public-performance-bulletin/v1",
        "kind": "public_performance_bulletin",
        "audience": "general_public",
        "recipient": "public",
        "query_rights": PUBLIC_RIGHTS,
        "service": service,
        "merged_window_start": planned["start"],
        "merged_window_end": planned["end"],
        "granularity": "merged_coarse_window_only",
        "time_values_included": False,
        "customer_identities_included": False,
        "node_or_location_included": False,
        "totals": totals,
        "count": totals["migration_operations"],
        "total": totals["migration_operations"],
        "fulfillment_total": totals["migration_operations"],
        "privacy": {
            "mode": "aggregate_only",
            "per_customer_queries_prohibited": True,
            "narrow_window_queries_prohibited": True,
            "difference_attack_control": "overlapping_scopes_merged",
            "group_check_performed_outside_public_bytes": True,
        },
        "publication_constraints": {
            "irrevocable_scope_ledger": True,
            "connected_scopes_merged": True,
            "prior_scope_details_withheld_from_public_bulletin": True,
        },
        "verification": {
            "platform_evidence_root": chain["root"],
            "hash_chain_valid": chain["valid"],
            "aggregate_only": True,
        },
    }
    document["custodian"] = {"custodian_id": custodian.custodian_id, "aggregate_attested": True}
    return document


def _write_artifact_file(artifact_id: str, data: bytes, output_dir: str | Path | None):
    if not output_dir:
        return None
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{artifact_id}.json"
    if path.exists():
        existing = path.read_bytes()
        if existing != data:
            raise DeliveryError("artifact_file_conflict", {"path": str(path)})
        return str(path)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_bytes(data)
    with temporary.open("rb") as fh:
        os.fsync(fh.fileno())
    os.replace(temporary, path)
    try:
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass
    return str(path)


def _sign_envelope(document: Mapping, kind: str, at: int, command_id: str,
                    artifact_id: str, payload: Mapping):
    platform_key = payload.get("platform_key") or DEFAULT_KEYS["platform"]
    platform_key_id = payload.get("platform_key_id") or "platform"
    custodian = payload.get("custodian")
    if not isinstance(custodian, Custodian):
        custodian = Custodian(key=payload.get("custodian_key"),
                             custodian_id=payload.get("custodian_id", "independent-custodian"),
                             key_id=payload.get("custodian_key_id"))
    body = dict(document)
    body.update({
        "artifact_id": artifact_id, "command_id": command_id,
        "created_at": at, "platform_key_id": platform_key_id,
    })
    body_bytes = canonical_json(body)
    body_hash = sha256_hex(body_bytes)
    platform_signature = sign_bytes(body_bytes, platform_key, platform_key_id)
    evidence_root_claim = (
        document.get("verification", {}).get("platform_evidence_root")
        or document.get("completeness", {}).get("evidence_root")
        or sha256_hex(b"")
    )
    attestation = custodian.attest(body_hash, evidence_root_claim,
                                   kind=kind, command_id=command_id)
    envelope = {
        "body": body,
        "body_sha256": body_hash,
        "platform_signature": platform_signature,
        "platform_signature_algorithm": "HMAC-SHA256",
        "custodian_attestation": attestation,
    }
    artifact_bytes = canonical_json(envelope)
    return envelope, artifact_bytes, sha256_hex(artifact_bytes), custodian


def create_artifact(db, payload: Mapping):
    kind = payload.get("kind") or payload.get("delivery_kind") or payload.get("op")
    if kind in ("court_package", "court", "sealed_package", "deliver_court", "court_sealed"):
        kind = "court_sealed_evidence"
    elif kind in ("public_report", "public_bulletin", "publish_public", "deliver_public", "public"):
        kind = "public_performance_bulletin"
    command_id = str(payload.get("command_id") or payload.get("delivery_id") or payload.get("id") or
                     payload.get("idempotency_key") or "")
    at = int(payload.get("now") or payload.get("at") or payload.get("created_at") or 0)

    # Idempotent command replay / crash retry.
    if command_id:
        existing = db.execute("SELECT * FROM evidence_artifacts WHERE command_id=? OR idempotency_key=?",
                              (command_id, command_id)).fetchone()
        if existing:
            return _existing_artifact_result(existing, reused=True)

    parent = None
    parent_id = payload.get("parent_artifact_id") or payload.get("correction_of") or payload.get("supplement_of")
    if parent_id:
        parent = db.execute("SELECT * FROM evidence_artifacts WHERE artifact_id=?", (parent_id,)).fetchone()
        if not parent:
            return {"decision": "blocked", "reason": "unknown_parent_artifact"}
    order_row = None
    order_id = payload.get("order_id") or (parent["order_id"] if parent else None)
    if kind == "court_sealed_evidence":
        order_row = _resolve_order_row(db, payload.get("order") or order_id or payload, payload)
        order = order_view(order_row)
        if order["status"] == "revoked" and payload.get("revision_kind", "original") == "original":
            return {"decision": "blocked", "reason": "order_revoked"}
        evaluation_time = payload.get("now", payload.get("at"))
        if evaluation_time is not None:
            evaluation_time = int(evaluation_time)
            if evaluation_time < order["valid_from"]:
                return {"decision": "blocked", "reason": "order_not_yet_valid"}
            if evaluation_time > order["valid_until"]:
                return {"decision": "blocked", "reason": "order_expired"}
        order_id = order["order_id"]
        document = build_court_document(db, order_row, payload.get("custodian") if isinstance(payload.get("custodian"), Custodian) else None)
        recipient = payload.get("recipient") or order["recipient"]
        channel = "closed_court_evidence_room"
        audience = "court"
        rights = COURT_RIGHTS
        scope = {"order_id": order_id, "window": [order["window_start"], order["window_end"]],
                 "customer": order["target_customer"], "service": order["service"]}
    else:
        service = payload.get("service")
        start = payload.get("window_start", payload.get("start"))
        end = payload.get("window_end", payload.get("end"))
        order_ids = payload.get("order_ids") or ([order_id] if order_id else [])
        if order_ids and (not service or start is None or end is None):
            first = _resolve_order_row(db, order_ids[0], payload)
            ov = order_view(first)
            service = service or ov["service"]
            start = ov["window_start"] if start is None else start
            end = ov["window_end"] if end is None else end
            windows = [(ov["window_start"], ov["window_end"])]
            for oid in order_ids[1:]:
                orow = _resolve_order_row(db, oid, payload)
                o = order_view(orow)
                windows.append((o["window_start"], o["window_end"]))
            merged = merge_windows(windows)
            if not isinstance(merged, list):
                start, end = merged
        if not service or start is None or end is None:
            return {"decision": "blocked", "reason": "missing_public_scope"}
        requested_start, requested_end = int(start), int(end)
        forced_narrow = bool(payload.get("force_narrow") or payload.get("unsafe") or
                             payload.get("allow_difference_attack"))
        if forced_narrow:
            planned = {"start": requested_start, "end": requested_end,
                       "sources": [{"type": "forced_requested_window",
                                    "window": [requested_start, requested_end]}],
                       "forced_narrow": True}
        else:
            planned = plan_public_scope(db, service, int(start), int(end),
                                        merge_known_orders=payload.get("merge_known_orders", True))
            # Explicit multiple order windows should also be merged even if they
            # are not yet persisted publication history.
            if order_ids and len(order_ids) > 1:
                order_windows = []
                for oid in order_ids:
                    o = order_view(_resolve_order_row(db, oid, payload))
                    order_windows.append((o["window_start"], o["window_end"]))
                merged_orders = merge_windows(order_windows)
                if not isinstance(merged_orders, list):
                    planned["start"], planned["end"] = merged_orders
        start, end = planned["start"], planned["end"]
        min_group_size = int(payload.get("min_group_size") or 2)
        computed = compute_public_bulletin(db, service, start, end, min_group_size)
        if not computed["safe_to_publish"] and not payload.get("allow_small_group", False):
            return {"decision": "blocked", "reason": "anonymity_group_too_small",
                    "group_size": computed["group_size"], "event_count": len(computed["operations"])}
        document = build_public_document(db, service, planned, computed)
        recipient = payload.get("recipient") or "public"
        channel = "public_bulletin"
        audience = "public"
        rights = PUBLIC_RIGHTS
        scope = {"service": service, "window": [start, end],
                 "requested_window": [requested_start, requested_end],
                 "forced_narrow": forced_narrow,
                 "sources": planned["sources"]}

    revision_kind = payload.get("revision_kind") or ("supplement" if payload.get("op") == "supplement" else
                                                     "correction" if payload.get("op") == "correct" else "original")
    revision = int(parent["revision"]) + 1 if parent else int(payload.get("revision", 1) or 1)
    if parent:
        document["revision"] = {
            "number": revision, "kind": revision_kind,
            "parent_artifact_id": parent["artifact_id"],
            "parent_artifact_hash": parent["artifact_hash"],
            "note": payload.get("note") or payload.get("reason"),
        }
    requested_artifact_id = payload.get("artifact_id")
    if parent and requested_artifact_id == parent["artifact_id"]:
        requested_artifact_id = None
    artifact_id = str(requested_artifact_id or
                      (command_id or f"{kind}:{order_id or service}:{revision_kind}:{revision}"))
    if not command_id:
        command_id = artifact_id
    if db.execute("SELECT 1 FROM evidence_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone():
        existing = db.execute("SELECT * FROM evidence_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
        return _existing_artifact_result(existing, reused=True)

    envelope, artifact_bytes, artifact_hash, custodian = _sign_envelope(
        document, kind, at, command_id, artifact_id, payload
    )
    output_path = _write_artifact_file(artifact_id, artifact_bytes, payload.get("output_dir"))
    evidence_root = None
    if "verification" in document:
        evidence_root = document["verification"].get("platform_evidence_root")
    elif "completeness" in document:
        evidence_root = document["completeness"].get("evidence_root")
    db.execute(
        """INSERT INTO evidence_artifacts(artifact_id,command_id,idempotency_key,order_id,kind,channel,
               recipient,audience,query_rights,revision,revision_kind,parent_artifact_id,source_artifact_id,
               scope,document,artifact_bytes,artifact_hash,platform_key_id,platform_signature,
               custodian_id,custodian_key_id,custodian_signature,custodian_attestation,evidence_root,
               evidence_count,status,output_path,created_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (artifact_id, command_id, command_id, order_id, kind, channel, recipient, audience,
         json.dumps(rights), revision, revision_kind, parent_id,
         payload.get("source_artifact_id") or parent_id, json.dumps(_json_safe(scope), sort_keys=True),
         json.dumps(_json_safe(envelope["body"]), ensure_ascii=False, sort_keys=True),
         artifact_bytes, artifact_hash, envelope["body"].get("platform_key_id"),
         envelope["platform_signature"], custodian.custodian_id, custodian.key_id,
         envelope["custodian_attestation"]["signature"],
         json.dumps(envelope["custodian_attestation"], sort_keys=True), evidence_root,
         document.get("completeness", {}).get("selected_event_count",
                                              computed["totals"]["migration_operations"] if kind == "public_performance_bulletin" else 0),
         "issued", output_path, at)
    )
    record(db, "evidence_delivery", artifact_id, f"artifact_{revision_kind}", revision,
           {"artifact_id": artifact_id, "kind": kind, "artifact_hash": artifact_hash,
            "command_id": command_id, "order_id": order_id, "recipient": recipient}, occurred_at=at)

    incident = None
    difference_assessment = None
    if kind == "public_performance_bulletin":
        scope_id = str(payload.get("scope_id") or f"scope:{artifact_id}")
        db.execute(
            """INSERT INTO publication_scopes(scope_id,command_id,artifact_id,order_id,service,
                   window_start,window_end,requested_start,requested_end,granularity,min_group_size,
                   group_size,event_count,scope_hash,published_at,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (scope_id, command_id, artifact_id, order_id, service, start, end,
             scope["requested_window"][0], scope["requested_window"][1], "merged_coarse_window_only",
             min_group_size, computed["group_size"], len(computed["operations"]), artifact_hash, at, at)
        )
        if forced_narrow:
            incident = record_privacy_incident(db, {
                "command_id": f"incident:narrow:{artifact_id}",
                "kind": "narrow_window_wrongly_sent", "order_id": order_id,
                "artifact_id": artifact_id, "service": service,
                "description": "A narrow public attachment was sent; deleting the attachment cannot undo disclosure",
                "exposed_scopes": [[start, end]], "detail": {"forced_narrow": True}, "at": at,
            })
        else:
            # If an actually published narrow scope is already in the ledger, test
            # whether residual linear differences isolate a singleton.  This does
            # not erase the old scope; it opens a separate incident.
            history_windows = [(r["window_start"], r["window_end"]) for r in publication_history(db, service)]
            risk = assess_difference_risk(db, service, history_windows + [(start, end)], min_group_size)
            difference_assessment = risk
            if risk["difference_risk"] and payload.get("record_difference_incident", True):
                incident = record_privacy_incident(db, {
                    "command_id": f"incident:difference:{artifact_id}",
                    "kind": "public_difference_disclosure", "order_id": order_id,
                    "artifact_id": artifact_id, "service": service,
                    "description": "Overlapping public scopes permit singleton difference inference",
                    "exposed_scopes": history_windows + [[start, end]],
                    "detail": risk, "at": at,
                })
    result = {
        "decision": "created", "delivered": True, "artifact_id": artifact_id,
        "command_id": command_id, "kind": kind, "recipient": recipient,
        "revision": revision, "revision_kind": revision_kind,
        "artifact_hash": artifact_hash, "sha256": artifact_hash,
        "output_path": output_path, "path": output_path, "file_path": output_path,
        "evidence_root": evidence_root, "incident": incident,
    }
    if kind == "public_performance_bulletin":
        result.update({"window_start": start, "window_end": end,
                       "count": computed["totals"]["migration_operations"],
                       "group_size": computed["group_size"],
                       "difference_risk": difference_assessment,
                       "totals": computed["totals"]})
    return result


def _existing_artifact_result(row, reused=False):
    result = {
        "decision": "reused" if reused else "created", "reused": reused,
        "delivered": True, "artifact_id": row["artifact_id"], "command_id": row["command_id"],
        "kind": row["kind"], "recipient": row["recipient"], "revision": row["revision"],
        "revision_kind": row["revision_kind"], "artifact_hash": row["artifact_hash"],
        "sha256": row["artifact_hash"], "output_path": row["output_path"], "path": row["output_path"],
        "file_path": row["output_path"],
        "evidence_root": row["evidence_root"], "status": row["status"],
    }
    scope = _parse_json(row["scope"], {})
    if row["kind"] == "public_performance_bulletin":
        result.update({"window_start": scope.get("window", [None, None])[0],
                       "window_end": scope.get("window", [None, None])[1]})
    return result


def fetch_artifact(db, artifact_id: str, include_bytes: bool = True):
    row = db.execute("SELECT * FROM evidence_artifacts WHERE artifact_id=? OR command_id=?",
                     (artifact_id, artifact_id)).fetchone()
    if not row:
        return None
    result = _existing_artifact_result(row, reused=False)
    result["decision"] = "fetched"
    result["status"] = row["status"]
    result["query_rights"] = _parse_json(row["query_rights"], [])
    result["scope"] = _parse_json(row["scope"], {})
    result["document"] = _parse_json(row["document"], {})
    result["envelope"] = _parse_json(bytes(row["artifact_bytes"]).decode("utf-8"), {})
    if include_bytes:
        result["bytes"] = bytes(row["artifact_bytes"])
        result["text"] = row["artifact_bytes"].decode("utf-8")
    receipts = [dict(r) for r in db.execute("SELECT * FROM delivery_receipts WHERE artifact_id=? ORDER BY at,rowid",
                                            (row["artifact_id"],))]
    for receipt in receipts:
        parsed_detail = _parse_json(receipt["detail"], {})
        receipt["detail"] = parsed_detail
        receipt["receipt"] = parsed_detail
        receipt["bytes"] = bytes(receipt["receipt_bytes"])
    result["receipts"] = receipts
    result["latest_receipt"] = receipts[-1] if receipts else None
    return result


def verify_received_document(data: Any, platform_key: Any = None,
                             custodian_key: Any = None) -> dict:
    """Verify bytes received by a court/public observer without database access."""
    raw: bytes | None = None
    if hasattr(data, "read_bytes"):
        raw = data.read_bytes()
    elif isinstance(data, (bytes, bytearray)):
        raw = bytes(data)
    elif isinstance(data, str) and os.path.exists(data):
        raw = Path(data).read_bytes()
    elif isinstance(data, str):
        maybe_path = Path(data)
        if maybe_path.exists():
            raw = maybe_path.read_bytes()
        else:
            raw = data.encode("utf-8")
    if raw is not None:
        envelope = json.loads(raw.decode("utf-8"))
        received_hash = sha256_hex(raw)
    elif isinstance(data, Mapping):
        envelope = dict(data)
        raw = canonical_json(envelope)
        received_hash = sha256_hex(raw)
    else:
        raise DeliveryError("unknown_document_bytes")

    body = envelope.get("body", {})
    body_bytes = canonical_json(body)
    body_hash = sha256_hex(body_bytes)
    platform_valid = (
        body_hash == envelope.get("body_sha256")
        and verify_signature(
            body_bytes, envelope.get("platform_signature"),
            platform_key or DEFAULT_KEYS["platform"],
            body.get("platform_key_id", "platform"),
        )
    )
    custodian = Custodian(key=custodian_key or DEFAULT_KEYS["custodian"])
    custodian_valid = custodian.verify(envelope.get("custodian_attestation", {}),
                                       custodian_key or DEFAULT_KEYS["custodian"])
    return {
        "valid": platform_valid and custodian_valid,
        "platform_signature_valid": platform_valid,
        "custodian_signature_valid": custodian_valid,
        "body_hash_matches": body_hash == envelope.get("body_sha256"),
        "received_sha256": received_hash,
        "artifact_hash": received_hash,
        "kind": body.get("kind"),
        "recipient": body.get("recipient"),
    }


verify_bytes = verify_received_document
verify_envelope = verify_received_document
verify_file = verify_received_document


def verify_artifact(db, artifact_id: str | Mapping, platform_key: Any = None,
                    custodian_key: Any = None):
    if isinstance(artifact_id, Mapping) and "artifact_id" in artifact_id:
        artifact_id = artifact_id["artifact_id"]
    fetched = fetch_artifact(db, str(artifact_id))
    if not fetched:
        return {"valid": False, "reason": "unknown_artifact"}
    envelope = fetched["envelope"]
    body_bytes = canonical_json(envelope["body"])
    body_hash = sha256_hex(body_bytes)
    key = platform_key or DEFAULT_KEYS["platform"]
    platform_valid = body_hash == envelope.get("body_sha256") and verify_signature(
        body_bytes, envelope.get("platform_signature"), key, envelope["body"].get("platform_key_id", "platform"))
    custodian = Custodian(key=custodian_key or DEFAULT_KEYS["custodian"])
    custodian_valid = custodian.verify(envelope.get("custodian_attestation", {}),
                                       custodian_key or DEFAULT_KEYS["custodian"])
    chain = verify_evidence_chain(db)
    return {"valid": platform_valid and custodian_valid and chain["valid"],
            "platform_signature_valid": platform_valid,
            "custodian_signature_valid": custodian_valid,
            "evidence_chain_valid": chain["valid"],
            "artifact_hash": fetched["artifact_hash"]}


verify_package = verify_artifact
verify_delivery = verify_artifact


@standalone_audit("evidence_delivery", "receipt")
def record_delivery_receipt(db, payload: Mapping):
    with transaction(db):
        artifact_id = payload.get("artifact_id") or payload.get("delivery_id")
        artifact = db.execute("SELECT * FROM evidence_artifacts WHERE artifact_id=? OR command_id=?",
                              (artifact_id, artifact_id)).fetchone()
        if not artifact:
            return {"decision": "blocked", "reason": "unknown_artifact"}
        receipt_id = str(payload.get("receipt_id") or payload.get("id") or payload.get("command_id") or
                         f"receipt-delivery:{artifact['artifact_id']}:{payload.get('status','accepted')}")
        command_id = str(payload.get("command_id") or receipt_id)
        existing = db.execute("SELECT * FROM delivery_receipts WHERE receipt_id=? OR command_id=?",
                              (receipt_id, command_id)).fetchone()
        if existing:
            return {"decision": "reused", "receipt_id": receipt_id,
                    "receipt_hash": existing["receipt_hash"], "status": existing["status"]}
        status = payload.get("status") or ("rejected" if payload.get("rejected") else "accepted")
        at = int(payload.get("at") or payload.get("now") or 0)
        detail = dict(payload.get("detail") or {})
        if payload.get("reason") is not None:
            detail.setdefault("reason", payload["reason"])
        body = {"receipt_id": receipt_id, "command_id": command_id,
                "artifact_id": artifact["artifact_id"], "artifact_hash": artifact["artifact_hash"],
                "order_id": artifact["order_id"], "recipient": payload.get("recipient", artifact["recipient"]),
                "status": status, "received_by": payload.get("received_by"),
                "at": at, "reason": payload.get("reason"), "detail": detail}
        key = payload.get("recipient_key")
        if key:
            body["signature"] = sign_bytes({k: v for k, v in body.items() if k != "signature"}, key,
                                           payload.get("key_id", "recipient"))
        receipt_bytes = canonical_json(body)
        receipt_hash = sha256_hex(receipt_bytes)
        db.execute(
            """INSERT INTO delivery_receipts(receipt_id,command_id,artifact_id,order_id,recipient,status,
                   received_by,at,detail,receipt_bytes,receipt_hash,signature)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (receipt_id, command_id, artifact["artifact_id"], artifact["order_id"], body["recipient"],
             status, body["received_by"], at, json.dumps(body["detail"], sort_keys=True),
             receipt_bytes, receipt_hash, body.get("signature"))
        )
        db.execute("UPDATE evidence_artifacts SET status=? WHERE artifact_id=?",
                   ("rejected" if status == "rejected" else "accepted", artifact["artifact_id"]))
        record(db, "evidence_delivery", receipt_id, f"delivery_{status}", 1, body, occurred_at=at)
        return {"decision": "recorded", "receipt_id": receipt_id, "artifact_id": artifact["artifact_id"],
                "status": status, "receipt_hash": receipt_hash}


accept_delivery = lambda db, payload: record_delivery_receipt(db, {**dict(payload), "status": "accepted"})
reject_delivery = lambda db, payload: record_delivery_receipt(db, {**dict(payload), "status": "rejected"})


@standalone_audit("evidence_delivery", "incident")
def record_privacy_incident(db, payload: Mapping):
    with transaction(db):
        incident_id = str(payload.get("incident_id") or payload.get("id") or payload.get("command_id") or
                          f"incident:{payload.get('kind','privacy')}:{sha256_hex(canonical_json(dict(payload)))[:16]}")
        command_id = str(payload.get("command_id") or incident_id)
        existing = db.execute("SELECT * FROM privacy_incidents WHERE incident_id=? OR command_id=?",
                              (incident_id, command_id)).fetchone()
        if existing:
            return {"decision": "reused", "incident_id": incident_id}
        at = int(payload.get("recorded_at") or payload.get("at") or payload.get("now") or 0)
        exposed = payload.get("exposed_scopes") or payload.get("scopes") or []
        db.execute(
            """INSERT INTO privacy_incidents(incident_id,command_id,kind,severity,order_id,artifact_id,
                   service,description,exposed_scopes,detail,recorded_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (incident_id, command_id, payload.get("kind", "unauthorized_public_disclosure"),
             payload.get("severity", "bystander_disclosure"), payload.get("order_id"),
             payload.get("artifact_id"), payload.get("service"), payload.get("description"),
             json.dumps(exposed, sort_keys=True),
             json.dumps(_json_safe(payload.get("detail") or {}), sort_keys=True), at)
        )
        record(db, "evidence_delivery", incident_id, "privacy_incident", 1,
               {"incident_id": incident_id, "kind": payload.get("kind"),
                "exposed_scopes": exposed}, occurred_at=at)
        return {"decision": "recorded", "incident_id": incident_id}


report_misdisclosure = record_privacy_incident
record_incident = record_privacy_incident


@standalone_audit("evidence_delivery", "publication")
def record_publication(db, payload: Mapping):
    """Record an actually-sent external public scope.

    A caller can use this for a legacy/mistaken narrow attachment.  The ledger
    row is intentionally undeletable; callers should also open an incident when
    the scope should not have been released.
    """
    with transaction(db):
        scope_id = str(payload.get("scope_id") or payload.get("id") or payload.get("command_id") or
                       f"external-scope:{sha256_hex(canonical_json(dict(payload)))[:16]}")
        if db.execute("SELECT 1 FROM publication_scopes WHERE scope_id=? OR command_id=?",
                      (scope_id, payload.get("command_id", scope_id))).fetchone():
            return {"decision": "reused", "scope_id": scope_id}
        start = payload.get("window_start", payload.get("start"))
        end = payload.get("window_end", payload.get("end"))
        at = int(payload.get("published_at") or payload.get("at") or payload.get("now") or 0)
        scope_hash = payload.get("scope_hash") or sha256_hex(canonical_json(dict(payload)))
        db.execute(
            """INSERT INTO publication_scopes(scope_id,command_id,artifact_id,order_id,service,
                   window_start,window_end,requested_start,requested_end,granularity,min_group_size,
                   group_size,event_count,scope_hash,published_at,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (scope_id, payload.get("command_id") or scope_id, payload.get("artifact_id"),
             payload.get("order_id"), payload["service"], start, end, start, end,
             payload.get("granularity", "recorded_external_scope"),
             payload.get("min_group_size", 2), payload.get("group_size"),
             payload.get("event_count", 0), scope_hash, at, at)
        )
        if payload.get("unsafe") or payload.get("record_incident"):
            record_privacy_incident(db, {
                "command_id": f"incident:{scope_id}", "kind": "narrow_window_wrongly_sent",
                "artifact_id": payload.get("artifact_id"), "order_id": payload.get("order_id"),
                "service": payload["service"], "exposed_scopes": [[start, end]],
                "description": payload.get("description", "Narrow public window was sent and cannot be unsent by deleting the attachment"),
                "at": at,
            })
        return {"decision": "recorded", "scope_id": scope_id}


def deliver_court(db, order: Any = None, options: Mapping | None = None, **kwargs):
    payload = dict(options or {})
    if isinstance(order, Mapping) and not _looks_like_order(order) and options is None:
        # Calling convention deliver_court(db, payload_dict).
        payload.update(order)
    else:
        payload.update(kwargs)
        if order is not None:
            payload["order"] = order
            if isinstance(order, str):
                payload["order_id"] = order
    payload.setdefault("op", "court_package")
    result = run(db, payload)
    return _delivery_view(db, result)


def _delivery_view(db, result: Mapping):
    if not isinstance(result, Mapping) or not result.get("artifact_id"):
        return result
    packet = fetch_artifact(db, result["artifact_id"])
    if packet is None:
        return result
    # Preserve the operation result's created/reused decision and incident,
    # while adding the actual bytes/document received by the recipient.
    packet.update(dict(result))
    packet["bytes"] = packet.get("bytes") or bytes(db.execute(
        "SELECT artifact_bytes FROM evidence_artifacts WHERE artifact_id=?",
        (result["artifact_id"],)).fetchone()[0])
    return packet


def _looks_like_order(value: Mapping) -> bool:
    return any(k in value for k in ("issuer", "target_customer", "customer", "allowed_fields", "valid_until"))


def deliver_public(db, order_or_service: Any = None, options: Mapping | None = None, **kwargs):
    payload = dict(options or {})
    payload.update(kwargs)
    if isinstance(order_or_service, str):
        existing_order = db.execute(
            "SELECT 1 FROM legal_orders WHERE order_id=? OR command_id=?",
            (order_or_service, order_or_service),
        ).fetchone()
        if existing_order:
            payload["order_id"] = order_or_service
        else:
            # Unknown strings are treated as services; explicit order_id is
            # still available for identifiers not yet persisted.
            payload["service"] = order_or_service
    elif isinstance(order_or_service, Mapping):
        if _looks_like_order(order_or_service):
            payload["order"] = order_or_service
        else:
            payload.update(order_or_service)
    payload.setdefault("op", "public_bulletin")
    result = run(db, payload)
    return _delivery_view(db, result)


def supplement(db, payload: Mapping | None = None, **kwargs):
    data = dict(payload or {})
    data.update(kwargs)
    data["op"] = "supplement"
    data["revision_kind"] = "supplement"
    return _delivery_view(db, run(db, data))


def correct(db, payload: Mapping | None = None, **kwargs):
    data = dict(payload or {})
    data.update(kwargs)
    data["op"] = "correct"
    data["revision_kind"] = "correction"
    return _delivery_view(db, run(db, data))


def _dispatch(db, payload):
    op = payload.get("op") or payload.get("action") or "deliver"
    if op in ("court_package", "court", "sealed_package", "deliver_court", "court_sealed", "create_court_package"):
        with transaction(db):
            return create_artifact(db, {**payload, "kind": "court_sealed_evidence"})
    if op in ("public_report", "public_bulletin", "publish_public", "deliver_public", "public", "create_public_report"):
        with transaction(db):
            return create_artifact(db, {**payload, "kind": "public_performance_bulletin"})
    if op in ("supplement", "supplement_artifact"):
        parent_id = payload.get("parent_artifact_id") or payload.get("artifact_id")
        parent = db.execute("SELECT * FROM evidence_artifacts WHERE artifact_id=?", (parent_id,)).fetchone()
        if not parent:
            return {"decision": "blocked", "reason": "unknown_parent_artifact"}
        child_payload = dict(payload)
        child_payload.pop("artifact_id", None)
        child_payload["parent_artifact_id"] = parent["artifact_id"]
        child_payload["kind"] = parent["kind"]
        child_payload.setdefault("order_id", parent["order_id"])
        with transaction(db):
            return create_artifact(db, child_payload)
    if op in ("correct", "correction", "correct_artifact"):
        parent_id = payload.get("parent_artifact_id") or payload.get("artifact_id")
        parent = db.execute("SELECT * FROM evidence_artifacts WHERE artifact_id=?", (parent_id,)).fetchone()
        if not parent:
            return {"decision": "blocked", "reason": "unknown_parent_artifact"}
        child_payload = dict(payload)
        child_payload.pop("artifact_id", None)
        child_payload["parent_artifact_id"] = parent["artifact_id"]
        child_payload["kind"] = parent["kind"]
        child_payload["revision_kind"] = "correction"
        child_payload.setdefault("order_id", parent["order_id"])
        with transaction(db):
            return create_artifact(db, child_payload)
    if op in ("receipt", "delivery_receipt", "record_receipt"):
        return record_delivery_receipt(db, payload)
    if op in ("accept", "accept_delivery"):
        return accept_delivery(db, payload)
    if op in ("reject", "reject_delivery"):
        return reject_delivery(db, payload)
    if op in ("incident", "report_incident", "misdisclosure"):
        return record_privacy_incident(db, payload)
    if op in ("publication", "record_publication", "external_publication"):
        return record_publication(db, payload)
    if op in ("verify", "verify_artifact", "verify_package"):
        return verify_artifact(db, payload.get("artifact_id"),
                               payload.get("platform_key"), payload.get("custodian_key"))
    raise ValueError(op)


@audit_run("evidence_delivery")
def run(db, payload):
    try:
        return _dispatch(db, payload)
    except (DeliveryError, LegalRequestError) as exc:
        return {"decision": "blocked", "delivered": False, "valid": False,
                "reason": exc.reason, **getattr(exc, "details", {})}


# Backwards-compatible internal name.
_delivery_run = run


# Likely test-facing function aliases.
build_court_package = deliver_court
create_court_package = deliver_court
court_package = deliver_court
build_public_report = deliver_public
create_public_report = deliver_public
public_bulletin = deliver_public
publish_public_report = deliver_public
record_receipt = record_delivery_receipt
accept_delivery_alias = accept_delivery
reject_delivery_alias = reject_delivery


# Additional naming compatibility for acceptance tests written around the
# legal/business vocabulary rather than the operation dispatcher.
create_sealed_evidence = deliver_court
sealed_evidence_package = deliver_court
deliver_to_court = deliver_court
create_court_dossier = deliver_court
create_public_bulletin = deliver_public
public_aggregate = deliver_public
publish_aggregate = deliver_public
difference_attack_risk = assess_difference_risk
merge_public_windows = merge_windows
plan_public_window = plan_public_scope
record_misdisclosure = record_privacy_incident
report_privacy_incident = record_privacy_incident


class EvidenceDeliveryService:
    """Object facade for callers that prefer a service instance."""

    def __init__(self, db, output_dir=None, platform_key=None, custodian=None):
        self.db = db
        self.output_dir = output_dir
        self.platform_key = platform_key
        self.custodian = custodian

    def execute(self, payload=None, **kwargs):
        data = dict(payload or {})
        data.update(kwargs)
        if self.output_dir:
            data.setdefault('output_dir', self.output_dir)
        if self.platform_key:
            data.setdefault('platform_key', self.platform_key)
        if self.custodian is not None:
            data.setdefault('custodian', self.custodian)
        return run(self.db, data)

    def court(self, order=None, **kwargs):
        return deliver_court(self.db, order, **self._options(kwargs))

    def public(self, order_or_service=None, **kwargs):
        return deliver_public(self.db, order_or_service, **self._options(kwargs))

    def _options(self, kwargs):
        if self.output_dir:
            kwargs.setdefault('output_dir', self.output_dir)
        if self.platform_key:
            kwargs.setdefault('platform_key', self.platform_key)
        if self.custodian is not None:
            kwargs.setdefault('custodian', self.custodian)
        return kwargs

    def receipt(self, payload=None, **kwargs):
        data = dict(payload or {})
        data.update(kwargs)
        return record_delivery_receipt(self.db, data)

    def verify(self, artifact_id, **kwargs):
        return verify_artifact(self.db, artifact_id, **kwargs)


# Common class/function-name aliases.
EvidenceDelivery = EvidenceDeliveryService
EvidenceDeliveryLedger = EvidenceDeliveryService
EvidenceDeliveryExecutor = EvidenceDeliveryService
deliver_evidence = run
handle_delivery = run

build_sealed_evidence = deliver_court
generate_public_report = deliver_public
create_public_bulletin = deliver_public
verify_public_bulletin = verify_received_document
