"""Customer-object custody and loss-aware rollback recovery.

This module is the write-ahead custody ledger behind the migration gate.  It
binds recovery anchors to exact old configuration bytes, node generation,
object/head versions and conversion rules; records idempotent customer
commands and their acknowledgements; fences write ownership during handoff;
and plans either causal physical replay or a forward compatibility repair.

All state lives in SQLite tables created by :func:`cloudlab.store.connect`.
The functions are deterministic for a given database and payload so evidence
replay reconstructs the same customer object set.
"""
import hashlib
import json

from . import compat
from .store import transaction

RULES_VERSION = compat.CONVERSION_RULES_VERSION


def _atomic(method):
    """Make a ledger entry point atomic when called outside migration.run."""
    def wrapper(self, *args, **kwargs):
        with transaction(self.db):
            return method(self, *args, **kwargs)
    wrapper.__name__ = getattr(method, "__name__", "wrapped")
    wrapper.__doc__ = method.__doc__
    return wrapper


class CustodyBlocked(Exception):
    """A guarded custody operation must not commit."""

    def __init__(self, reason, **extra):
        self.reason = reason
        self.extra = extra
        super().__init__(reason)

    def result(self):
        out = {"decision": "blocked", "reason": self.reason}
        out.update(self.extra)
        return out


def canonical_text(value):
    return compat.canonical_json(value)


def canonical_bytes(value):
    return compat.canonical_bytes(value)


def digest(value):
    raw = value if isinstance(value, (bytes, bytearray)) else canonical_bytes(value)
    return hashlib.sha256(bytes(raw)).hexdigest()


def coerce_bytes(value):
    """Accept raw bytes, exact text, JSON values, or evidence byte markers."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, dict) and set(value.keys()) == {"__bytes_b64__"}:
        import base64
        return base64.b64decode(value["__bytes_b64__"])
    if isinstance(value, str):
        return value.encode("utf-8")
    if value is None:
        raise CustodyBlocked("missing_config_bytes")
    return canonical_bytes(value)


def _loads(raw, default=None):
    if raw is None:
        return default
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8")
    return json.loads(raw)


def _row_dict(row):
    return dict(row) if row is not None else None


def _normalize_operation(value):
    value = (value or "").lower()
    aliases = {
        "write": "upsert",
        "customer_write": "upsert",
        "object_write": "upsert",
        "record_write": "upsert",
        "confirmed_write": "upsert",
        "save": "upsert",
        "put_object": "upsert",
        "new": "create",
        "creation": "create",
        "put": "update",
        "modify": "update",
        "modification": "update",
        "set": "update",
        "patch": "patch",
        "remove": "delete",
        "deletion": "delete",
        "del": "delete",
    }
    return aliases.get(value, value or "create")


class CustodyLedger:
    def __init__(self, db):
        self.db = db

    # ------------------------------------------------------------------
    # Generic dispatch for the optional object_custody entry point.
    # ------------------------------------------------------------------
    def dispatch(self, payload):
        op = payload.get("action") or payload.get("custody_op") or payload.get("op")
        write_ops = {
            "write", "commit_write", "customer_write", "object_write",
            "record_write", "confirmed_write", "create", "update", "patch", "delete",
        }
        if op in write_ops:
            operation = None if op in write_ops - {"create", "update", "patch", "delete"} else op
            return self.commit_write(payload, operation=operation)
        if op in {"old_write", "old_api_write", "compat_write"}:
            return self.old_write(payload)
        if op in {"read_old", "old_read", "get_old", "read"}:
            return self.read_old_payload(payload)
        if op in {"list_old", "old_list"}:
            return {"decision": "read", "objects": self.list_old(payload.get("workload", "default"))}
        if op in {"read_new", "new_read"}:
            return self.read_new_payload(payload)
        if op in {"freeze", "freeze_writes"}:
            row = self.freeze_new_writes(payload.get("workload", "default"), payload.get("at"))
            return {"decision": "frozen", "fence": row}
        if op in {"acquire", "acquire_committer", "fence", "become_committer"}:
            row = self.acquire_committer(
                payload.get("workload", "default"), payload.get("role", "new"),
                payload.get("committer_id"), payload.get("fence_token") or payload.get("token"),
                payload.get("at"), bool(payload.get("takeover", False)),
            )
            return {"decision": "committer_ready", "fence": row}
        if op in {"handoff", "handoff_write_fence"}:
            row = self.handoff_write_fence(
                payload.get("workload", "default"), payload.get("to_role", "old"),
                payload.get("to_committer"), payload.get("fence_token") or payload.get("token"),
                payload.get("at"), payload.get("anchor_id"),
            )
            return {"decision": "write_fence_handed_off", "fence": row}
        if op in {"assess", "assessment", "plan", "plan_recovery"}:
            return self.assessment_for_anchor(payload.get("anchor_id") or payload.get("id"))
        if op in {"handoff_recovery", "rollback_handoff", "stage_handoff"}:
            return self.begin_physical_handoff(payload, None, None)
        if op in {"recover", "rollback", "resume"}:
            return self.recover(payload, None, None)
        if op in {"seed", "seed_baseline", "baseline_object"}:
            return self.seed_object(payload)
        raise ValueError(f"unknown custody op: {op}")

    # ------------------------------------------------------------------
    # Verification contract and anchor binding.
    # ------------------------------------------------------------------
    def save_contract(self, migration_id, workload, old_api, new_api,
                      old_manifest, new_manifest, raw_config=None, at=None,
                      expressible_fields=None, state="verified"):
        old_bytes = coerce_bytes(old_manifest if raw_config is None else raw_config)
        old_hash = digest(old_bytes)
        contract = compat.object_contract(old_api, expressible_fields, new_api)
        rules = compat.conversion_rules(old_api, new_api, expressible_fields)
        self.db.execute(
            """INSERT INTO custody_contracts
               (migration_id,workload,old_api,new_api,old_config_bytes,old_config_hash,
                old_manifest_json,new_manifest_json,contract_json,rules_json,state,at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(migration_id) DO UPDATE SET
                 workload=excluded.workload, old_api=excluded.old_api, new_api=excluded.new_api,
                 old_config_bytes=excluded.old_config_bytes, old_config_hash=excluded.old_config_hash,
                 old_manifest_json=excluded.old_manifest_json, new_manifest_json=excluded.new_manifest_json,
                 contract_json=excluded.contract_json, rules_json=excluded.rules_json,
                 state=excluded.state, at=excluded.at""",
            (migration_id, workload, old_api, new_api, old_bytes, old_hash,
             canonical_text(old_manifest), canonical_text(new_manifest),
             canonical_text(contract), canonical_text(rules), state, at),
        )
        return {
            "migration_id": migration_id,
            "old_config_hash": old_hash,
            "field_scope": contract,
            "conversion_rules": rules,
        }

    def _contract_for_migration(self, migration):
        row = self.db.execute(
            "SELECT * FROM custody_contracts WHERE migration_id=?", (migration["id"],)
        ).fetchone()
        if row:
            return row
        # Defensive fallback for callers that created a migration row directly.
        old_api = migration["old_api"]
        new_api = migration["new_api"]
        expected = _loads(migration["expected"], {})
        self.save_contract(
            migration["id"], migration["workload"], old_api, new_api,
            expected, _loads(migration["observed"], expected), raw_config=canonical_bytes(expected),
            state=migration["state"],
        )
        return self.db.execute(
            "SELECT * FROM custody_contracts WHERE migration_id=?", (migration["id"],)
        ).fetchone()

    @_atomic
    def bind_anchor(self, payload, migration, node):
        anchor_id = payload["id"]
        existing = _row_dict(self.db.execute(
            "SELECT * FROM custody_anchors WHERE anchor_id=?", (anchor_id,)
        ).fetchone())
        if existing:
            return self._anchor_binding_or_conflict(existing, payload, migration, node)

        contract_row = self._contract_for_migration(migration)
        contract = _loads(contract_row["contract_json"])
        rules = _loads(contract_row["rules_json"])
        fence = self.ensure_fence(migration["workload"], payload.get("at"))
        object_version = int(fence["head_version"])
        requested_version = payload.get("object_version")
        if requested_version not in (None, "") and int(requested_version) != object_version:
            raise CustodyBlocked(
                "object_version_mismatch",
                expected_object_version=object_version,
                supplied_object_version=requested_version,
            )
        supplied_generation = payload.get("node_generation")
        if supplied_generation not in (None, "") and int(supplied_generation) != int(node["generation"]):
            raise CustodyBlocked(
                "anchor_generation_mismatch",
                observed_node_generation=node["generation"],
                supplied_node_generation=supplied_generation,
            )

        baseline_objects = payload.get("baseline_objects", payload.get("objects", []))
        for obj in baseline_objects:
            self._seed_baseline_object(anchor_id, migration["workload"], obj, payload.get("at"), contract)
        # An anchor must capture the real on-site set even if the runbook does
        # not repeat every object in the anchor request.  Explicit objects are
        # already present and win via INSERT OR IGNORE.
        self._snapshot_live_baseline(anchor_id, migration["workload"], payload.get("at"), contract)
        baseline_rows = self.db.execute(
            "SELECT object_uid, old_hash FROM custody_baseline_objects WHERE anchor_id=? ORDER BY object_uid",
            (anchor_id,),
        ).fetchall()
        baseline_hash = digest([{"uid": r["object_uid"], "hash": r["old_hash"]} for r in baseline_rows])

        authorization = self._authorization(payload, default_basis="rollback_anchor")
        old_config_bytes = contract_row["old_config_bytes"]
        self.db.execute(
            """INSERT INTO custody_anchors
               (anchor_id,migration_id,workload,node_id,node_version,node_generation,config_version,
                old_config_hash,old_config_bytes,object_version,baseline_hash,contract_json,rules_json,
                authorization_json,state,at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (anchor_id, migration["id"], migration["workload"], node["id"],
             payload["node_version"], int(node["generation"]), payload["config_version"],
             contract_row["old_config_hash"], old_config_bytes, object_version, baseline_hash,
             canonical_text(contract), canonical_text(rules), canonical_text(authorization),
             "ready", payload.get("at")),
        )
        row = _row_dict(self.db.execute("SELECT * FROM custody_anchors WHERE anchor_id=?", (anchor_id,)).fetchone())
        return self._anchor_dict(row, reused=False)

    def _anchor_binding_or_conflict(self, existing, payload, migration, node):
        same = (
            existing["migration_id"] == migration["id"]
            and existing["node_id"] == node["id"]
            and existing["node_version"] == payload["node_version"]
            and existing["config_version"] == payload["config_version"]
            and existing["node_generation"] == node["generation"]
        )
        if not same:
            raise CustodyBlocked("anchor_conflict", anchor_id=payload["id"])
        return self._anchor_dict(existing, reused=True)

    def _anchor_dict(self, row, reused=False):
        return {
            "anchor_id": row["anchor_id"],
            "migration_id": row["migration_id"],
            "workload": row["workload"],
            "node_id": row["node_id"],
            "node_version": row["node_version"],
            "node_generation": row["node_generation"],
            "config_version": row["config_version"],
            "old_config_hash": row["old_config_hash"],
            "object_version": row["object_version"],
            "baseline_hash": row["baseline_hash"],
            "rules_version": _loads(row["rules_json"], {}).get("version", RULES_VERSION),
            "state": row["state"],
            "reused": reused,
        }

    def _snapshot_live_baseline(self, anchor_id, workload, at=None, contract=None):
        if contract is None:
            contract = compat.object_contract()
        # The old-interface read model is the first source: its bytes are
        # already constrained to the old field contract.
        old_rows = self.db.execute(
            """SELECT object_uid,name,object_version,bytes,hash FROM custody_old_objects
               WHERE workload=? AND state='alive'""",
            (workload,),
        ).fetchall()
        for row in old_rows:
            self.db.execute(
                """INSERT OR IGNORE INTO custody_baseline_objects
                   (anchor_id,workload,object_uid,name,object_version,old_bytes,old_hash)
                   VALUES(?,?,?,?,?,?,?)""",
                (anchor_id, workload, row["object_uid"], row["name"], row["object_version"],
                 row["bytes"], row["hash"]),
            )

        # Cover objects inserted directly into the custody projection without
        # going through an old-interface write.  Project rather than copying
        # extension bytes into what must be an old-model baseline.
        live_rows = self.db.execute(
            "SELECT object_uid,name,current_version,bytes FROM custody_objects WHERE workload=? AND state='alive'",
            (workload,),
        ).fetchall()
        for row in live_rows:
            exists = self.db.execute(
                "SELECT 1 FROM custody_baseline_objects WHERE anchor_id=? AND object_uid=?",
                (anchor_id, row["object_uid"]),
            ).fetchone()
            if exists:
                continue
            obj = _loads(row["bytes"], {})
            old_view = compat.project_old(obj, contract)
            raw = canonical_bytes(old_view)
            self.db.execute(
                """INSERT INTO custody_baseline_objects
                   (anchor_id,workload,object_uid,name,object_version,old_bytes,old_hash)
                   VALUES(?,?,?,?,?,?,?)""",
                (anchor_id, workload, row["object_uid"], row["name"], row["current_version"],
                 raw, digest(raw)),
            )

    def _authorization(self, payload, default_basis):
        for key in ("approval", "authorization", "customer_approval"):
            if payload.get(key):
                value = payload[key]
                return value if isinstance(value, dict) else {"reference": value}
        approval_id = payload.get("approval_id") or payload.get("approved_by")
        if approval_id:
            return {"approval_id": approval_id}
        return {"basis": default_basis, "customer_approval_recorded": False}

    def _seed_baseline_object(self, anchor_id, workload, obj, at=None, contract=None):
        if contract is None:
            contract = compat.object_contract()
        report = compat.classify_object(obj, contract)
        if not report["object_name"]:
            raise CustodyBlocked("baseline_object_name_required")
        uid = report["object_uid"] or f"uid:{report['object_name']}"
        old_view = compat.project_old(obj, contract)
        raw = canonical_bytes(old_view)
        old_hash = digest(raw)
        self.db.execute(
            """INSERT OR REPLACE INTO custody_baseline_objects
               (anchor_id,workload,object_uid,name,object_version,old_bytes,old_hash)
               VALUES(?,?,?,?,?,?,?)""",
            (anchor_id, workload, uid, report["object_name"], 1, raw, old_hash),
        )
        self.db.execute(
            """INSERT INTO custody_objects
               (workload,object_uid,name,object_type,api_format,state,current_version,bytes,
                payload_hash,reversible,classification_json,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(workload,object_uid) DO UPDATE SET
                 name=excluded.name, api_format=excluded.api_format, state='alive',
                 current_version=MAX(custody_objects.current_version,1),
                 bytes=excluded.bytes, payload_hash=excluded.payload_hash,
                 reversible=excluded.reversible, classification_json=excluded.classification_json""",
            (workload, uid, report["object_name"], "customer-object", compat.OLD_API,
             "alive", 1, raw, old_hash, 1 if report["expressible"] else 0,
             canonical_text(report), at),
        )
        self.db.execute(
            """INSERT OR IGNORE INTO custody_object_versions
               (workload,object_uid,version,command_id,op,api_format,bytes,payload_hash,
                reversible,classification_json,at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (workload, uid, 1, f"anchor:{anchor_id}", "baseline", compat.OLD_API, raw,
             old_hash, 1 if report["expressible"] else 0, canonical_text(report), at),
        )
        self.db.execute(
            """INSERT INTO custody_old_objects
               (workload,name,object_uid,object_version,bytes,hash,state,updated_at)
               VALUES(?,?,?,?,?,?,?,?)
               ON CONFLICT(workload,name) DO UPDATE SET
                 object_uid=excluded.object_uid, object_version=excluded.object_version,
                 bytes=excluded.bytes, hash=excluded.hash, state='alive', updated_at=excluded.updated_at""",
            (workload, report["object_name"], uid, 1, raw, old_hash, "alive", at),
        )
        return {"object_uid": uid, "name": report["object_name"], "old_hash": old_hash}

    def seed_object(self, payload):
        workload = payload.get("workload", "default")
        anchor_id = payload.get("anchor_id", "unanchored")
        obj = payload.get("object") or {k: v for k, v in payload.items() if k in compat.OLD_OBJECT_FIELDS}
        with transaction(self.db):
            return {"decision": "observed", **self._seed_baseline_object(anchor_id, workload, obj, payload.get("at"))}

    # ------------------------------------------------------------------
    # Write fence and exactly-once customer command log.
    # ------------------------------------------------------------------
    def ensure_fence(self, workload="default", at=None):
        row = self.db.execute("SELECT * FROM custody_fences WHERE workload=?", (workload,)).fetchone()
        if row:
            return _row_dict(row)
        token = f"fence-{workload}-e1-new"
        self.db.execute(
            """INSERT INTO custody_fences
               (workload,epoch,state,committer_role,committer_id,token,new_ingress,head_version,
                frozen_at,handoff_at,updated_at)
               VALUES(?,1,'open','new','new-controller',?,'open',0,NULL,NULL,?)""",
            (workload, token, at),
        )
        return _row_dict(self.db.execute("SELECT * FROM custody_fences WHERE workload=?", (workload,)).fetchone())

    def acquire_committer(self, workload="default", role="new", committer_id=None,
                          token=None, at=None, takeover=False):
        with transaction(self.db):
            fence = self.ensure_fence(workload, at)
            if takeover:
                epoch = int(fence["epoch"]) + 1
                token = token or f"fence-{workload}-e{epoch}-{role}"
                self.db.execute(
                    """UPDATE custody_fences SET epoch=?, state=?, committer_role=?, committer_id=?,
                       token=?, updated_at=? WHERE workload=?""",
                    (epoch, "open" if role == "new" else f"{role}_active", role,
                     committer_id or f"{role}-committer", token, at, workload),
                )
            elif token and token != fence["token"]:
                raise CustodyBlocked("write_fence_violation", current_epoch=fence["epoch"])
            elif committer_id and committer_id != fence["committer_id"] and not takeover:
                # Explicit acquisition by another committer requires takeover so
                # callers cannot accidentally create two eligible committers.
                raise CustodyBlocked("commit_lease_held", current_committer=fence["committer_id"], epoch=fence["epoch"])
            row = _row_dict(self.db.execute("SELECT * FROM custody_fences WHERE workload=?", (workload,)).fetchone())
            return row

    def freeze_new_writes(self, workload="default", at=None, anchor_id=None):
        with transaction(self.db):
            fence = self.ensure_fence(workload, at)
            if fence["state"] != "frozen":
                self.db.execute(
                    "UPDATE custody_fences SET state='frozen', new_ingress='frozen', frozen_at=?, updated_at=? WHERE workload=?",
                    (at, at, workload),
                )
            row = _row_dict(self.db.execute("SELECT * FROM custody_fences WHERE workload=?", (workload,)).fetchone())
            return row

    def handoff_write_fence(self, workload, to_role="old", to_committer=None,
                            token=None, at=None, anchor_id=None):
        with transaction(self.db):
            fence = self.ensure_fence(workload, at)
            if fence["state"] != "frozen":
                self.db.execute(
                    "UPDATE custody_fences SET state='frozen', new_ingress='frozen', frozen_at=COALESCE(frozen_at,?), updated_at=? WHERE workload=?",
                    (at, at, workload),
                )
                fence = _row_dict(self.db.execute("SELECT * FROM custody_fences WHERE workload=?", (workload,)).fetchone())
            epoch = int(fence["epoch"]) + 1
            token = token or f"fence-{workload}-e{epoch}-{to_role}"
            committer = to_committer or f"{to_role}-controller"
            state = "old_active" if to_role == "old" else f"{to_role}_active"
            self.db.execute(
                """UPDATE custody_fences SET epoch=?,state=?,committer_role=?,committer_id=?,token=?,
                   new_ingress='closed',handoff_at=?,updated_at=? WHERE workload=?""",
                (epoch, state, to_role, committer, token, at, at, workload),
            )
            self.db.execute(
                """INSERT OR REPLACE INTO custody_handoffs
                   (workload,epoch,anchor_id,from_role,from_committer,to_role,to_committer,token,at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (workload, epoch, anchor_id, fence["committer_role"], fence["committer_id"],
                 to_role, committer, token, at),
            )
            return _row_dict(self.db.execute("SELECT * FROM custody_fences WHERE workload=?", (workload,)).fetchone())

    def _check_fence(self, payload):
        workload = payload.get("workload", "default")
        fence = self.ensure_fence(workload, payload.get("at"))
        supplied_epoch = payload.get("fence_epoch") or payload.get("epoch")
        supplied_token = payload.get("fence_token") or payload.get("token")
        supplied_committer = payload.get("committer_id") or payload.get("writer_id") or payload.get("replica_id")
        if supplied_epoch not in (None, "") and int(supplied_epoch) != int(fence["epoch"]):
            raise CustodyBlocked("stale_fence_epoch", current_epoch=fence["epoch"], supplied_epoch=int(supplied_epoch))
        if supplied_token is not None and supplied_token != fence["token"]:
            raise CustodyBlocked("write_fence_violation", current_epoch=fence["epoch"])
        if supplied_committer and supplied_committer != fence["committer_id"]:
            raise CustodyBlocked(
                "not_sole_committer", current_committer=fence["committer_id"],
                supplied_committer=supplied_committer, epoch=fence["epoch"])
        if fence["state"] == "frozen":
            raise CustodyBlocked("writes_frozen", epoch=fence["epoch"])
        return fence

    def _write_identity(self, payload, operation, obj, contract):
        workload = payload.get("workload", "default")
        name = payload.get("name")
        uid = payload.get("uid") or payload.get("object_uid")
        if obj:
            report = compat.classify_object(obj, contract)
            name = name or report["object_name"]
            uid = uid or report["object_uid"]
        if not name:
            raise CustodyBlocked("object_name_required")
        uid = uid or f"uid:{name}"
        return workload, str(name), str(uid)

    def commit_write(self, payload, operation=None):
        operation = _normalize_operation(
            operation or payload.get("operation") or payload.get("change_op")
            or payload.get("verb") or payload.get("op")
        )
        if operation not in {"create", "update", "patch", "delete", "upsert"}:
            raise CustodyBlocked("unsupported_operation", operation=operation)
        workload = payload.get("workload", "default")
        command_id = str(payload.get("command_id") or payload.get("client_command_id") or payload.get("id") or "")
        if not command_id:
            raise CustodyBlocked("command_id_required")

        existing = _row_dict(self.db.execute(
            "SELECT * FROM custody_commands WHERE workload=? AND command_id=?", (workload, command_id)
        ).fetchone())
        if existing:
            return self._retry_existing_command(payload, existing)

        client_request_id = payload.get("client_request_id") or payload.get("retry_id") or payload.get("request_id")
        if client_request_id:
            other = self.db.execute(
                "SELECT command_id,payload_hash FROM custody_commands WHERE workload=? AND client_request_id=?",
                (workload, str(client_request_id)),
            ).fetchone()
            if other and other["command_id"] != command_id:
                raise CustodyBlocked("idempotency_key_conflict", client_request_id=client_request_id)

        with transaction(self.db):
            # Re-check inside the write transaction for concurrent retries.
            existing = _row_dict(self.db.execute(
                "SELECT * FROM custody_commands WHERE workload=? AND command_id=?", (workload, command_id)
            ).fetchone())
            if existing:
                return self._retry_existing_command(payload, existing)

            fence = self._check_fence(payload)
            migration_id = payload.get("migration_id") or payload.get("migration")
            contract = self._contract_for_payload(workload, migration_id)
            api = payload.get("api") or payload.get("api_version") or compat.NEW_API
            object_type = payload.get("object_type") or payload.get("kind") or "customer-object"
            obj = payload.get("object") or payload.get("body") or payload.get("data")
            if obj is None and operation != "delete":
                reserved = {
                    "op", "action", "operation", "change_op", "verb", "workload", "command_id", "id",
                    "client_request_id", "retry_id", "request_id", "api", "api_version", "object_type",
                    "kind", "uid", "object_uid", "name", "at", "ack_id", "notifications", "notification_id",
                    "fence_epoch", "epoch", "fence_token", "token", "migration_id", "migration", "source",
                    "submitted_object", "translation",
                }
                obj = {k: v for k, v in payload.items() if k not in reserved}
            if operation == "patch" and obj:
                current = self._current_object(workload, payload.get("uid") or payload.get("object_uid") or f"uid:{payload.get('name')}")
                if not current:
                    raise CustodyBlocked("object_not_found_for_patch")
                obj = _deep_merge(_loads(current["bytes"], {}), obj)
                operation = "update"

            name = payload.get("name") or (obj or {}).get("name")
            uid = payload.get("uid") or payload.get("object_uid") or ((obj or {}).get("uid"))
            if isinstance((obj or {}).get("metadata"), dict):
                name = name or obj["metadata"].get("name")
                uid = uid or obj["metadata"].get("uid")
            if not name and operation != "delete":
                raise CustodyBlocked("object_name_required")
            name = str(name or payload.get("name") or "")
            uid = str(uid or (f"uid:{name}" if name else payload.get("uid") or payload.get("object_uid") or ""))
            if not name:
                raise CustodyBlocked("object_name_required")

            current = self._current_object(workload, uid)
            if current is None and uid == f"uid:{name}":
                by_name = self.db.execute(
                    "SELECT * FROM custody_objects WHERE workload=? AND name=? AND state='alive'",
                    (workload, name),
                ).fetchone()
                current = _row_dict(by_name)
                if current:
                    uid = current["object_uid"]

            if operation == "upsert":
                operation = "update" if current and current["state"] == "alive" else "create"

            at = payload.get("at")
            next_seq = int(self.db.execute(
                "SELECT COALESCE(MAX(seq),0)+1 FROM custody_commands WHERE workload=?", (workload,)
            ).fetchone()[0])

            stored_obj = _loads(canonical_text(obj)) if isinstance(obj, (dict, list)) else obj
            requested_object = _loads(canonical_text(obj)) if isinstance(obj, (dict, list)) else obj
            submitted_object = payload.get("submitted_object", requested_object)
            translation = payload.get("translation")
            if operation == "create":
                if current and current["state"] == "alive":
                    raise CustodyBlocked("object_already_exists", object_uid=uid, name=name)
                if current and current["state"] == "deleted" and payload.get("uid"):
                    raise CustodyBlocked("object_identifier_retired", object_uid=uid, name=name)
                object_version = 1 if not current else int(current["current_version"]) + 1
            elif operation == "update":
                if not current or current["state"] != "alive":
                    raise CustodyBlocked("object_not_found", object_uid=uid, name=name)
                object_version = int(current["current_version"]) + 1
                if not uid:
                    uid = current["object_uid"]
            else:  # delete
                if not current or current["state"] != "alive":
                    raise CustodyBlocked("object_not_found", object_uid=uid, name=name)
                object_version = int(current["current_version"]) + 1
                stored_obj = _loads(current["bytes"])
                obj = None

            if operation in {"create", "update"}:
                if not isinstance(stored_obj, dict):
                    raise CustodyBlocked("object_must_be_mapping")
                # Ensure stable identity is present in the stored object.
                stored_obj.setdefault("uid", uid)
                if "name" not in stored_obj and not isinstance(stored_obj.get("metadata"), dict):
                    stored_obj["name"] = name
                report = compat.classify_object(stored_obj, contract)
                raw = canonical_bytes(stored_obj)
                reversible = 1 if report["expressible"] else 0
                classification = report
            else:
                report = compat.classify_object(stored_obj or {}, contract)
                raw = canonical_bytes(stored_obj or {})
                reversible = current["reversible"] if current else 1
                classification = report

            payload_envelope = {
                "operation": operation,
                "api": api,
                "object": _loads(raw),
                "submitted_object": submitted_object,
                "translation": translation,
                "name": name,
                "uid": uid,
                "notifications": payload.get("notifications"),
                "notification_id": payload.get("notification_id"),
            }
            payload_text = canonical_text(payload_envelope)
            payload_hash = digest(payload_text)
            client_request_id = str(client_request_id) if client_request_id else None
            self.db.execute(
                """INSERT INTO custody_commands
                   (workload,command_id,client_request_id,seq,op,api,source,object_type,object_uid,
                    object_name,payload_json,payload_hash,fence_epoch,fence_token_hash,at,status)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'committed')""",
                (workload, command_id, client_request_id, next_seq, operation, api,
                 payload.get("source", "customer"), object_type, uid, name, payload_text,
                 payload_hash, int(fence["epoch"]), digest(fence["token"]), at),
            )
            self.db.execute("UPDATE custody_fences SET head_version=? WHERE workload=?", (next_seq, workload))

            if operation == "delete":
                self.db.execute(
                    """UPDATE custody_objects SET state='deleted',current_version=?,bytes=?,payload_hash=?,
                       updated_at=? WHERE workload=? AND object_uid=?""",
                    (object_version, raw, payload_hash, at, workload, uid),
                )
                self.db.execute(
                    "UPDATE custody_old_objects SET state='deleted',updated_at=? WHERE workload=? AND name=?",
                    (at, workload, name),
                )
            else:
                self.db.execute(
                    """INSERT INTO custody_objects
                       (workload,object_uid,name,object_type,api_format,state,current_version,bytes,
                        payload_hash,reversible,classification_json,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(workload,object_uid) DO UPDATE SET
                         name=excluded.name,object_type=excluded.object_type,api_format=excluded.api_format,
                         state='alive',current_version=excluded.current_version,bytes=excluded.bytes,
                         payload_hash=excluded.payload_hash,reversible=excluded.reversible,
                         classification_json=excluded.classification_json,updated_at=excluded.updated_at""",
                    (workload, uid, name, object_type, api, "alive", object_version, raw, payload_hash,
                     reversible, canonical_text(classification), at),
                )
                old_view = classification.get("old_view") or compat.project_old(stored_obj, contract)
                old_raw = canonical_bytes(old_view)
                self.db.execute(
                    """INSERT INTO custody_old_objects
                       (workload,name,object_uid,object_version,bytes,hash,state,updated_at)
                       VALUES(?,?,?,?,?,?,?,?)
                       ON CONFLICT(workload,name) DO UPDATE SET
                         object_uid=excluded.object_uid,object_version=excluded.object_version,
                         bytes=excluded.bytes,hash=excluded.hash,state='alive',updated_at=excluded.updated_at""",
                    (workload, name, uid, object_version, old_raw, digest(old_raw), "alive", at),
                )

            self.db.execute(
                """INSERT OR IGNORE INTO custody_object_versions
                   (workload,object_uid,version,command_id,op,api_format,bytes,payload_hash,
                    reversible,classification_json,at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (workload, uid, object_version, command_id, operation, api, raw, payload_hash,
                 reversible, canonical_text(classification), at),
            )

            ack_id = str(payload.get("ack_id") or f"ack:{workload}:{command_id}")
            notification_ids = self._record_notifications(payload, workload, command_id, uid, at)
            ack = {
                "ack_id": ack_id,
                "decision": "confirmed",
                "workload": workload,
                "command_id": command_id,
                "seq": next_seq,
                "op": operation,
                "object_uid": uid,
                "name": name,
                "object_version": object_version,
                "payload_hash": payload_hash,
                "notification_ids": notification_ids,
                "at": at,
            }
            self.db.execute(
                """INSERT INTO custody_acks
                   (ack_id,workload,command_id,seq,object_uid,object_version,decision,receipt_json,
                    notification_ids_json,at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (ack_id, workload, command_id, next_seq, uid, object_version, "confirmed",
                 canonical_text(ack), canonical_text(notification_ids), at),
            )
            return {
                "decision": "confirmed",
                "committed": True,
                "reused": False,
                **ack,
                "fence_epoch": int(fence["epoch"]),
                "write_fence": {
                    "epoch": int(fence["epoch"]),
                    "committer_role": fence["committer_role"],
                    "committer_id": fence["committer_id"],
                    "token": fence["token"],
                },
                "reversible": bool(reversible),
                "untranslatable_fields": classification.get("untranslatable_fields", []),
            }

    def _contract_for_payload(self, workload, migration_id=None):
        if migration_id:
            row = self.db.execute("SELECT contract_json FROM custody_contracts WHERE migration_id=?", (migration_id,)).fetchone()
            if row:
                return _loads(row["contract_json"])
        row = self.db.execute(
            "SELECT contract_json FROM custody_contracts WHERE workload=? ORDER BY rowid DESC LIMIT 1",
            (workload,),
        ).fetchone()
        return _loads(row["contract_json"]) if row else compat.object_contract()

    def _current_object(self, workload, uid):
        if not uid:
            return None
        return _row_dict(self.db.execute(
            "SELECT * FROM custody_objects WHERE workload=? AND object_uid=?", (workload, uid)
        ).fetchone())

    def _retry_existing_command(self, payload, command):
        request_hash = digest(canonical_text(self._idempotency_fingerprint(payload)))
        # The stored hash covers a fuller envelope; compare command id and, when
        # possible, the canonical object supplied by the retry.  A differing
        # business object under the same key is still rejected.
        envelope = _loads(command["payload_json"], {})
        retry_obj = payload.get("object") or payload.get("body") or payload.get("data")
        stored_request = envelope.get("submitted_object")
        if stored_request is None:
            stored_request = envelope.get("object")
        if retry_obj is not None and canonical_text(retry_obj) != canonical_text(stored_request):
            raise CustodyBlocked("idempotency_key_conflict", command_id=command["command_id"])
        ack_row = self.db.execute(
            "SELECT receipt_json FROM custody_acks WHERE workload=? AND command_id=?",
            (command["workload"], command["command_id"]),
        ).fetchone()
        ack = _loads(ack_row["receipt_json"], {}) if ack_row else {}
        ack["reused"] = True
        ack["decision"] = ack.get("decision", "confirmed")
        ack["committed"] = True
        ack["idempotent_retry"] = True
        return ack

    def _idempotency_fingerprint(self, payload):
        keys = ("operation", "op", "change_op", "verb", "object", "body", "data", "name", "uid",
                "object_uid", "api", "api_version", "client_request_id")
        return {k: payload.get(k) for k in keys if k in payload}

    def _record_notifications(self, payload, workload, command_id, uid, at):
        items = []
        if payload.get("notification_id"):
            items.append(payload["notification_id"])
        for item in payload.get("notifications", []) or []:
            items.append(item if isinstance(item, str) else item.get("notification_id") or item.get("id"))
        ids = []
        for index, item in enumerate(items):
            if not item:
                continue
            if isinstance(item, str):
                notification_id = item
                body = {"notification_id": notification_id}
                kind = "customer_confirmation"
                destination = None
                corrects = None
            else:
                notification_id = item.get("notification_id") or item.get("id") or f"notif:{command_id}:{index}"
                body = item
                kind = item.get("kind", "customer_confirmation")
                destination = item.get("destination")
                corrects = item.get("corrects_notification_id") or item.get("corrects")
            self.db.execute(
                """INSERT OR IGNORE INTO custody_notifications
                   (notification_id,workload,command_id,object_uid,kind,destination,payload_json,
                    state,sent_at,corrects_notification_id,correction_id)
                   VALUES(?,?,?,?,?,?,?, 'sent', ?,?,?)""",
                (notification_id, workload, command_id, uid, kind, destination,
                 canonical_text(body), at, corrects, body.get("correction_id")),
            )
            ids.append(notification_id)
        return ids

    # ------------------------------------------------------------------
    # Old interface reads and compatibility-preserving writes.
    # ------------------------------------------------------------------
    def list_old(self, workload="default"):
        rows = self.db.execute(
            "SELECT bytes FROM custody_old_objects WHERE workload=? AND state='alive' ORDER BY name",
            (workload,),
        ).fetchall()
        return [_loads(row["bytes"]) for row in rows]

    def read_old(self, workload, name=None, uid=None):
        if name is None and uid is not None:
            row = self.db.execute(
                "SELECT bytes FROM custody_old_objects WHERE workload=? AND object_uid=? AND state='alive'",
                (workload, uid),
            ).fetchone()
        else:
            row = self.db.execute(
                "SELECT bytes FROM custody_old_objects WHERE workload=? AND name=? AND state='alive'",
                (workload, name),
            ).fetchone()
        return _loads(row["bytes"]) if row else None

    def read_old_payload(self, payload):
        workload = payload.get("workload", "default")
        value = self.read_old(workload, payload.get("name"), payload.get("uid") or payload.get("object_uid"))
        return {"decision": "read", "object": value, "found": value is not None}

    def read_new(self, workload, name=None, uid=None):
        if uid:
            row = self._current_object(workload, uid)
        else:
            row = _row_dict(self.db.execute(
                "SELECT * FROM custody_objects WHERE workload=? AND name=? AND state='alive'",
                (workload, name),
            ).fetchone())
        if not row:
            return None
        value = _loads(row["bytes"])
        return {
            "object": value,
            "object_uid": row["object_uid"],
            "version": row["current_version"],
            "hash": row["payload_hash"],
            "reversible": bool(row["reversible"]),
        }

    def read_new_payload(self, payload):
        result = self.read_new(payload.get("workload", "default"), payload.get("name"),
                               payload.get("uid") or payload.get("object_uid"))
        return {"decision": "read", **(result or {"object": None, "found": False})}

    def old_write(self, payload):
        workload = payload.get("workload", "default")
        old_body = payload.get("object") or payload.get("body") or {
            k: payload[k] for k in compat.OLD_OBJECT_FIELDS if k in payload
        }
        contract = self._contract_for_payload(workload, payload.get("migration_id") or payload.get("migration"))
        strict = compat.classify_object(old_body, contract)
        extra_keys = set(old_body) - set(compat.OLD_OBJECT_FIELDS) - {"uid", "id"}
        if extra_keys or strict.get("violations"):
            raise CustodyBlocked(
                "field_not_in_old_contract",
                untranslatable_fields=sorted(extra_keys) or strict.get("untranslatable_fields", []),
            )
        name = payload.get("name") or old_body.get("name")
        if not name:
            raise CustodyBlocked("object_name_required")

        with transaction(self.db):
            fence = self._check_fence(payload)
            current_row = self.db.execute(
                "SELECT * FROM custody_objects WHERE workload=? AND name=? AND state='alive'",
                (workload, name),
            ).fetchone()
            current = _row_dict(current_row)
            current_obj = _loads(current["bytes"], {}) if current else {}
            repair = self.db.execute(
                "SELECT * FROM custody_compat_repairs WHERE workload=? AND state='active' ORDER BY rowid DESC LIMIT 1",
                (workload,),
            ).fetchone()
            if repair or fence["committer_role"] == "compat":
                stored_obj = _apply_old_fields(current_obj, old_body, contract)
                translation = {
                    "mode": "compatibility_facade_preserve_unknown_fields",
                    "preserved_fields": sorted(set(_leaf_top_keys(current_obj)) - set(compat.OLD_OBJECT_FIELDS)),
                }
                source = "old-api-compat-facade"
            else:
                # Physical old controller: there must be no extension to preserve.
                stored_obj = dict(old_body)
                translation = {"mode": "physical_old_model"}
                source = "old-api"
            write_payload = dict(payload)
            write_payload.update({
                "workload": workload,
                "operation": payload.get("operation") or ("update" if current else "create"),
                "object": stored_obj,
                "submitted_object": old_body,
                "translation": translation,
                "api": compat.OLD_API,
                "source": source,
                "name": name,
                "uid": current["object_uid"] if current else payload.get("uid"),
                "fence_token": fence["token"] if not payload.get("fence_token") else payload.get("fence_token"),
                "fence_epoch": fence["epoch"],
            })
            return self.commit_write(write_payload)

    # ------------------------------------------------------------------
    # Assessment and recovery.
    # ------------------------------------------------------------------
    def assessment_for_anchor(self, anchor_id):
        row = self.db.execute("SELECT * FROM custody_anchors WHERE anchor_id=?", (anchor_id,)).fetchone()
        if not row:
            raise CustodyBlocked("unknown_anchor", anchor_id=anchor_id)
        anchor = _row_dict(row)
        contract = _loads(anchor["contract_json"], compat.object_contract())
        commands = [_row_dict(r) for r in self.db.execute(
            "SELECT * FROM custody_commands WHERE workload=? AND seq>? ORDER BY seq",
            (anchor["workload"], anchor["object_version"]),
        ).fetchall()]

        steps = []
        blockers = []
        receipt_ids = []
        notification_ids = []
        for command in commands:
            envelope = _loads(command["payload_json"], {})
            ack_row = self.db.execute(
                "SELECT receipt_json FROM custody_acks WHERE workload=? AND command_id=?",
                (command["workload"], command["command_id"]),
            ).fetchone()
            ack = _loads(ack_row["receipt_json"]) if ack_row else None
            receipt_ok = bool(ack and ack.get("payload_hash") == command["payload_hash"])
            if not receipt_ok:
                blockers.append({
                    "type": "missing_or_mismatched_customer_receipt",
                    "command_id": command["command_id"], "seq": command["seq"],
                })
            if ack:
                receipt_ids.append(ack["ack_id"])
                notification_ids.extend(ack.get("notification_ids", []))
            obj = envelope.get("object")
            step = {
                "seq": command["seq"],
                "command_id": command["command_id"],
                "op": command["op"],
                "api": command["api"],
                "object_uid": command["object_uid"],
                "name": command["object_name"],
                "receipt_ok": receipt_ok,
                "ack_id": ack.get("ack_id") if ack else None,
            }
            if command["op"] in {"create", "update"} and isinstance(obj, dict):
                report = compat.classify_object(obj, contract)
                step["reversible"] = report["expressible"]
                step["old_object"] = report["old_view"]
                step["untranslatable_fields"] = report["untranslatable_fields"]
                if not report["expressible"]:
                    blockers.append({
                        "type": "irreversible_confirmed_command",
                        "seq": command["seq"], "command_id": command["command_id"],
                        "object_uid": command["object_uid"], "name": command["object_name"],
                        "fields": report["untranslatable_fields"],
                        "violations": report["violations"],
                    })
            else:
                step["reversible"] = True
                step["old_object"] = None
            steps.append(step)

        live_rows = [_row_dict(r) for r in self.db.execute(
            "SELECT * FROM custody_objects WHERE workload=? AND state='alive' ORDER BY name",
            (anchor["workload"],),
        ).fetchall()]
        live_objects = []
        for obj_row in live_rows:
            obj = _loads(obj_row["bytes"])
            report = _loads(obj_row["classification_json"]) or compat.classify_object(obj, contract)
            item = {
                "object_uid": obj_row["object_uid"],
                "name": obj_row["name"],
                "version": obj_row["current_version"],
                "hash": obj_row["payload_hash"],
                "reversible": bool(obj_row["reversible"]),
                "old_view": report.get("old_view", compat.project_old(obj, contract)),
                "untranslatable_fields": report.get("untranslatable_fields", []),
            }
            live_objects.append(item)
            if not report.get("expressible", bool(obj_row["reversible"])):
                blockers.append({
                    "type": "irreversible_live_object",
                    "object_uid": obj_row["object_uid"], "name": obj_row["name"],
                    "version": obj_row["current_version"],
                    "fields": report.get("untranslatable_fields", []),
                })

        lossless = not blockers
        plan = {
            "path": "physical_rollback" if lossless else "forward_compat",
            "steps": steps,
            "baseline_hash": anchor["baseline_hash"],
            "checkpoint_seq": anchor["object_version"],
            "receipts_checked": len(receipt_ids),
        }
        return {
            "anchor": self._anchor_dict(anchor),
            "lossless": lossless,
            "reversible": lossless,
            "blockers": blockers,
            "steps": steps,
            "receipt_ids": receipt_ids,
            "notification_ids": sorted(set(notification_ids)),
            "live_objects": live_objects,
            "physical_plan": plan if lossless else None,
            "forward_plan": None if lossless else self._forward_plan(anchor, blockers, live_objects),
        }

    def _forward_plan(self, anchor, blockers, live_objects):
        fields = sorted({f for b in blockers for f in b.get("fields", []) if f})
        return {
            "strategy": "retain_new_bytes_and_publish_old_api_facade",
            "old_api": _loads(anchor["contract_json"], {}).get("old_api", compat.OLD_API),
            "new_api": _loads(anchor["contract_json"], {}).get("new_api", compat.NEW_API),
            "untranslatable_fields": fields,
            "preserve_objects": [o["object_uid"] for o in live_objects],
            "old_clients_see": "only contract fields; extensions remain persisted and enforced by new controller",
            "physical_rollback_claim": False,
            "corrections_required": True,
        }

    def get_recovery(self, anchor_id):
        row = self.db.execute("SELECT * FROM custody_recoveries WHERE anchor_id=?", (anchor_id,)).fetchone()
        return _row_dict(row)

    @_atomic
    def recover(self, payload, rollback_row=None, migration_row=None):
        anchor_id = payload.get("id") or payload.get("anchor_id")
        existing = self.get_recovery(anchor_id)
        if existing and existing["state"] == "physical_completed":
            result = _loads(existing["result_json"], {})
            result["reused"] = True
            result["idempotent_retry"] = True
            return result
        if existing and existing["state"] == "forward_compat_active":
            result = _loads(existing["result_json"], {})
            result["reused"] = True
            result["idempotent_retry"] = True
            return result

        requested = _path_choice(payload.get("recovery_path") or payload.get("path") or payload.get("strategy"))
        assessment = self.assessment_for_anchor(anchor_id)

        if requested == "forward_compat":
            return self.apply_forward(payload, assessment)
        if requested == "physical_rollback":
            if not assessment["lossless"]:
                return self.forward_fix_required(payload, assessment)
            return self.apply_physical(payload, assessment)

        # Safe default: never issue rolled_back unless real confirmed objects
        # and receipts prove lossless causal restoration.
        if assessment["lossless"]:
            return self.apply_physical(payload, assessment)
        return self.forward_fix_required(payload, assessment)

    @_atomic
    def begin_physical_handoff(self, payload, rollback_row=None, migration_row=None):
        anchor_id = payload.get("id") or payload.get("anchor_id")
        existing = self.get_recovery(anchor_id)
        if existing and existing["state"] == "physical_completed":
            result = _loads(existing["result_json"], {})
            result["reused"] = True
            return result
        if existing and existing["state"] in {"handoff_committed", "replaying"}:
            # A committed handoff boundary is itself retryable evidence.  Do
            # not rotate the epoch/token on response loss or operator retry.
            stored = _loads(existing["result_json"], {})
            fence = _row_dict(self.db.execute(
                "SELECT * FROM custody_fences WHERE workload=?", (existing["workload"],)
            ).fetchone())
            if fence:
                stored.setdefault("decision", "handoff_ready")
                stored.setdefault("anchor_id", anchor_id)
                stored.setdefault("next_op", "rollback")
                stored.setdefault("next_request", {"op": "rollback", "id": anchor_id, "stage": "resume"})
                stored.setdefault("lossless", True)
                stored["write_fence"] = {
                    "epoch": fence["epoch"], "committer_role": fence["committer_role"],
                    "token": fence["token"],
                }
                stored["reused"] = True
                stored["idempotent_retry"] = True
                return stored

        assessment = self.assessment_for_anchor(anchor_id)
        if not assessment["lossless"]:
            return self.forward_fix_required(payload, assessment, stage="handoff")

        anchor = _row_dict(self.db.execute("SELECT * FROM custody_anchors WHERE anchor_id=?", (anchor_id,)).fetchone())
        approval = self._authorization(payload, "physical_rollback")
        self._upsert_recovery(
            anchor, "physical_rollback", "physical_rollback", "handoff_committed",
            assessment, payload, approval, checkpoint=anchor["object_version"],
            decision="handoff_ready", result={},
        )
        fence = self.handoff_write_fence(
            anchor["workload"], "old", payload.get("old_committer_id", "old-controller"),
            payload.get("old_fence_token"), payload.get("at"), anchor_id,
        )
        self.db.execute(
            """INSERT OR REPLACE INTO custody_recovery_items
               (anchor_id,seq,command_id,stage,state,attempts,detail_json,updated_at)
               VALUES(?,?, '', 'write_handoff','committed',1,?,?)""",
            (anchor_id, fence["epoch"], canonical_text({"epoch": fence["epoch"], "role": "old"}), payload.get("at")),
        )
        handoff_result = {
            "decision": "handoff_ready",
            "anchor_id": anchor_id,
            "next_op": "rollback",
            "next_request": {"op": "rollback", "id": anchor_id, "stage": "resume"},
            "write_fence": {"epoch": fence["epoch"], "committer_role": "old", "token": fence["token"]},
            "lossless": True,
            "reused": False,
        }
        self._upsert_recovery(
            anchor, "physical_rollback", "physical_rollback", "handoff_committed",
            assessment, payload, approval, checkpoint=anchor["object_version"],
            decision="handoff_ready", result=handoff_result,
        )
        return handoff_result

    @_atomic
    def apply_physical(self, payload, assessment=None):
        anchor_id = payload.get("id") or payload.get("anchor_id")
        if assessment is None:
            assessment = self.assessment_for_anchor(anchor_id)
        if not assessment["lossless"]:
            return self.forward_fix_required(payload, assessment)
        anchor = _row_dict(self.db.execute("SELECT * FROM custody_anchors WHERE anchor_id=?", (anchor_id,)).fetchone())
        approval = self._authorization(payload, "physical_rollback")

        existing = self.get_recovery(anchor_id)
        if not existing or existing["state"] not in {"handoff_committed", "replaying", "physical_completed"}:
            self._upsert_recovery(
                anchor, "auto", "physical_rollback", "replaying", assessment, payload, approval,
                checkpoint=anchor["object_version"], decision="rolled_back", result={},
            )
            fence = self.handoff_write_fence(
                anchor["workload"], "old", payload.get("old_committer_id", "old-controller"),
                payload.get("old_fence_token"), payload.get("at"), anchor_id,
            )
        else:
            fence = _row_dict(self.db.execute(
                "SELECT * FROM custody_fences WHERE workload=?", (anchor["workload"],)
            ).fetchone())

        # Rebuild the old-controller store from the exact anchor baseline and
        # the immutable confirmed command log.  Set reconciliation makes retry
        # idempotent; no customer command effect is inserted twice.
        self.db.execute("DELETE FROM custody_old_objects WHERE workload=?", (anchor["workload"],))
        baselines = self.db.execute(
            "SELECT * FROM custody_baseline_objects WHERE anchor_id=? ORDER BY object_uid", (anchor_id,)
        ).fetchall()
        for base in baselines:
            self.db.execute(
                """INSERT INTO custody_old_objects
                   (workload,name,object_uid,object_version,bytes,hash,state,updated_at)
                   VALUES(?,?,?,?,?,?,'alive',?)""",
                (base["workload"], base["name"], base["object_uid"], base["object_version"],
                 base["old_bytes"], base["old_hash"], payload.get("at")),
            )

        replayed = []
        max_seq = anchor["object_version"]
        for step in assessment["steps"]:
            if not step["reversible"] or not step["receipt_ok"]:
                raise CustodyBlocked("physical_replay_guard_failed", step=step)
            command = _row_dict(self.db.execute(
                "SELECT * FROM custody_commands WHERE workload=? AND command_id=?",
                (anchor["workload"], step["command_id"]),
            ).fetchone())
            envelope = _loads(command["payload_json"], {})
            if command["op"] in {"create", "update"}:
                old_obj = compat.to_old_object(envelope["object"], _loads(anchor["contract_json"]))
                raw = canonical_bytes(old_obj)
                ack = self.db.execute(
                    "SELECT object_version FROM custody_acks WHERE workload=? AND command_id=?",
                    (anchor["workload"], command["command_id"]),
                ).fetchone()
                version = ack["object_version"] if ack else 1
                self.db.execute(
                    """INSERT INTO custody_old_objects
                       (workload,name,object_uid,object_version,bytes,hash,state,updated_at)
                       VALUES(?,?,?,?,?,?, 'alive',?)
                       ON CONFLICT(workload,name) DO UPDATE SET
                         object_uid=excluded.object_uid,object_version=excluded.object_version,
                         bytes=excluded.bytes,hash=excluded.hash,state='alive',updated_at=excluded.updated_at""",
                    (anchor["workload"], step["name"], step["object_uid"], version, raw, digest(raw), payload.get("at")),
                )
            elif command["op"] == "delete":
                self.db.execute(
                    "DELETE FROM custody_old_objects WHERE workload=? AND name=?",
                    (anchor["workload"], step["name"]),
                )
            max_seq = max(max_seq, step["seq"])
            replayed.append({"seq": step["seq"], "command_id": step["command_id"], "op": step["op"]})
            self.db.execute(
                """INSERT INTO custody_recovery_items
                   (anchor_id,seq,command_id,stage,state,attempts,detail_json,updated_at)
                   VALUES(?,?,?, 'old_model_replay','applied',1,?,?)
                   ON CONFLICT(anchor_id,seq,stage) DO UPDATE SET
                     state='applied',attempts=attempts+1,detail_json=excluded.detail_json,updated_at=excluded.updated_at""",
                (anchor_id, step["seq"], step["command_id"], canonical_text(step), payload.get("at")),
            )

        old_objects = self.list_old(anchor["workload"])
        result = {
            "decision": "rolled_back",
            "receipt": "rolled_back",
            "recovery_path": "physical_rollback",
            "physical_rollback": True,
            "rolled_back": True,
            "not_rolled_back": False,
            "anchor_id": anchor_id,
            "migration_id": anchor["migration_id"],
            "workload": anchor["workload"],
            "node_id": anchor["node_id"],
            "node_version": anchor["node_version"],
            "node_generation": anchor["node_generation"],
            "config_version": anchor["config_version"],
            "storage_format": compat.OLD_API,
            "actual_controller_version": anchor["node_version"],
            "old_api": _loads(anchor["contract_json"], {}).get("old_api", compat.OLD_API),
            "old_api_readable": True,
            "old_api_writable": True,
            "replayed_commands": replayed,
            "receipts_checked": assessment["receipt_ids"],
            "receipt_count": len(assessment["receipt_ids"]),
            "notification_ids": assessment["notification_ids"],
            "object_set": old_objects,
            "object_count": len(old_objects),
            "checkpoint_seq": max_seq,
            "write_fence": {"epoch": fence["epoch"], "committer_role": fence["committer_role"], "token": fence["token"]},
            "correction_ids": [],
        }
        self._upsert_recovery(
            anchor, payload.get("recovery_path", "auto"), "physical_rollback", "physical_completed",
            assessment, payload, approval, checkpoint=max_seq, decision="rolled_back", result=result,
            completed=True,
        )
        self.db.execute("UPDATE custody_anchors SET state='physically_restored' WHERE anchor_id=?", (anchor_id,))
        return result

    @_atomic
    def apply_forward(self, payload, assessment=None):
        anchor_id = payload.get("id") or payload.get("anchor_id")
        if assessment is None:
            assessment = self.assessment_for_anchor(anchor_id)
        anchor = _row_dict(self.db.execute("SELECT * FROM custody_anchors WHERE anchor_id=?", (anchor_id,)).fetchone())
        approval = self._authorization(payload, "forward_compat")
        existing_repair = _row_dict(self.db.execute(
            "SELECT * FROM custody_compat_repairs WHERE anchor_id=?", (anchor_id,)
        ).fetchone())

        if existing_repair and existing_repair["state"] == "active":
            result = _loads(self.get_recovery(anchor_id)["result_json"], {}) if self.get_recovery(anchor_id) else {}
            result["reused"] = True
            return result

        self._upsert_recovery(
            anchor, "forward_compat", "forward_compat", "publishing_compat", assessment, payload,
            approval, checkpoint=max([anchor["object_version"]] + [s["seq"] for s in assessment["steps"]]),
            decision="forward_fix_applied", result={},
        )
        if existing_repair:
            fence = _row_dict(self.db.execute(
                "SELECT * FROM custody_fences WHERE workload=?", (anchor["workload"],)
            ).fetchone())
        else:
            fence = self.handoff_write_fence(
                anchor["workload"], "compat", payload.get("compat_committer_id", "compat-facade"),
                payload.get("compat_fence_token"), payload.get("at"), anchor_id,
            )

        contract = _loads(anchor["contract_json"])
        correction_ids = []
        for item in assessment["live_objects"]:
            if not item["untranslatable_fields"]:
                continue
            for field_path in item["untranslatable_fields"]:
                correction_id = payload.get("correction_id") if len(item["untranslatable_fields"]) == 1 else None
                correction_id = correction_id or f"correction:{anchor_id}:{item['object_uid']}:{digest(field_path)[:12]}"
                detail = {
                    "object_uid": item["object_uid"],
                    "name": item["name"],
                    "object_version": item["version"],
                    "persisted_hash": item["hash"],
                    "field_path": field_path,
                    "old_client_visible": False,
                    "new_bytes_retained": True,
                    "facade_policy": "project contract fields; preserve extension on old-client writes",
                }
                self.db.execute(
                    """INSERT OR IGNORE INTO custody_corrections
                       (correction_id,anchor_id,migration_id,workload,object_uid,field_path,kind,summary,
                        detail_json,notification_id,at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (correction_id, anchor_id, anchor["migration_id"], anchor["workload"],
                     item["object_uid"], field_path, "old_api_compatibility_view",
                     f"Field {field_path} is retained in new storage but not physically expressible by old/v1",
                     canonical_text(detail), payload.get("correction_notification_id"), payload.get("at")),
                )
                correction_ids.append(correction_id)

        # Optional customer correction notice: never recalls the original ACK/notification.
        if payload.get("correction_notification_id") or payload.get("notify_customers"):
            notif_id = payload.get("correction_notification_id") or f"correction-notif:{anchor_id}"
            self.db.execute(
                """INSERT OR IGNORE INTO custody_notifications
                   (notification_id,workload,command_id,object_uid,kind,destination,payload_json,state,
                    sent_at,corrects_notification_id,correction_id)
                   VALUES(?,?, NULL,NULL,'correction',NULL,?, 'sent', ?,?,?)""",
                (notif_id, anchor["workload"], canonical_text({"correction_ids": correction_ids}),
                 payload.get("at"), payload.get("corrects_notification_id"), correction_ids[0] if correction_ids else None),
            )

        preserved = [{
            "object_uid": o["object_uid"], "name": o["name"], "version": o["version"],
            "hash": o["hash"], "reversible": o["reversible"],
        } for o in assessment["live_objects"]]
        self.db.execute(
            """INSERT INTO custody_compat_repairs
               (anchor_id,migration_id,workload,old_api,new_api,state,view_contract_json,preserved_json,
                approval_json,correction_ids_json,token,epoch,at)
               VALUES(?,?,?,?,?, 'active',?,?,?,?,?,?,?)
               ON CONFLICT(anchor_id) DO UPDATE SET state='active'""",
            (anchor_id, anchor["migration_id"], anchor["workload"], contract["old_api"], contract["new_api"],
             canonical_text(contract), canonical_text(preserved), canonical_text(approval),
             canonical_text(correction_ids), fence["token"], fence["epoch"], payload.get("at")),
        )

        node = self.db.execute("SELECT version,generation FROM nodes WHERE id=?", (anchor["node_id"],)).fetchone()
        old_objects = self.list_old(anchor["workload"])
        result = {
            "decision": "forward_fix_applied",
            "receipt": "forward_compat_active",
            "status": "forward_compat_active",
            "recovery_path": "forward_compat",
            "physical_rollback": False,
            "rolled_back": False,
            "not_rolled_back": True,
            "physical_rollback_claim": False,
            "anchor_id": anchor_id,
            "migration_id": anchor["migration_id"],
            "workload": anchor["workload"],
            "actual_controller_version": node["version"] if node else None,
            "anchor_old_node_version": anchor["node_version"],
            "node_generation": node["generation"] if node else anchor["node_generation"],
            "storage_format": compat.NEW_API,
            "old_api": contract["old_api"],
            "old_api_serving": "compatibility_facade",
            "old_api_readable": True,
            "old_api_writable": True,
            "old_api_write_semantics": "contract fields translated; non-contract fields preserved",
            "object_set": old_objects,
            "visible_objects": old_objects,
            "preserved_objects": preserved,
            "untranslatable_fields": assessment.get("forward_plan", {}).get("untranslatable_fields", []),
            "correction_ids": correction_ids,
            "notification_ids": assessment["notification_ids"],
            "receipt_count": len(assessment["receipt_ids"]),
            "write_fence": {"epoch": fence["epoch"], "committer_role": "compat", "token": fence["token"]},
            "compat_repair_id": anchor_id,
        }
        checkpoint = max([anchor["object_version"]] + [s["seq"] for s in assessment["steps"]])
        self._upsert_recovery(
            anchor, "forward_compat", "forward_compat", "forward_compat_active", assessment, payload,
            approval, checkpoint=checkpoint, decision="forward_fix_applied", result=result, completed=True,
        )
        self.db.execute("UPDATE custody_anchors SET state='forward_compat_active' WHERE anchor_id=?", (anchor_id,))
        return result

    def forward_fix_required(self, payload, assessment, stage=None):
        anchor_id = payload.get("id") or payload.get("anchor_id")
        anchor_row = self.db.execute("SELECT * FROM custody_anchors WHERE anchor_id=?", (anchor_id,)).fetchone()
        if not anchor_row:
            raise CustodyBlocked("unknown_anchor", anchor_id=anchor_id)
        anchor = _row_dict(anchor_row)
        # Close the new write entrance before handing the incident to forward fix.
        fence = self.freeze_new_writes(anchor["workload"], payload.get("at"), anchor_id)
        approval = self._authorization(payload, "assessment_only")
        apply_request = {
            "op": "rollback",
            "id": anchor_id,
            "recovery_path": "forward_compat",
            "approval_id": payload.get("approval_id") or "<customer-operations-approval-id>",
        }
        if payload.get("at") is not None:
            apply_request["at"] = payload["at"]
        if payload.get("correction_notification_id"):
            apply_request["correction_notification_id"] = payload["correction_notification_id"]
        result = {
            "decision": "forward_fix_required",
            "receipt": "forward_fix_handoff",
            "recovery_path": "forward_compat",
            "physical_rollback": False,
            "rolled_back": False,
            "not_rolled_back": True,
            "reason": "irreversible_confirmed_customer_field",
            "anchor_id": anchor_id,
            "migration_id": anchor["migration_id"],
            "workload": anchor["workload"],
            "blockers": assessment["blockers"],
            "untranslatable_fields": assessment.get("forward_plan", {}).get("untranslatable_fields", []),
            "forward_plan": assessment["forward_plan"],
            "apply_request": apply_request,
            "executable_handoff": apply_request,
            "write_fence": {"epoch": fence["epoch"], "state": fence["state"]},
            "receipt_ids": assessment["receipt_ids"],
            "notification_ids": assessment["notification_ids"],
            "stage": stage or "assessment",
        }
        self._upsert_recovery(
            anchor, payload.get("recovery_path", "auto"), None, "forward_fix_required",
            assessment, payload, approval, checkpoint=anchor["object_version"],
            decision="forward_fix_required", result=result,
        )
        return result

    def _upsert_recovery(self, anchor, requested_path, actual_path, state, assessment,
                         payload, approval, checkpoint, decision, result, completed=False):
        anchor_id = anchor["anchor_id"]
        now = payload.get("at")
        existing = self.get_recovery(anchor_id)
        started = existing["started_at"] if existing else now
        self.db.execute(
            """INSERT INTO custody_recoveries
               (anchor_id,migration_id,workload,requested_path,actual_path,decision,state,lossless,
                assessment_json,plan_json,checkpoint_seq,approval_json,result_json,started_at,
                updated_at,completed_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(anchor_id) DO UPDATE SET
                 requested_path=excluded.requested_path, actual_path=excluded.actual_path,
                 decision=excluded.decision,state=excluded.state,lossless=excluded.lossless,
                 assessment_json=excluded.assessment_json,plan_json=excluded.plan_json,
                 checkpoint_seq=excluded.checkpoint_seq,approval_json=excluded.approval_json,
                 result_json=excluded.result_json,updated_at=excluded.updated_at,
                 completed_at=excluded.completed_at""",
            (anchor_id, anchor["migration_id"], anchor["workload"], requested_path, actual_path,
             decision, state, 1 if assessment.get("lossless") else 0, canonical_text(assessment),
             canonical_text(assessment.get("physical_plan") or assessment.get("forward_plan") or {}),
             int(checkpoint), canonical_text(approval), canonical_text(result), started, now,
             now if completed else None),
        )


def _path_choice(value):
    value = (value or "auto").lower()
    if value in {"forward", "compat", "forward_fix", "forward_compat", "compatibility_repair"}:
        return "forward_compat"
    if value in {"physical", "physical_rollback", "old", "rollback"}:
        return "physical_rollback"
    return "auto"


def _deep_merge(base, patch):
    out = dict(base)
    for key, value in patch.items():
        if key in out and isinstance(out[key], dict) and isinstance(value, dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _leaf_top_keys(obj):
    if not isinstance(obj, dict):
        return []
    return list(obj.keys())


def _apply_old_fields(current, old_body, contract):
    out = dict(current or {})
    for field in contract.get("fields", []):
        name = field["field"]
        if name not in old_body:
            continue
        value = old_body[name]
        paths = field.get("new_paths", [name])
        target_path = None
        for dotted in paths:
            path = tuple(dotted.split("."))
            cur = out
            for part in path[:-1]:
                if not isinstance(cur.get(part), dict):
                    cur = None
                    break
                cur = cur[part]
            if cur is not None and path[-1] in cur:
                target_path = path
                break
        if target_path is None:
            target_path = tuple(paths[0].split("."))
        cur = out
        for part in target_path[:-1]:
            cur = cur.setdefault(part, {})
        cur[target_path[-1]] = value
    current_uid = (current or {}).get("uid")
    if current_uid:
        out["uid"] = current_uid
    else:
        out.pop("uid", None)
    return out


# ----------------------------------------------------------------------
# Module-level functional API.
# ----------------------------------------------------------------------
def run(db, payload):
    from .store import audit_run

    @audit_run("object_custody")
    def _run(database, item):
        try:
            with transaction(database):
                return CustodyLedger(database).dispatch(item)
        except CustodyBlocked as blocked:
            return blocked.result()

    return _run(db, payload)


def save_contract(db, *args, **kwargs):
    return CustodyLedger(db).save_contract(*args, **kwargs)


def commit_write(db, payload=None, **kwargs):
    payload = dict(payload or {})
    payload.update(kwargs)
    return CustodyLedger(db).commit_write(payload)


record_customer_write = commit_write
acknowledge_write = commit_write


def old_write(db, payload=None, **kwargs):
    payload = dict(payload or {})
    payload.update(kwargs)
    return CustodyLedger(db).old_write(payload)


def read_old(db, workload="default", name=None, uid=None):
    return CustodyLedger(db).read_old(workload, name, uid)


def read_new(db, workload="default", name=None, uid=None):
    return CustodyLedger(db).read_new(workload, name, uid)


def assess(db, anchor_id):
    return CustodyLedger(db).assessment_for_anchor(anchor_id)


def recover(db, payload):
    return CustodyLedger(db).recover(payload)


def freeze_writes(db, workload="default", at=None, anchor_id=None):
    return CustodyLedger(db).freeze_new_writes(workload, at, anchor_id)


def handoff_write_fence(db, *args, **kwargs):
    return CustodyLedger(db).handoff_write_fence(*args, **kwargs)


# Vocabulary aliases for rescue runbooks and alternate test naming.
CustodyLedger.record_operation = CustodyLedger.commit_write
CustodyLedger.write = CustodyLedger.commit_write
CustodyLedger.acknowledge_operation = CustodyLedger.commit_write
CustodyLedger.plan_recovery = CustodyLedger.assessment_for_anchor
CustodyLedger.execute_recovery = CustodyLedger.recover
CustodyLedger.execute_rollback = CustodyLedger.recover
CustodyLedger.physical_rollback = CustodyLedger.apply_physical
CustodyLedger.publish_forward_fix = CustodyLedger.apply_forward
CustodyLedger.get_old_object = CustodyLedger.read_old
CustodyLedger.get_new_object = CustodyLedger.read_new

ObjectCustody = CustodyLedger
CustodyStore = CustodyLedger
CustomerObjectCustody = CustodyLedger
ObjectCustodyStore = CustodyLedger
record_operation = commit_write
write_object = commit_write
acknowledge_operation = commit_write
plan_recovery = assess
execute_recovery = recover
execute_rollback = recover
