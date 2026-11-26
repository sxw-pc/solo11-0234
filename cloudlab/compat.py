"""Versioned workload and customer-object compatibility semantics.

The historical :func:`effective` contract only describes workload selector /
availability configuration.  Customer objects have a separate field contract;
rollback custody uses :func:`object_contract` and :func:`classify_object` to
decide whether confirmed writes can be physically represented by ``old/v1``.
"""
import json

OLD_API = "old/v1"
NEW_API = "new/v2"
CONVERSION_RULES_VERSION = "object-custody-v1"

# The fixed on-site original in the rescue exercise has exactly these
# customer-visible old-model fields.  Additional new-model fields are not
# silently dropped; they classify the live confirmed object as irreversible.
OLD_OBJECT_FIELDS = ("name", "replicas")

_IDENTITY_FIELDS = (
    "uid", "id", "name", "namespace", "apiVersion", "kind",
    "resourceVersion", "generation",
)


class CompatibilityError(ValueError):
    """Base class for contract and conversion failures."""


class IrreversibleField(CompatibilityError):
    def __init__(self, report):
        self.report = report
        fields = ",".join(report.get("untranslatable_fields", [])) or "object"
        super().__init__(f"field(s) not expressible by old API: {fields}")


def effective(manifest, api):
    if api == 'old/v1':
        desired = manifest.get('replicas', 1)
        minimum = manifest.get('minAvailable', 0)
    elif api == 'new/v2':
        desired = manifest.get('desiredReplicas', 2)
        minimum = manifest.get('availability', {}).get('minimumReady', 1)
    else:
        raise ValueError('unsupported API version')
    if not isinstance(desired, int) or isinstance(desired, bool) or not isinstance(minimum, int) or isinstance(minimum, bool) or desired < 1 or minimum < 0 or minimum > desired:
        raise ValueError('invalid availability contract')
    selector = tuple(sorted(manifest.get('selector', {}).items()))
    return {'desired': desired, 'minimum_ready': minimum, 'selector': selector}


def canonical_json(value):
    """Deterministic JSON text used for hashes, anchors and replay."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canonical_bytes(value):
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return canonical_json(value).encode("utf-8")


def _path_get(data, path):
    cur = data
    for part in path:
        if not isinstance(cur, dict) or part not in cur:
            return None, False
        cur = cur[part]
    return cur, True


def _dotted(path):
    return ".".join(path)


def object_contract(old_api=OLD_API, expressible_fields=None, new_api=NEW_API):
    """Return the field boundary that old clients can express.

    ``expressible_fields`` may contain field names from the built-in binding
    table.  The result is JSON-safe and is hashed into recovery anchors.
    """
    selected = tuple(expressible_fields or OLD_OBJECT_FIELDS)
    known = {binding["field"]: binding for binding in FIELD_BINDINGS}
    fields = []
    for name in selected:
        if isinstance(name, dict):
            binding = dict(name)
        else:
            if name not in known:
                # A declared custom field is still represented explicitly.  It
                # has the same JSON field name on both surfaces unless paths
                # are supplied by the caller.
                binding = {
                    "field": name,
                    "type": "any",
                    "old_paths": [(name,)],
                    "new_paths": [(name,)],
                    "required": False,
                    "writable": True,
                }
            else:
                binding = known[name]
        item = dict(binding)
        item["old_paths"] = [_dotted(p) if isinstance(p, tuple) else p for p in item.get("old_paths", [(name,)])]
        item["new_paths"] = [_dotted(p) if isinstance(p, tuple) else p for p in item.get("new_paths", [(name,)])]
        fields.append(item)

    old_paths = set()
    new_paths = set()
    for field in fields:
        for path in field["old_paths"]:
            old_paths.add(path)
        for path in field["new_paths"]:
            new_paths.add(path)

    # Identity/bookkeeping paths remain stable across the conversion.  They
    # are not treated as customer spec extensions.
    identity_paths = set(_IDENTITY_FIELDS)
    identity_paths.update(f"metadata.{name}" for name in ("name", "uid", "id", "namespace", "resourceVersion", "generation"))
    new_paths.update(identity_paths)
    old_paths.update(("uid", "id"))

    return {
        "rules_version": CONVERSION_RULES_VERSION,
        "old_api": old_api,
        "new_api": new_api,
        "expressible_fields": list(selected),
        "fields": fields,
        "old_paths": sorted(old_paths),
        "new_paths": sorted(new_paths),
        "identity_fields": list(_IDENTITY_FIELDS),
        "unknown_field_policy": "reject_and_preserve_for_forward_fix",
        "ordering": "committed_seq_with_causal_after",
        "idempotency_keys": ["workload", "command_id"],
        "write_fence": "monotonic_epoch_single_committer",
    }


FIELD_BINDINGS = (
    {
        "field": "name",
        "type": "string",
        "required": True,
        "writable": False,
        "old_paths": [("name",)],
        "new_paths": [("name",), ("metadata", "name")],
    },
    {
        "field": "replicas",
        "type": "integer",
        "required": False,
        "writable": True,
        "old_paths": [("replicas",)],
        "new_paths": [("replicas",), ("spec", "replicas")],
    },
)


def _leaf_paths(value, prefix=()):
    if isinstance(value, dict):
        if not value and prefix:
            yield _dotted(prefix)
        for key, child in value.items():
            path = prefix + (str(key),)
            if isinstance(child, dict):
                yield from _leaf_paths(child, path)
            elif isinstance(child, list):
                yield _dotted(path) + "[]"
                for item in child:
                    if isinstance(item, (dict, list)):
                        yield from _leaf_paths(item, path + ("[]",))
                    # scalar list entries are covered by the field[] marker
            else:
                yield _dotted(path)
    elif isinstance(value, list):
        for item in value:
            yield from _leaf_paths(item, prefix + ("[]",))


def _type_ok(value, expected):
    if expected in ("any", None):
        return True
    if expected in ("integer", "int"):
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "string":
        return isinstance(value, str)
    if expected in ("number", "float"):
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected in ("object", "dict"):
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    return True


def _paths_from_contract(contract, side):
    paths = set(contract.get(f"{side}_paths", []))
    # JSON contract stores dotted paths; built-in tuple paths were converted.
    return paths


def project_old(obj, contract=None):
    """Project a new object onto the strict old-client field surface."""
    if contract is None:
        contract = object_contract()
    elif isinstance(contract, str):
        contract = object_contract(contract)

    view = {}
    values = {}
    for field in contract.get("fields", []):
        value = None
        found = False
        for dotted in field.get("new_paths", [field["field"]]):
            path = tuple(dotted.split("."))
            candidate, ok = _path_get(obj, path)
            if ok:
                value, found = candidate, True
                break
        if not found:
            for dotted in field.get("old_paths", [field["field"]]):
                candidate, ok = _path_get(obj, tuple(dotted.split(".")))
                if ok:
                    value, found = candidate, True
                    break
        if found:
            view[field["field"]] = value
            values[field["field"]] = value
    return view


def classify_object(obj, contract=None):
    """Classify a confirmed object against the old expression boundary."""
    if not isinstance(obj, dict):
        return {
            "expressible": False,
            "old_view": {},
            "untranslatable_fields": [],
            "violations": [{"path": "$", "reason": "object_must_be_mapping"}],
            "object_uid": None,
            "object_name": None,
        }
    if contract is None:
        contract = object_contract()
    elif isinstance(contract, str):
        contract = object_contract(contract)

    allowed_new = _paths_from_contract(contract, "new")
    violations = []
    unknown = []
    for path in sorted(set(_leaf_paths(obj))):
        # List marker and ordinary path both need an allowed prefix/root.
        normal = path.replace("[].", ".").replace(".[]", "").replace("[]", "")
        normal = normal.replace("..", ".").strip(".")
        root = normal.split(".")[0].split("[")[0]
        if path in allowed_new or normal in allowed_new or root in allowed_new:
            continue
        # A nested known path can have list marker children not explicitly
        # listed.  Check whether any allowed path is a prefix.
        if any(normal == p or normal.startswith(p + ".") or p.startswith(normal + ".") for p in allowed_new):
            continue
        unknown.append(path)
        violations.append({
            "path": path,
            "field": root,
            "reason": "not_expressible_by_old_api",
        })

    type_errors = []
    old_view = project_old(obj, contract)
    for field in contract.get("fields", []):
        name = field["field"]
        if name in old_view and not _type_ok(old_view[name], field.get("type")):
            type_errors.append({"field": name, "reason": "type_contract_mismatch", "expected": field.get("type")})
        if field.get("required") and name not in old_view:
            type_errors.append({"field": name, "reason": "missing_required_field"})

    uid = obj.get("uid") or obj.get("id")
    if not uid and isinstance(obj.get("metadata"), dict):
        uid = obj["metadata"].get("uid") or obj["metadata"].get("id")
    name = old_view.get("name") or obj.get("name")
    if not name and isinstance(obj.get("metadata"), dict):
        name = obj["metadata"].get("name")

    untranslatable = sorted({v["field"] for v in violations})
    expressible = not violations and not type_errors
    return {
        "expressible": expressible,
        "reversible": expressible,
        "old_view": old_view,
        "untranslatable_fields": untranslatable,
        "violations": violations + type_errors,
        "object_uid": uid or (f"uid:{name}" if name else None),
        "object_name": name,
        "rules_version": contract.get("rules_version", CONVERSION_RULES_VERSION),
    }


def is_lossless_object(obj, contract=None):
    return bool(classify_object(obj, contract).get("expressible"))


def to_old_object(obj, contract=None):
    report = classify_object(obj, contract)
    if not report["expressible"]:
        raise IrreversibleField(report)
    return dict(report["old_view"])


def conversion_rules(old_api=OLD_API, new_api=NEW_API, expressible_fields=None):
    contract = object_contract(old_api, expressible_fields, new_api)
    return {
        "version": CONVERSION_RULES_VERSION,
        "contract_hash": hashes(contract)["sha256"],
        "old_api": old_api,
        "new_api": new_api,
        "field_bindings": contract["fields"],
        "unknown_fields": "reject",
        "write_handoff": "freeze_new_then_monotonic_fence_epoch",
        "idempotent_replay": "command_id_returns_original_ack",
    }


def hashes(value):
    import hashlib
    raw = value if isinstance(value, (bytes, bytearray)) else canonical_bytes(value)
    return {"sha256": hashlib.sha256(bytes(raw)).hexdigest()}


# Common descriptive aliases for callers/tests using the task's vocabulary.
OLD_API_OBJECT_FIELDS = OLD_OBJECT_FIELDS
EXPRESSIBLE_FIELDS = OLD_OBJECT_FIELDS
field_scope = object_contract
describe_object = classify_object
lossless = is_lossless_object
