# P-5 P-11 P-67 P-72
import hashlib
import json
import os
import sys

OUT = sys.argv[1]
CBOR_OUT = sys.argv[2] if len(sys.argv) > 2 else None


class Tag:
    def __init__(self, tag, value):
        self.tag, self.value = tag, value


class Reject(Exception):
    pass


def _head(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")


def enc(v):
    if v is False:
        return b"\xf4"
    if v is True:
        return b"\xf5"
    if v is None:
        return b"\xf6"
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, bytes):
        return _head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, (list, tuple)):
        return _head(4, len(v)) + b"".join(enc(x) for x in v)
    if isinstance(v, dict):
        items = sorted(((enc(k), enc(x)) for k, x in v.items()), key=lambda kv: kv[0])
        for a, b in zip(items, items[1:]):
            if a[0] == b[0]:
                raise ValueError("duplicate key")
        return _head(5, len(items)) + b"".join(k + x for k, x in items)
    if isinstance(v, Tag):
        return _head(6, v.tag) + enc(v.value)
    raise TypeError(type(v))


MAX_DEPTH, MAX_ITEMS, MAX_STR = 16, 256, 65536


def check(data, allowed_tags=()):
    pos = 0

    def arg(ai):
        nonlocal pos
        if ai < 24:
            return ai
        size = {24: 1, 25: 2, 26: 4, 27: 8}.get(ai)
        if size is None:
            if ai != 31:
                raise Reject("malformed_cbor:reserved_additional_info")
            raise Reject("non_canonical_cbor:indefinite_length")
        if pos + size > len(data):
            raise Reject("malformed_cbor:truncated")
        n = int.from_bytes(data[pos:pos + size], "big")
        pos += size
        if n < {1: 24, 2: 0x100, 4: 0x10000, 8: 0x100000000}[size]:
            raise Reject("non_canonical_cbor:non_preferred_argument")
        return n

    def nested(depth):
        if depth + 1 > MAX_DEPTH:
            raise Reject("limit_exceeded:depth")
        return depth + 1

    def item(depth):
        nonlocal pos
        if pos >= len(data):
            raise Reject("malformed_cbor:truncated")
        ib = data[pos]
        pos += 1
        major, ai = ib >> 5, ib & 31
        if major == 7:
            if ai in (20, 21, 22):
                return {20: False, 21: True, 22: None}[ai]
            if ai in (25, 26, 27):
                raise Reject("non_canonical_cbor:float_not_in_profile")
            raise Reject("non_canonical_cbor:simple_not_in_profile")
        n = arg(ai)
        if major == 0:
            return n
        if major == 1:
            return -1 - n
        if major in (2, 3):
            if n > MAX_STR:
                raise Reject("limit_exceeded:string")
            if pos + n > len(data):
                raise Reject("malformed_cbor:truncated")
            raw = data[pos:pos + n]
            pos += n
            if major == 2:
                return bytes(raw)
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                raise Reject("malformed_cbor:invalid_utf8")
        if major == 4:
            if n > MAX_ITEMS:
                raise Reject("limit_exceeded:items")
            inner = nested(depth)
            return [item(inner) for _ in range(n)]
        if major == 5:
            if n > MAX_ITEMS:
                raise Reject("limit_exceeded:items")
            inner = nested(depth)
            out, prev = {}, None
            for _ in range(n):
                start = pos
                k = item(inner)
                kb = bytes(data[start:pos])
                if prev is not None:
                    if kb == prev:
                        raise Reject("non_canonical_cbor:duplicate_map_key")
                    if kb < prev:
                        raise Reject("non_canonical_cbor:unsorted_map_keys")
                prev = kb
                out[k if not isinstance(k, list) else tuple(k)] = item(inner)
            return out
        if n not in allowed_tags:
            raise Reject("non_canonical_cbor:tag_not_allowed")
        return Tag(n, item(nested(depth)))

    v = item(0)
    if pos != len(data):
        raise Reject("malformed_cbor:trailing_bytes")
    return v


def diag(v, indent=0):
    pad = "  " * indent
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, bytes):
        return "h'" + v.hex() + "'"
    if isinstance(v, str):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(v, (list, tuple)):
        if all(not isinstance(x, (list, tuple, dict)) for x in v) and len(v) <= 4:
            return "[" + ", ".join(diag(x, indent) for x in v) + "]"
        inner = ",\n".join(pad + "  " + diag(x, indent + 1) for x in v)
        return "[\n" + inner + "\n" + pad + "]"
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: enc(kv[0]))
        inner = ",\n".join(pad + "  " + diag(k, indent + 1) + ": " + diag(x, indent + 1) for k, x in items)
        return "{\n" + inner + "\n" + pad + "}"
    raise TypeError(type(v))


def project(v):
    if isinstance(v, bool) or v is None or isinstance(v, str):
        return v
    if isinstance(v, int):
        return v if -(2 ** 53) <= v <= 2 ** 53 else str(v)
    if isinstance(v, bytes):
        return v.hex()
    if isinstance(v, (list, tuple)):
        return [project(x) for x in v]
    if isinstance(v, dict):
        return {k: project(x) for k, x in v.items()}
    raise TypeError(type(v))


def canonical(v):
    if isinstance(v, dict):
        return {k: canonical(v[k]) for k in sorted(v, key=enc)}
    if isinstance(v, (list, tuple)):
        return [canonical(x) for x in v]
    return v


def decoded(b, value=None):
    try:
        return project(check(b))
    except Reject:
        return project(canonical(value))


def sha(b):
    return hashlib.sha256(b).digest()


def label(s):
    return [-16, sha(("work-vector:" + s).encode())]


def write_json(name, obj):
    with open(os.path.join(OUT, name), "w") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")


manifest = []


def write_cbor(root, name, b, cddl):
    if CBOR_OUT is None:
        return
    with open(os.path.join(CBOR_OUT, name + ".cbor"), "wb") as f:
        f.write(b)
    manifest.append("%s %s %s" % (root, name, cddl))


os.makedirs(OUT, exist_ok=True)
if CBOR_OUT is not None:
    os.makedirs(CBOR_OUT, exist_ok=True)

ACCESS_CR_10 = "Access CR-10"
D4, D5, D7 = ["P-91"], ["P-92"], ["P-94"]
CORE = "https://suiss.app/ns/work/"
DECLARATION = CORE + "declaration/"
ACT = CORE + "act/"
CLAIM = CORE + "claim/"
EVIDENCE = CORE + "evidence/"
ROLE = CORE + "derived_from/"
PROC = "https://procurement.example/ns/"
CLINIC = "https://clinic.example/ns/"
CDDL_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "cddl", "work-record.cddl")
with open(CDDL_FILE, "rb") as f:
    CDDL_DIGEST = [-16, sha(f.read())]
GENESIS = {
    "pos": 0,
    "recorded_at": 1792109000000,
    "versions": {"protocol": [1, 0], "schema": CDDL_DIGEST},
    "nonce": sha(b"work-vector:genesis-nonce"),
}
GENESIS_BYTES = enc(GENESIS)
LEDGER = [-16, sha(GENESIS_BYTES)]
GENESIS_LEAF = sha(b"\x00" + GENESIS_BYTES)
W1 = bytes.fromhex("019a2f4c8e1b7c3da5e6f70812345678")
W2 = bytes.fromhex("019a2f4c8e1b7c3da5e6f70887654321")
ALICE = "party:acme:alice"
BUYER = "party:acme:buyer-org"
AGENT = "party:acme:agent-procure-7"
SUPPLIER = "party:globex:supplier"
SYS = "party:acme:work-scheduler"
ACTOR = {AGENT: "agent", SUPPLIER: "organization", SYS: "system", ALICE: "human"}
DECLARATIONS = (
    "request promise promise_conditional decline counter accept_counter state accept reject cancel release "
    "delegate assign allow refuse amend declare_obsolete expire administrative_close dispute defer resume "
    "notice revoke_request revoke_promise revoke_statement revoke_acceptance claim unclaim forward nominate "
    "offer reassign renew_lease gate_decision stop_request stop_response open_condition withdraw_condition "
    "resume_after_stop practice_adoption disclosure queue_definition control_lease handoff_note "
    "conflict_resolution admission autonomy_policy implicit_acceptance_terms waiver attention_request "
    "acknowledgement"
).split()
CORE_TYPES = ({DECLARATION + n for n in DECLARATIONS} | {ACT + "action"}
              | {CLAIM + n for n in ("observation", "assessment", "assumption")})
CONDITIONS = {CORE + "condition/" + n for n in (
    "information", "commitment", "external_event", "time", "third_party",
    "authority", "decision", "acceptance", "resource")}
PARAMS = {
    "decline": {"reason": {"no_capacity", "no_authority", "out_of_scope", "missing_information",
                           "unacceptable_terms", "other"}},
    "cancel": {"reason": {"cannot_complete", "failed", "abandoned", "other"}},
    "notice": {"notice_type": {"at_risk", "cannot_complete", "obsolete_suggested"}},
    "stop_request": {"stop_type": {"immediate", "finish_then_stop", "pause"}},
    "stop_response": {"response": {"accept", "finish_then_stop", "refuse"}},
    "open_condition": {"condition_type": CONDITIONS, "wait_reason": {"internal", "external"},
                       "gate_form": {"approval", "pre_action_review", "delivery_acceptance"},
                       "address": None, "deadline": None, "criterion": None},
}
PARAM_REQUIRED = {
    "decline": ("reason",),
    "cancel": ("reason",),
    "notice": ("notice_type",),
    "stop_request": ("stop_type",),
    "stop_response": ("response",),
    "open_condition": ("condition_type", "wait_reason", "address", "deadline", "criterion"),
}
REASON_KEYS = {"reason", "notice_type"}
CORE_ROLES = {ROLE + n for n in ("source", "fulfills", "supports")}
CORE_EVIDENCE = {EVIDENCE + n for n in ("artifact", "external_event", "measurement", "human_verification")}
CONSENT = CLINIC + "ext/patient_consent"
WARD = CLINIC + "ext/ward"


def big_array(n):
    return (bytes([0x99]) + n.to_bytes(2, "big") + b"\x00" * n) if n > 255 else (bytes([0x98, n]) + b"\x00" * n)


cbor_cases = [
    ("uint-0", "00", "accept", None, "P-5"),
    ("uint-23", "17", "accept", None, "P-5"),
    ("uint-24", "1818", "accept", None, "P-5"),
    ("uint-256", "190100", "accept", None, "P-5"),
    ("uint-2^32", "1b0000000100000000", "accept", None, "P-5"),
    ("nint-25", "3818", "accept", None, "P-5"),
    ("map-text-keys-sorted", enc({"a": 1, "b": 2}).hex(), "accept", None, "P-5"),
    ("map-shorter-key-first", enc({"b": 1, "aa": 2}).hex(), "accept", None, "P-5"),
    ("map-int-before-text", enc({1: -19, "a": 0}).hex(), "accept", None, "P-5"),
    ("map-uint-before-nint", enc({1: 0, -1: 0}).hex(), "accept", None, "P-5"),
    ("array-256-items", big_array(256).hex(), "accept", None, "P-7"),
    ("depth-16", (b"\x81" * 16 + b"\x00").hex(), "accept", None, "P-7"),
    ("cose-tag-18-at-container", "d28440a0f640", "container", None, "P-6"),
    ("uint-23-in-1-byte", "1817", "reject", "non_canonical_cbor:non_preferred_argument", "P-5"),
    ("uint-23-in-2-bytes", "190017", "reject", "non_canonical_cbor:non_preferred_argument", "P-5"),
    ("uint-255-in-4-bytes", "1a000000ff", "reject", "non_canonical_cbor:non_preferred_argument", "P-5"),
    ("uint-255-in-8-bytes", "1b00000000000000ff", "reject", "non_canonical_cbor:non_preferred_argument", "P-5"),
    ("nint-in-1-byte", "3817", "reject", "non_canonical_cbor:non_preferred_argument", "P-5"),
    ("text-length-non-preferred", "780161", "reject", "non_canonical_cbor:non_preferred_argument", "P-5"),
    ("map-unsorted-keys", "a2616201616102", "reject", "non_canonical_cbor:unsorted_map_keys", "P-5"),
    ("map-length-first-violated", "a262616101616202", "reject", "non_canonical_cbor:unsorted_map_keys", "P-5"),
    ("map-nint-before-uint", "a220000100", "reject", "non_canonical_cbor:unsorted_map_keys", "P-5"),
    ("map-duplicate-key", "a2616101616102", "reject", "non_canonical_cbor:duplicate_map_key", "P-5"),
    ("indefinite-array", "9f01ff", "reject", "non_canonical_cbor:indefinite_length", "P-5"),
    ("indefinite-map", "bf616101ff", "reject", "non_canonical_cbor:indefinite_length", "P-5"),
    ("indefinite-text", "7f61616162ff", "reject", "non_canonical_cbor:indefinite_length", "P-5"),
    ("indefinite-bytes", "5f4101ff", "reject", "non_canonical_cbor:indefinite_length", "P-5"),
    ("tag-1-epoch-time", "c11a5f5e1000", "reject", "non_canonical_cbor:tag_not_allowed", "P-72"),
    ("tag-0-datetime-text", "c074323032362d31302d31365430303a30303a30305a", "reject", "non_canonical_cbor:tag_not_allowed", "P-72"),
    ("tag-2-bignum", "c249010000000000000000", "reject", "non_canonical_cbor:tag_not_allowed", "P-72"),
    ("tag-24-embedded-cbor", "d8184100", "reject", "non_canonical_cbor:tag_not_allowed", "P-72"),
    ("float-half", "f93c00", "reject", "non_canonical_cbor:float_not_in_profile", "P-5"),
    ("float-double-non-preferred", "fb3ff0000000000000", "reject", "non_canonical_cbor:float_not_in_profile", "P-5"),
    ("simple-undefined", "f7", "reject", "non_canonical_cbor:simple_not_in_profile", "P-5"),
    ("trailing-bytes", "0000", "reject", "malformed_cbor:trailing_bytes", "P-5"),
    ("invalid-utf8", "62c328", "reject", "malformed_cbor:invalid_utf8", "P-5"),
    ("reserved-ai-28-uint", "1c", "reject", "malformed_cbor:reserved_additional_info", "P-103"),
    ("reserved-ai-29-text", "7d", "reject", "malformed_cbor:reserved_additional_info", "P-103"),
    ("reserved-ai-30-in-array", "811e", "reject", "malformed_cbor:reserved_additional_info", "P-103"),
    ("simple-ai-28", "fc", "reject", "non_canonical_cbor:simple_not_in_profile", "P-103"),
    ("array-257-items", big_array(257).hex(), "reject", "limit_exceeded:items", "P-7"),
    ("depth-17", (b"\x81" * 17 + b"\x00").hex(), "reject", "limit_exceeded:depth", "P-7"),
]
out_cbor = []
for name, hx, outcome, reason, rule in cbor_cases:
    allowed = (18,) if outcome == "container" else ()
    try:
        check(bytes.fromhex(hx), allowed)
        got = ("accept", None)
    except Reject as e:
        got = ("reject", str(e))
    exp = ("reject", reason) if outcome == "reject" else ("accept", None)
    assert got == exp, (name, got, exp)
    out_cbor.append({"id": "cbor/" + name, "rules": [rule, ACCESS_CR_10], "hex": hx,
                     "context": {"tag_allowlist": list(allowed)},
                     "expect": {"outcome": exp[0], **({"reason": reason} if reason else {})}})
long_string = bytes.fromhex("5a00010001") + b"\x00" * 65537
try:
    check(long_string)
    raise SystemExit("string limit not enforced")
except Reject as e:
    assert str(e) == "limit_exceeded:string"
out_cbor.append({"id": "cbor/string-65537-bytes", "rules": ["P-7", ACCESS_CR_10],
                 "generator": {"head_hex": "5a00010001", "fill_hex": "00", "fill_count": 65537},
                 "context": {"tag_allowlist": []},
                 "expect": {"outcome": "reject", "reason": "limit_exceeded:string"}})
write_json("cbor-canonical.json", {
    "file": "cbor-canonical.json",
    "profile": "RFC 8949 section 4.2.1 core deterministic encoding with the Access CR-10 limits",
    "limits": {"depth": MAX_DEPTH, "items": MAX_ITEMS, "string_bytes": MAX_STR},
    "cases": out_cbor})




def ordered(xs):
    keys = [enc(x) for x in xs]
    return keys == sorted(set(keys))


def repeated(xs):
    keys = [enc(x) for x in xs]
    return len(keys) != len(set(keys))


KNOWN_PROTOCOLS = ([1, 0],)
SEMANTIC_LIMITS = (("basis", 64), ("on_behalf_of", 8), ("relations", 256), ("concerns", 64))
GATE_FORMS = {"approval", "pre_action_review", "delivery_acceptance"}
GATE_RULES = {
    CORE + "condition/acceptance": {"delivery_acceptance"},
    CORE + "condition/decision": {"approval", "pre_action_review"},
    CORE + "condition/resource": {"approval", "pre_action_review"},
}


def is_type_uri(v):
    if not isinstance(v, str) or not v.startswith("https://"):
        return False
    rest = v[len("https://"):]
    if "/" not in rest:
        return False
    authority, path = rest.split("/", 1)
    host, _, port = authority.partition(":")
    return (bool(host) and all(c in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in host)
            and (":" not in authority or (port.isdigit()))
            and all("!" <= c <= "~" for c in path))


def under(uri, ns):
    return uri.startswith(ns) and (ns.endswith("/") or uri[len(ns):] in ("",) or uri[len(ns):].startswith("/"))


def pinned(uri, rec):
    return (isinstance(uri, str) and is_type_uri(uri) and not uri.startswith(CORE)
            and any(under(uri, ns) for ns in rec["versions"].get("practices", {})))


def text_len_ok(v, limit):
    return 0 < len(v.encode()) <= limit


def reason_code(v, codes):
    if not isinstance(v, str):
        return False
    parent, sep, sub = v.partition(":")
    return parent in codes and (not sep or is_type_uri(sub))


def catalog_code(k, v, codes):
    return reason_code(v, codes) if k in REASON_KEYS else isinstance(v, str) and v in codes


def condition_params_ok(params, rec):
    condition = params.get("condition_type")
    if not (condition in CONDITIONS or pinned(condition, rec)):
        return False
    gate = params.get("gate_form")
    if condition in GATE_RULES:
        if gate not in GATE_RULES[condition]:
            return False
    elif condition in CONDITIONS:
        if gate is not None:
            return False
    elif gate is not None and gate not in GATE_FORMS:
        return False
    if "address" in params and not (isinstance(params["address"], str) and 0 < len(params["address"].encode()) <= 255
                                    or is_type_uri(params["address"])):
        return False
    if "deadline" in params and not (params["deadline"] == "none" or
                                     isinstance(params["deadline"], int) and not isinstance(params["deadline"], bool)):
        return False
    if "criterion" in params and not is_type_uri(params["criterion"]):
        return False
    return True


def scalar_ok(v):
    if isinstance(v, str):
        return text_len_ok(v, 255) or is_type_uri(v)
    return isinstance(v, (int, bytes)) or (isinstance(v, list) and v[:1] == [-16])


def params_ok(rec):
    params = rec.get("params")
    if params is None and not rec["type"].startswith(DECLARATION):
        return True
    params = params or {}
    for v in params.values():
        if not all(scalar_ok(x) for x in (v if isinstance(v, list) and v[:1] != [-16] else [v])):
            return False
    if "effective_at" in params and (rec["kind"] != "declaration" or not isinstance(params["effective_at"], int)):
        return False
    core_subtype = rec["type"].startswith(CORE)
    if not rec["type"].startswith(DECLARATION):
        return not core_subtype or set(params) <= {"effective_at"}
    name = rec["type"][len(DECLARATION):]
    schema = PARAMS.get(name, {})
    if not set(PARAM_REQUIRED.get(name, ())) <= set(params):
        return False
    for k, v in params.items():
        if k == "effective_at":
            continue
        if k not in schema:
            return False
        if name != "open_condition" and not catalog_code(k, v, schema[k]):
            return False
    if name == "open_condition":
        if not catalog_code("wait_reason", params["wait_reason"], schema["wait_reason"]):
            return False
        return condition_params_ok(params, rec)
    return True


def semantic(rec, ctx):
    if rec["versions"]["protocol"] not in KNOWN_PROTOCOLS:
        return ("quarantine", "protocol_version_unknown")
    for field, limit in SEMANTIC_LIMITS:
        if len(rec.get(field, [])) > limit:
            return ("reject", "limit_exceeded:" + field)
    see = rec["visibility"]["see"]
    parties = see[1] if isinstance(see, list) else []
    lists = [rec.get(f, []) for f in ("correlation", "evidence", "body", "params", "ext", "critical")]
    lists += [rec["versions"].get("practices", {}), parties]
    lists += [v for v in rec.get("params", {}).values() if isinstance(v, list) and v[:1] != [-16]]
    if any(len(xs) > 256 for xs in lists):
        return ("reject", "limit_exceeded:items")
    if not (text_len_ok(rec.get("producer", {}).get("version", "x"), 255)
            and all(text_len_ok(c[1], 1024) for c in rec.get("correlation", []))
            and all(text_len_ok(e["subject"], 1024) for e in rec.get("evidence", []) if isinstance(e["subject"], str))):
        return ("reject", "limit_exceeded:string")
    for field, xs in (("basis", rec.get("basis")), ("concerns", rec["concerns"]),
                      ("critical", rec.get("critical")), ("visibility", parties)):
        if xs is not None and not ordered(xs):
            return ("reject", "non_canonical_set_order:" + field)
    for field, xs in (("relations", rec.get("relations", [])), ("evidence", rec.get("evidence", [])),
                      ("correlation", rec.get("correlation", [])),
                      ("body", [b["part"] for b in rec.get("body", [])]),
                      ("on_behalf_of", rec.get("on_behalf_of", []))):
        if repeated(xs):
            return ("reject", "duplicate_entry:" + field)
    if see == "work" and not rec["concerns"]:
        return ("reject", "visibility_no_work")
    if set(parties) & ({rec["author"]} | set(rec.get("on_behalf_of", []))):
        return ("reject", "duplicate_entry:visibility")
    if any(k not in rec.get("ext", {}) for k in rec.get("critical", [])):
        return ("reject", "extension_critical_dangling")
    obo, cap = rec.get("on_behalf_of"), rec.get("capacity")
    if obo is not None and cap != ["for", obo[0]]:
        return ("reject", "capacity_mismatch")
    if obo is None and isinstance(cap, list):
        return ("reject", "capacity_mismatch")
    if len(ctx["actor_type"].get("on_behalf_of", [])) != len(obo or []):
        return ("reject", "envelope_mismatch:actor_type")
    if rec["kind"] == "declaration" and "authority" not in rec:
        return ("reject", "authority_missing")
    if rec["kind"] == "declaration" and cap is None:
        return ("reject", "capacity_missing")
    if ctx["actor_type"]["author"][0] == "agent" and "producer" not in rec:
        return ("reject", "producer_missing")
    if rec["type"].startswith(CORE):
        if rec["type"] not in CORE_TYPES:
            return ("reject", "unmapped_extension_value")
    elif not pinned(rec["type"], rec):
        return ("reject", "unmapped_extension_value")
    for r in rec.get("relations", []):
        q = r.get("qualifier")
        if r["rel"] == "derived_from":
            if q not in CORE_ROLES and not pinned(q, rec):
                return ("reject", "unmapped_extension_value")
        elif q is not None and not pinned(q, rec):
            return ("reject", "unmapped_extension_value")
    for e in rec.get("evidence", []):
        if e["type"] not in CORE_EVIDENCE and not pinned(e["type"], rec):
            return ("reject", "unmapped_extension_value")
    if not params_ok(rec):
        return ("reject", "schema:params")
    if rec.get("params", {}).get("effective_at", ctx.get("recorded_at", 0)) < ctx.get("recorded_at", 0):
        return ("reject", "retroactive_declaration")
    if ctx["origin"] == "automation" and (
            ctx["actor_type"]["author"] != ["system", "access_binding"] or not rec.get("basis")):
        return ("reject", "unattributed_automation")
    if [k for k in rec.get("critical", []) if k not in ctx["understood_extensions"]]:
        return ("quarantine", "extension_critical_unknown")
    return ("accept", None)


def vis(see="work", **kw):
    v = {"see": see}
    v.update(kw)
    return v


def ctx(rec, origin="direct", understood=(), actor=None, recorded_at=None, rings=None):
    actors = {"author": actor or [ACTOR[rec["author"]], "access_binding"]}
    rings = len(rec.get("on_behalf_of", [])) if rings is None else rings
    if rings:
        actors["on_behalf_of"] = [["organization", "access_binding"] for _ in range(rings)]
    c = {"origin": origin, "actor_type": actors, "understood_extensions": list(understood)}
    if recorded_at is not None:
        c["recorded_at"] = recorded_at
    return c


rec_promise = {
    "kind": "declaration",
    "type": DECLARATION + "promise",
    "author": AGENT,
    "on_behalf_of": [BUYER],
    "capacity": ["for", BUYER],
    "basis": [label("record:commitment.request")],
    "visibility": vis(),
    "ledger": LEDGER,
    "concerns": [W1],
    "authority": {"proof": "decision_receipt", "digest": label("access:decision-receipt:1")},
    "producer": {"version": "procure-agent/3.2.0", "config": label("producer-config:1"),
                 "model": "urn:example:model:m-2026-09"},
    "correlation": [["https://a2a-protocol.org/context-id", "ctx-8f2c"]],
    "body": [{"part": "terms", "commit": label("body:terms:promise")}],
    "versions": {"protocol": [1, 0], "schema": label("schema:declaration.promise")},
}

rec_act = {
    "kind": "act",
    "type": ACT + "action",
    "occurred_at": 1792108800000,
    "author": SUPPLIER,
    "capacity": "own",
    "visibility": vis(),
    "ledger": LEDGER,
    "concerns": [W1],
    "relations": [{"rel": "derived_from", "target": ["record", label("record:commitment.promise:supplier")],
                   "qualifier": ROLE + "fulfills"}],
    "evidence": [{
        "subject": label("artifact:delivery-note.pdf"),
        "type": EVIDENCE + "artifact",
        "presenter": SUPPLIER,
        "claimed_at": 1792108700000,
        "signature": label("cose-sign1:evidence:1"),
    }],
    "versions": {"protocol": [1, 0], "schema": label("schema:act.action")},
}

rec_obs = {
    "kind": "claim",
    "type": CLAIM + "observation",
    "occurred_at": 1792109000000,
    "author": SYS,
    "basis": [label("record:schedule-rule:po-sync")],
    "visibility": vis("work", agent_context=False),
    "ledger": LEDGER,
    "concerns": sorted([W1, W2], key=enc),
    "relations": [{"rel": "references", "target": ["external", "https://erp.example/orders/PO-4471"]}],
    "versions": {"protocol": [1, 0], "schema": label("schema:claim.observation")},
}

PROC_PIN = {PROC: label("practice:procurement:2.1.0")}
rec_amend = {
    "kind": "declaration",
    "type": DECLARATION + "amend",
    "author": ALICE,
    "capacity": "own",
    "basis": sorted([label("record:commitment.promise:alice"), label("record:commitment.request:alice")], key=enc),
    "visibility": vis(),
    "ledger": LEDGER,
    "concerns": [W1],
    "relations": [{"rel": "supersedes", "target": ["record", label("record:commitment.promise:alice")]}],
    "authority": {"proof": "decision_receipt", "digest": label("access:decision-receipt:2")},
    "body": [{"part": "note", "commit": label("body:note:amend")},
             {"part": "terms", "commit": label("body:terms:amend")}],
    "params": {"effective_at": 1792195200000},
    "versions": {"protocol": [1, 0], "schema": label("schema:declaration.amend"), "practices": PROC_PIN},
    "ext": {PROC + "ext/cost_center": "CC-4410"},
}

rec_comment = {
    "kind": "claim",
    "type": PROC + "claim/comment",
    "occurred_at": 1792109050000,
    "author": ALICE,
    "visibility": vis("author"),
    "ledger": LEDGER,
    "concerns": [],
    "versions": {"protocol": [1, 0], "schema": label("schema:practice-comment"), "practices": PROC_PIN},
}

rec_consent = {
    "kind": "claim",
    "type": CLINIC + "claim/care_note",
    "occurred_at": 1792109060000,
    "author": ALICE,
    "capacity": "own",
    "visibility": vis("work", search=False),
    "ledger": LEDGER,
    "concerns": [W2],
    "body": [{"part": "note", "commit": label("body:note:care")}],
    "versions": {"protocol": [1, 0], "schema": label("schema:clinic.care-note"),
                 "practices": {CLINIC: label("practice:clinic:1.0.0")}},
    "ext": {CONSENT: label("consent-form:4471"), WARD: "B-2"},
    "critical": [CONSENT],
}

rec_decline = {
    "kind": "declaration",
    "type": DECLARATION + "decline",
    "author": SUPPLIER,
    "capacity": "own",
    "basis": [label("record:commitment.request:supplier")],
    "visibility": vis(["parties", [BUYER]]),
    "ledger": LEDGER,
    "concerns": [W2],
    "authority": {"proof": "decision_receipt", "digest": label("access:decision-receipt:3")},
    "params": {"reason": "no_capacity"},
    "versions": {"protocol": [1, 0], "schema": label("schema:declaration.decline")},
}

rec_open_gate = {
    "kind": "declaration",
    "type": DECLARATION + "open_condition",
    "author": ALICE,
    "capacity": "own",
    "basis": [label("record:commitment.promise:alice")],
    "visibility": vis(),
    "ledger": LEDGER,
    "concerns": [W1],
    "authority": {"proof": "decision_receipt", "digest": label("access:decision-receipt:4")},
    "params": {"condition_type": CORE + "condition/decision", "wait_reason": "internal",
               "gate_form": "approval", "address": BUYER, "deadline": 1792800000000,
               "criterion": PROC + "criterion/budget_approved"},
    "versions": {"protocol": [1, 0], "schema": label("schema:declaration.open_condition")},
}

CUSTOMS = PROC + "condition/customs_clearance"
rec_wait_practice = {
    "kind": "declaration",
    "type": DECLARATION + "open_condition",
    "author": SUPPLIER,
    "capacity": "own",
    "basis": [label("record:commitment.promise:supplier")],
    "visibility": vis(),
    "ledger": LEDGER,
    "concerns": [W2],
    "authority": {"proof": "decision_receipt", "digest": label("access:decision-receipt:5")},
    "params": {"condition_type": CUSTOMS, "wait_reason": "external", "deadline": "none",
               "address": "https://customs.example/ns/office/ist",
               "criterion": PROC + "criterion/customs_released"},
    "versions": {"protocol": [1, 0], "schema": label("schema:declaration.open_condition"), "practices": PROC_PIN},
}

rec_cancel_subcode = {
    "kind": "declaration",
    "type": DECLARATION + "cancel",
    "author": ALICE,
    "capacity": "own",
    "basis": [label("record:commitment.request:alice")],
    "visibility": vis(),
    "ledger": LEDGER,
    "concerns": [W1],
    "authority": {"proof": "decision_receipt", "digest": label("access:decision-receipt:6")},
    "params": {"reason": "other:" + PROC + "reason/budget_frozen"},
    "versions": {"protocol": [1, 0], "schema": label("schema:declaration.cancel")},
}

rec_inspection = {
    "kind": "claim",
    "type": PROC + "claim/inspection",
    "occurred_at": 1792109070000,
    "author": ALICE,
    "capacity": "own",
    "visibility": vis(),
    "ledger": LEDGER,
    "concerns": [W1],
    "relations": [{"rel": "references", "target": ["external", "https://erp.example/orders/PO-4471"],
                   "qualifier": PROC + "relation/inspected_order"}],
    "params": {"inspected_lot": label("lot:4471-a"), "sample_ids": ["lot-4471-a-01", "lot-4471-a-02"]},
    "versions": {"protocol": [1, 0], "schema": label("schema:procurement.inspection"), "practices": PROC_PIN},
}

records = [
    ("declaration-promise-for-principal", rec_promise, {},
     ["P-9", "P-10", "P-13", "P-15", "P-16", "P-17", "P-68", "P-71", "P-83", "E-13", "C-32"],
     "Agent promise on behalf of the buyer organisation; capacity FOR(buyer) matches on_behalf_of[0]; every Declaration is consequential, so authority is present."),
    ("act-action-fulfills", rec_act, {},
     ["P-9", "P-10", "P-14", "P-71", "P-73", "P-81", "P-82", "C-27", "C-29", "EV-3", "EV-4"],
     "Supplier Act of the core action subtype linked to its promise with derived_from and the fulfills role URI, carrying one core-typed evidence reference and no basis."),
    ("claim-observation-system", rec_obs, {"origin": "automation"},
     ["P-9", "P-71", "P-81", "C-16", "C-34", "EV-21", "INV-20", "T-66", "T-68"],
     "Automation-originated Observation by the scheduler (an Access-bound system Party) with a non-empty basis, concerning two Works, excluded from agent context."),
    ("declaration-amend-supersedes-ext", rec_amend, {},
     ["P-18", "P-19", "P-24", "P-69", "P-70", "P-80", "C-25"],
     "Amendment superseding an earlier promise, effective after its recorded_at, pinned Practice in versions, one non-critical extension the verifier does not understand (preserved, not interpreted)."),
    ("claim-comment-private", rec_comment, {},
     ["P-9", "P-13", "P-70", "P-77", "P-84", "EV-24"],
     "Practice comment subtype as a Claim mapped to observation, private to the author, no basis and no concerns, no authority."),
    ("claim-critical-ext-understood", rec_consent, {"understood": [CONSENT]},
     ["P-17", "P-19", "P-69", "C-5"],
     "Practice care note Claim with one critical and one non-critical extension; the verifier understands the critical one, so the record is admitted."),
    ("declaration-decline-parties", rec_decline, {},
     ["P-77", "P-80", "P-83", "P-85", "CM-20"],
     "Supplier declines a request with a catalog reason code, visible to the named buyer only."),
    ("declaration-open-condition-decision-gate", rec_open_gate, {},
     ["P-80", "P-84", "P-85", "P-92", "ST-10", "ST-12", "ST-27"] + D5,
     "A decision gate opened with the approval form, the addressed Party, a deadline and a criterion URI."),
    ("declaration-open-condition-practice-type", rec_wait_practice, {},
     ["P-80", "P-71", "P-92", "ST-10", "ST-11", "ST-12", "PR-3"] + D5,
     "A wait with a condition type from the pinned Practice, an external wait reason, a URI address, an explicit open-ended deadline and a criterion URI; a Practice condition type takes no gate form rule."),
    ("declaration-cancel-reason-sub-code", rec_cancel_subcode, {},
     ["P-71", "P-85", "P-93", "CM-30"] + D5,
     "Cancel with a namespaced sub-code of the catalog reason other; the sub-code reads as its parent."),
    ("claim-practice-params-digest-and-list", rec_inspection, {},
     ["P-80", "P-70", "C-27"] + D5,
     "Practice Claim whose params carry a digest scalar written as [-16, bytes] and a list of text scalars, with a Practice qualifier on references under the pinned namespace."),
]

envelope_state = {"prev": [-16, GENESIS_LEAF], "pos": 1, "recorded_at": 1792109100000}


def envelope(rec, c, rid, ingest):
    s = envelope_state
    env = {
        "record": rid,
        "ledger": LEDGER,
        "pos": s["pos"],
        "recorded_at": s["recorded_at"],
        "prev": s["prev"],
        "actor_type": c["actor_type"],
        "ingest": ingest,
    }
    if c["actor_type"]["author"][0] == "human":
        env["auth_context"] = {"ref": label("access:auth-context:alice"), "assurance": "aal2", "step_up": False}
    else:
        env["proof_commit"] = label("cose-sign1:record:%d" % s["pos"])
    eb = enc(env)
    check(eb)
    leaf = sha(b"\x00" + eb)
    s["prev"] = [-16, leaf]
    s["pos"] += 1
    s["recorded_at"] += 1000
    return env, eb, leaf


def context_for(rec, kw):
    if "effective_at" in rec.get("params", {}) and "recorded_at" not in kw:
        kw = dict(kw, recorded_at=envelope_state["recorded_at"])
    return ctx(rec, **kw)


ENVELOPE_RULES = ["P-11", "P-12", "P-21", "P-67", "P-75", "P-76", "P-100"]
out_recs = []
out_envs = []
for name, rec, kw, rules, purpose in records:
    b = enc(rec)
    c = context_for(rec, kw)
    assert semantic(rec, c) == ("accept", None), (name, semantic(rec, c))
    rid = [-16, sha(b)]
    write_cbor("SignedRecord", "record-" + name, b, "pass")
    out_recs.append({"id": "record/" + name, "rules": rules, "purpose": purpose,
                     "diag": diag(rec), "hex": b.hex(), "decoded": decoded(b), "context": c,
                     "record_digest": enc(rid).hex(), "cddl": "pass",
                     "expect": {"outcome": "accept"}})
    env, eb, leaf = envelope(rec, c, rid, "admitted")
    write_cbor("LedgerEnvelope", "envelope-" + name, eb, "pass")
    out_envs.append({"id": "envelope/" + name, "rules": ENVELOPE_RULES,
                     "diag": diag(env), "hex": eb.hex(), "decoded": decoded(eb), "leaf_hash": leaf.hex(),
                     "cddl": "pass", "expect": {"outcome": "accept"}})

write_json("records.json", {
    "file": "records.json",
    "notes": ["record_digest = det-CBOR(Digest) of SHA-256(det-CBOR(SignedRecord)), no prefix",
              "leaf_hash = SHA-256(0x00 || det-CBOR(LedgerEnvelope))",
              "proof_commit = SHA-256 of the full tagged WorkRecordCose bytes as received; these vectors carry no signatures, so proof_commit values are placeholders",
              "Digest values labelled work-vector:* are SHA-256 of ASCII placeholder strings, not real objects",
              "context holds verifier inputs that are not record bytes: origin, actor_type exactly as the envelope ActorTypeAnnotation (author and one entry per on_behalf_of party), understood_extensions, and recorded_at when the record carries params.effective_at",
              "ledger is the LedgerID of genesis.json genesis/accept; the first envelope is at pos 1 and its prev is the genesis leaf hash (P-100)",
              "PartyRef values are placeholder text until the Access Party reference byte form is fixed"],
    "records": out_recs, "envelopes": out_envs})

body_salt = bytes(range(32))
body_content = enc({"obligee": BUYER, "due": 1793318400000})
body_input = enc(["terms", "application/cbor", body_content])
digest_cases = [
    {"id": "digest/label-encoding", "rules": ["P-5", "P-67", "Access CR-1"],
     "input_hex": "", "digest_hex": sha(b"").hex(),
     "encoded_digest_hex": enc([-16, sha(b"")]).hex(),
     "note": "Digest = [-16, bstr .size 32]; -16 is SHA-256 in the IANA COSE algorithms registry (RFC 9054 COSE_Hash_V)"},
    {"id": "digest/record-id", "rules": ["P-6", "P-11", "P-79"],
     "input": "records.json record/declaration-promise-for-principal hex",
     "digest_hex": sha(enc(rec_promise)).hex(), "prefix": None},
    {"id": "digest/leaf-0x00", "rules": ["P-5", "P-67"],
     "input": "records.json envelope/declaration-promise-for-principal hex",
     "prefix_hex": "00", "digest_hex": out_envs[0]["leaf_hash"]},
    {"id": "digest/body-commit-0x03", "rules": ["P-5", "P-17", "P-68", "P-101"],
     "note": "commit = SHA-256(0x03 || salt[32] || det-CBOR([name, media_type, content])); the salt is fixed here and comes from the Rng port in production",
     "prefix_hex": "03", "salt_hex": body_salt.hex(),
     "part": {"name": "terms", "media_type": "application/cbor", "content_hex": body_content.hex()},
     "part_cbor_hex": body_input.hex(),
     "digest_hex": sha(b"\x03" + body_salt + body_input).hex()},
    {"id": "digest/wrong-alg-label", "rules": ["P-5", "P-67", "Access CR-1"],
     "encoded_digest_hex": enc([-44, sha(b"")]).hex(), "cddl": "fail",
     "expect": {"outcome": "reject", "reason": "schema:digest_alg"}},
    {"id": "digest/short-value", "rules": ["P-5", "P-67"],
     "encoded_digest_hex": enc([-16, sha(b"")[:31]]).hex(), "cddl": "fail",
     "expect": {"outcome": "reject", "reason": "schema:digest_length"}},
]
for case in digest_cases[4:]:
    write_cbor("Digest", "digest-" + case["id"].split("/")[1], bytes.fromhex(case["encoded_digest_hex"]), "fail")
write_json("digest.json", {"file": "digest.json", "cases": digest_cases})


def variant(base, **changes):
    r = json.loads(json.dumps(base, default=lambda b: {"__b": b.hex()}),
                   object_hook=lambda d: bytes.fromhex(d["__b"]) if set(d) == {"__b"} else d)
    for k, v in changes.items():
        if v is None:
            r.pop(k, None)
        else:
            r[k] = v
    return r

GENESIS_RULES = ["P-100", "P-11", "P-18", "P-27", "P-67", "Access CR-1"]
write_cbor("GenesisEnvelope", "genesis-accept", GENESIS_BYTES, "pass")
genesis_cases = [{
    "id": "genesis/accept", "rules": GENESIS_RULES,
    "purpose": "The genesis at position 0 of the ledger every records.json envelope names; nonce is a fixed placeholder for the Rng port value.",
    "diag": diag(GENESIS), "hex": GENESIS_BYTES.hex(), "decoded": decoded(GENESIS_BYTES),
    "ledger_id": {"encoded_digest_hex": enc(LEDGER).hex(), "digest_hex": LEDGER[1].hex()},
    "leaf_hash": GENESIS_LEAF.hex(), "cddl": "pass", "expect": {"outcome": "accept"}}]
genesis_rejects = [
    ("prev-present", variant(GENESIS, prev=[-16, b"\x00" * 32]), ["P-100", "P-67"], "schema:unknown_core_field"),
    ("ledger-present", variant(GENESIS, ledger=label("ledger:other")), ["P-100", "C-35"], "schema:unknown_core_field"),
    ("record-present", variant(GENESIS, record=label("record:genesis")), ["P-100"], "schema:unknown_core_field"),
    ("nonce-missing", variant(GENESIS, nonce=None), ["P-100", "T-32"], "schema:required_field"),
    ("nonce-31-bytes", variant(GENESIS, nonce=GENESIS["nonce"][:31]), ["P-100", "T-32", "P-72"], "limit_exceeded:string"),
    ("pos-1", variant(GENESIS, pos=1), ["P-100"], "schema:required_field"),
]
for name, g, rules, reason in genesis_rejects:
    b = enc(g)
    check(b)
    write_cbor("GenesisEnvelope", "genesis-reject-" + name, b, "fail")
    expect = {"outcome": "reject"}
    if reason is not None:
        expect["reason"] = reason
    genesis_cases.append({"id": "genesis-reject/" + name, "rules": rules, "diag": diag(g), "hex": b.hex(),
                          "decoded": decoded(b, g), "cddl": "fail", "expect": expect})
first_env = check(bytes.fromhex(out_envs[0]["hex"]))
envelope_rejects = [
    ("pos-0", dict(first_env, pos=0), ["P-100", "P-11"], "pass", "schema:unknown_core_field",
     "A LedgerEnvelope that claims position 0; the CDDL allows any uint, the kernel reads position 0 as the genesis schema."),
    ("prev-missing", variant(first_env, prev=None), ["P-100", "P-11"], "fail", "schema:required_field",
     "An envelope at position 1 without prev; prev is required at every position above 0."),
]
for name, e, rules, cddl, reason, purpose in envelope_rejects:
    b = enc(e)
    check(b)
    write_cbor("LedgerEnvelope", "genesis-envelope-reject-" + name, b, cddl)
    expect = {"outcome": "reject"}
    if reason is not None:
        expect["reason"] = reason
    genesis_cases.append({"id": "envelope-reject/" + name, "rules": rules, "purpose": purpose, "hex": b.hex(),
                          "decoded": decoded(b, e), "cddl": cddl, "expect": expect})
write_json("genesis.json", {
    "file": "genesis.json",
    "notes": ["ledger_id.digest_hex = SHA-256(det-CBOR(GenesisEnvelope)), no prefix; ledger_id.encoded_digest_hex is its det-CBOR Digest [-16, bstr]",
              "leaf_hash = SHA-256(0x00 || det-CBOR(GenesisEnvelope)); records.json envelope 0 carries it as prev",
              "versions.schema is the Digest of the work-record.cddl bytes (P-100 item 7); nonce is a work-vector:* placeholder for the Rng port value",
              "the kernel picks the envelope schema by pos: 0 is GenesisEnvelope, above 0 is LedgerEnvelope (P-100 item 6)"],
    "cases": genesis_cases})


amend_top_ext = variant(rec_amend, ext=None)
amend_top_ext[PROC + "ext/cost_center"] = "CC-4410"
two_critical = sorted([CONSENT, WARD], key=enc)
X = label("x")
AMEND_AT = 1792109103000
AUTO = {"origin": "automation"}


def derived(qualifier=None, rel="derived_from"):
    r = {"rel": rel, "target": ["record", X]}
    if qualifier is not None:
        r["qualifier"] = qualifier
    return [r]


def parties(*ps):
    return vis(["parties", list(ps)])


def cond(condition="decision", **changes):
    params = dict(rec_open_gate["params"], condition_type=CORE + "condition/" + condition)
    for k, v in changes.items():
        if v is None:
            params.pop(k, None)
        else:
            params[k] = v
    return params


FAMILY_PARAMS = {
    "decline": {"reason": "no_capacity"},
    "cancel": {"reason": "failed"},
    "notice": {"notice_type": "at_risk"},
    "stop_request": {"stop_type": "pause"},
    "stop_response": {"response": "accept"},
    "open_condition": {"condition_type": CORE + "condition/information", "wait_reason": "internal",
                       "address": BUYER, "deadline": "none", "criterion": PROC + "criterion/information_received"},
}
AUTHORITY_FAMILIES = (
    ("request", "CM-17"), ("cancel", "CM-30"), ("notice", "CM-17"), ("assign", "RC-17"),
    ("renew_lease", "RC-17"), ("gate_decision", "ST-25"), ("stop_request", "RC-36"),
    ("stop_response", "RC-36"), ("open_condition", "ST-12"), ("withdraw_condition", "ST-25"),
    ("resume_after_stop", "RC-40"), ("practice_adoption", "PR-13"), ("disclosure", "SEC-14"),
    ("queue_definition", "RC-10"), ("control_lease", "RC-33"), ("handoff_note", "RC-34"),
    ("conflict_resolution", "P-28"), ("admission", "FD-21"), ("autonomy_policy", "RC-27"),
    ("implicit_acceptance_terms", "CM-41"), ("waiver", "RC-9"), ("attention_request", "RC-31"),
    ("acknowledgement", "ST-48"),
)


def family_declaration(name):
    return variant(rec_amend, type=DECLARATION + name, authority=None, relations=None, ext=None,
                   params=FAMILY_PARAMS.get(name),
                   versions={"protocol": [1, 0], "schema": label("schema:declaration." + name)})


practice_declaration = variant(rec_amend, type=PROC + "declaration/approval_request", authority=None,
                               relations=None, params=None)
rejects = [
    ("declaration-authority-missing", variant(rec_promise, authority=None), {},
     ["P-13", "P-83", "C-32"], "authority_missing"),
    ("practice-declaration-authority-missing", practice_declaration, {},
     ["P-13", "P-83", "PR-3"], "authority_missing"),
    ("on-behalf-of-capacity-own", variant(rec_promise, capacity="own"), {},
     ["P-13", "E-13"], "capacity_mismatch"),
    ("on-behalf-of-capacity-other-principal", variant(rec_promise, capacity=["for", ALICE]), {},
     ["P-13", "E-13"], "capacity_mismatch"),
    ("capacity-for-without-on-behalf-of", variant(rec_promise, on_behalf_of=None), {},
     ["P-13", "E-13"], "capacity_mismatch"),
    ("ninth-relation-depends-on", variant(rec_act, relations=derived(rel="depends_on")), {},
     ["P-14", "P-73", "C-2", "C-26"], "schema:relation"),
    ("relation-name-kebab-case", variant(rec_act, relations=derived(ROLE + "fulfills", rel="derived-from")), {},
     ["P-14", "P-72", "P-85"], "schema:relation"),
    ("derived-from-without-role", variant(rec_act, relations=derived()), {},
     ["C-27", "P-73"], "schema:relation"),
    ("derived-from-short-role", variant(rec_act, relations=derived("fulfills")), {},
     ["C-27", "P-70", "P-81"], "schema:relation"),
    ("derived-from-basis-role", variant(rec_act, relations=derived(ROLE + "basis")), {},
     ["C-27", "C-32", "P-81"], "schema:relation"),
    ("derived-from-role-outside-core-catalog", variant(rec_act, relations=derived(ROLE + "causes")), {},
     ["C-27", "P-71"], "unmapped_extension_value"),
    ("empty-relations-array", variant(rec_obs, relations=[]), AUTO,
     ["P-14", "P-72"], "schema:empty_optional_list"),
    ("empty-on-behalf-of-array", variant(rec_promise, on_behalf_of=[]), {},
     ["P-13", "P-72"], "schema:empty_optional_list"),
    ("empty-correlation-array", variant(rec_promise, correlation=[]), {},
     ["P-16", "P-72"], "schema:empty_optional_list"),
    ("empty-evidence-array", variant(rec_act, evidence=[]), {},
     ["EV-3", "P-72"], "schema:empty_optional_list"),
    ("empty-body-array", variant(rec_comment, body=[]), {},
     ["P-17", "P-72"], "schema:empty_optional_list"),
    ("empty-critical-array", variant(rec_amend, critical=[]), {},
     ["P-19", "P-69", "P-72"], "schema:empty_optional_list"),
    ("empty-ext-map", variant(rec_comment, ext={}), {},
     ["P-19", "P-69"], "schema:empty_optional_map"),
    ("empty-params-map", variant(rec_promise, params={}), {},
     ["P-72", "P-80"], "schema:empty_optional_map"),
    ("act-empty-basis", variant(rec_act, basis=[]), {},
     ["P-72", "P-81"], "schema:empty_optional_list"),
    ("claim-empty-basis", variant(rec_comment, basis=[]), {},
     ["P-72", "P-81"], "schema:empty_optional_list"),
    ("declaration-missing-basis", variant(rec_amend, basis=None), {},
     ["P-10", "P-81"], "schema:required_field"),
    ("basis-65", variant(rec_amend, basis=sorted([label("b%d" % i) for i in range(65)], key=enc)), {},
     ["P-33", "T-65", "SEC-18"], "limit_exceeded:basis"),
    ("concerns-65", variant(rec_obs, concerns=sorted([bytes([0x01, 0x9a]) + i.to_bytes(14, "big") for i in range(65)])), AUTO,
     ["P-33", "T-65", "SEC-18"], "limit_exceeded:concerns"),
    ("on-behalf-of-9", variant(rec_promise, on_behalf_of=[BUYER] + ["party:acme:p%d" % i for i in range(8)]), {},
     ["P-33", "T-65", "SEC-18"], "limit_exceeded:on_behalf_of"),
    ("basis-unsorted", variant(rec_amend, basis=list(reversed(rec_amend["basis"]))), {},
     ["P-72"], "non_canonical_set_order:basis"),
    ("basis-duplicate", variant(rec_amend, basis=[rec_amend["basis"][0], rec_amend["basis"][0]]), {},
     ["P-72"], "non_canonical_set_order:basis"),
    ("concerns-unsorted", variant(rec_obs, concerns=list(reversed(rec_obs["concerns"]))), AUTO,
     ["P-72", "C-34"], "non_canonical_set_order:concerns"),
    ("concerns-duplicate", variant(rec_obs, concerns=[W1, W1]), AUTO,
     ["P-72", "C-34"], "non_canonical_set_order:concerns"),
    ("critical-unsorted", variant(rec_consent, critical=list(reversed(two_critical))), {"understood": [CONSENT, WARD]},
     ["P-69", "P-72"], "non_canonical_set_order:critical"),
    ("critical-duplicate", variant(rec_consent, critical=[CONSENT, CONSENT]), {"understood": [CONSENT]},
     ["P-69", "P-72"], "non_canonical_set_order:critical"),
    ("visibility-parties-unsorted", variant(rec_decline, visibility=parties(BUYER, ALICE)), {},
     ["P-72", "P-77"], "non_canonical_set_order:visibility"),
    ("visibility-parties-duplicate", variant(rec_decline, visibility=parties(BUYER, BUYER)), {},
     ["P-72", "P-77"], "non_canonical_set_order:visibility"),
    ("visibility-author-in-parties", variant(rec_decline, visibility=parties(*sorted([BUYER, SUPPLIER], key=enc))), {},
     ["P-77", "RC-9"], "duplicate_entry:visibility"),
    ("visibility-principal-in-parties", variant(rec_promise, visibility=parties(BUYER)), {},
     ["P-77", "RC-9"], "duplicate_entry:visibility"),
    ("visibility-work-without-concerns", variant(rec_comment, visibility=vis()), {},
     ["P-77", "EV-25"], "visibility_no_work"),
    ("duplicate-relation", variant(rec_act, relations=rec_act["relations"] * 2), {},
     ["P-78"], "duplicate_entry:relations"),
    ("duplicate-evidence", variant(rec_act, evidence=rec_act["evidence"] * 2), {},
     ["P-78", "EV-3"], "duplicate_entry:evidence"),
    ("duplicate-correlation", variant(rec_promise, correlation=rec_promise["correlation"] * 2), {},
     ["P-78", "P-16"], "duplicate_entry:correlation"),
    ("duplicate-body-part-name", variant(rec_amend, body=[rec_amend["body"][0], dict(rec_amend["body"][1], part="note")]), {},
     ["P-78", "P-68"], "duplicate_entry:body"),
    ("duplicate-on-behalf-of-party", variant(rec_promise, on_behalf_of=[BUYER, BUYER]), {},
     ["P-78", "E-13"], "duplicate_entry:on_behalf_of"),
    ("critical-without-ext-entry", variant(rec_amend, critical=[PROC + "ext/approval_chain"]), {"understood": [PROC + "ext/approval_chain"]},
     ["P-19", "P-69"], "extension_critical_dangling"),
    ("critical-without-ext-map", variant(rec_comment, critical=[PROC + "ext/approval_chain"]), {"understood": [PROC + "ext/approval_chain"]},
     ["P-19", "P-69"], "extension_critical_dangling"),
    ("extension-key-at-top-level", amend_top_ext, {},
     ["P-10", "P-69"], "schema:unknown_core_field"),
    ("ext-key-reverse-dns", variant(rec_amend, ext={"com.example.procurement/cost-center": "CC-4410"}), {},
     ["P-19", "P-70"], "schema:ext_key"),
    ("type-reverse-dns", variant(rec_comment, type="com.example.procurement/claim/comment"), {},
     ["P-9", "P-70", "PR-5"], "schema:type_uri"),
    ("type-http-scheme", variant(rec_comment, type="http://procurement.example/ns/claim/comment"), {},
     ["P-9", "P-70"], "schema:type_uri"),
    ("type-relative-uri", variant(rec_comment, type="claim/comment"), {},
     ["P-9", "P-70"], "schema:type_uri"),
    ("claim-type-unmapped-old-root", variant(rec_obs, type="https://suiss.org/work/claim/observation"), AUTO,
     ["C-16", "C-5", "PR-5", "P-71"], "unmapped_extension_value"),
    ("act-type-outside-core-catalog", variant(rec_act, type=ACT + "delivery"), {},
     ["P-71", "P-82"], "unmapped_extension_value"),
    ("declaration-type-outside-core-catalog", variant(rec_amend, type=DECLARATION + "comment"), {},
     ["C-15", "P-71", "P-84"], "unmapped_extension_value"),
    ("declaration-type-kebab-case", variant(rec_amend, type=DECLARATION + "declare-obsolete"), {},
     ["P-71", "P-85"], "unmapped_extension_value"),
    ("evidence-type-outside-core-catalog", variant(rec_act, evidence=[dict(rec_act["evidence"][0], type=EVIDENCE + "photo")]), {},
     ["EV-4", "P-71"], "unmapped_extension_value"),
    ("params-map-value", variant(rec_decline, params={"reason": {"code": "no_capacity"}}), {},
     ["P-80"], "schema:params"),
    ("params-key-not-in-subtype-schema", variant(rec_amend, params={"effective_at": 1792195200000, "stop_type": "pause"}), {},
     ["P-80"], "schema:params"),
    ("params-reason-outside-catalog", variant(rec_decline, params={"reason": "busy"}), {},
     ["P-80", "P-85", "CM-20"], "schema:params"),
    ("params-effective-at-on-claim", variant(rec_obs, params={"effective_at": 1792195200000}), AUTO,
     ["P-80"], "schema:params"),
    ("retroactive-declaration", variant(rec_amend, params={"effective_at": AMEND_AT - 1}), {"recorded_at": AMEND_AT},
     ["P-80", "P-24", "INV-4"], "retroactive_declaration"),
    ("automation-without-basis", variant(rec_obs, basis=None), AUTO,
     ["INV-20", "P-81", "T-66", "T-68"], "unattributed_automation"),
    ("automation-human-author", variant(rec_comment, concerns=[W1], basis=[X]), AUTO,
     ["INV-20", "P-12", "T-66", "T-68"], "unattributed_automation"),
    ("automation-unverified-system-author", rec_obs, dict(AUTO, actor=["system", "declared_unverified"]),
     ["INV-20", "P-12", "T-68"], "unattributed_automation"),
    ("claim-missing-occurred-at", variant(rec_obs, occurred_at=None), AUTO,
     ["P-10"], "schema:required_field"),
    ("unknown-kind", variant(rec_obs, kind="event"), AUTO,
     ["P-9", "C-31"], "schema:kind"),
    ("confidence-field", variant(rec_obs, confidence=93), AUTO,
     ["P-10", "C-16", "C-32"], "schema:unknown_core_field"),
    ("declaration-capacity-missing", variant(rec_amend, capacity=None), {},
     ["P-13", "P-83"] + D4, "capacity_missing"),
    ("producer-missing", variant(rec_promise, producer=None), {},
     ["P-15", "C-23"], "producer_missing"),
    ("actor-type-rings-mismatch", rec_promise, {"rings": 0},
     ["P-12", "INV-18"], "envelope_mismatch:actor_type"),
    ("unpinned-practice-act-subtype", variant(rec_act, type=PROC + "act/delivery"), {},
     ["P-71", "P-82", "C-5", "PR-3"], "unmapped_extension_value"),
    ("unpinned-practice-derived-from-role", variant(rec_act, relations=derived(PROC + "role/backs")), {},
     ["C-5", "C-27", "P-71"], "unmapped_extension_value"),
    ("core-qualifier-on-references", variant(rec_obs, relations=[dict(rec_obs["relations"][0], qualifier=ROLE + "supports")]), AUTO,
     ["C-27", "P-14", "P-73"], "schema:relation"),
    ("unpinned-practice-qualifier-on-references", variant(rec_obs, relations=[dict(rec_obs["relations"][0], qualifier=PROC + "relation/source_document")]), AUTO,
     ["C-5", "C-27", "P-71"], "unmapped_extension_value"),
    ("params-on-core-act", variant(rec_act, params={"delivery_note": "dn-4471"}), {},
     ["P-80", "P-82"], "schema:params"),
    ("decline-reason-missing", variant(rec_decline, params=None), {},
     ["P-80", "P-85", "CM-20"] + D5, "schema:params"),
    ("cancel-reason-missing", variant(rec_cancel_subcode, params=None), {},
     ["P-80", "CM-30"] + D5, "schema:params"),
    ("notice-type-missing", variant(rec_decline, type=DECLARATION + "notice", params=None), {},
     ["P-80", "CM-17"] + D5, "schema:params"),
    ("stop-type-missing", variant(rec_decline, type=DECLARATION + "stop_request", params=None), {},
     ["P-80", "P-85", "RC-36"] + D5, "schema:params"),
    ("stop-response-missing", variant(rec_decline, type=DECLARATION + "stop_response", params=None), {},
     ["P-80", "P-84", "P-85", "RC-36"] + D5, "schema:params"),
    ("open-condition-wait-reason-missing", variant(rec_open_gate, params=cond(wait_reason=None)), {},
     ["P-80", "P-85", "ST-11", "ST-12"] + D5, "schema:params"),
    ("open-condition-type-missing", variant(rec_open_gate, params=cond(condition_type=None)), {},
     ["P-80", "ST-10", "ST-12"] + D5, "schema:params"),
    ("acceptance-gate-form-missing", variant(rec_open_gate, params=cond("acceptance", gate_form=None)), {},
     ["P-85", "ST-27"] + D5, "schema:params"),
    ("acceptance-gate-form-approval", variant(rec_open_gate, params=cond("acceptance")), {},
     ["P-85", "ST-27"] + D5, "schema:params"),
    ("decision-gate-form-delivery-acceptance", variant(rec_open_gate, params=cond(gate_form="delivery_acceptance")), {},
     ["P-85", "ST-27"] + D5, "schema:params"),
    ("resource-gate-form-missing", variant(rec_open_gate, params=cond("resource", gate_form=None)), {},
     ["P-85", "ST-27"] + D5, "schema:params"),
    ("authority-gate-form-forbidden", variant(rec_open_gate, params=cond("authority")), {},
     ["P-85", "ST-27"] + D5, "schema:params"),
    ("epistemic-gate-form-forbidden", variant(rec_open_gate, params=cond("information")), {},
     ["P-85", "ST-10", "ST-27"] + D5, "schema:params"),
    ("gate-form-outside-catalog", variant(rec_open_gate, params=cond(gate_form="sign_off")), {},
     ["P-85", "ST-27"] + D5, "schema:params"),
    ("open-condition-address-missing", variant(rec_open_gate, params=cond(address=None)), {},
     ["P-92", "ST-12"] + D5, "schema:params"),
    ("open-condition-deadline-missing", variant(rec_open_gate, params=cond(deadline=None)), {},
     ["P-92", "ST-12"] + D5, "schema:params"),
    ("open-condition-criterion-missing", variant(rec_open_gate, params=cond(criterion=None)), {},
     ["P-92", "ST-12"] + D5, "schema:params"),
    ("stop-type-sub-code", variant(rec_decline, type=DECLARATION + "stop_request", params={"stop_type": "pause:" + PROC + "stop/shift_end"}), {},
     ["P-92", "P-93", "RC-36"] + D5, "schema:params"),
    ("stop-response-sub-code", variant(rec_decline, type=DECLARATION + "stop_response", params={"response": "refuse:" + PROC + "stop/safety"}), {},
     ["P-92", "P-93", "RC-36"] + D5, "schema:params"),
    ("wait-reason-sub-code", variant(rec_open_gate, params=cond(wait_reason="internal:" + PROC + "wait/review")), {},
     ["P-92", "P-93", "ST-11"] + D5, "schema:params"),
    ("gate-form-sub-code", variant(rec_open_gate, params=cond(gate_form="approval:" + PROC + "gate/board")), {},
     ["P-92", "P-93", "ST-27"] + D5, "schema:params"),
    ("open-condition-address-not-text", variant(rec_open_gate, params=cond(address=42)), {},
     ["P-80", "ST-12"] + D5, "schema:params"),
    ("open-condition-deadline-word", variant(rec_open_gate, params=cond(deadline="never")), {},
     ["P-80", "ST-12"] + D5, "schema:params"),
    ("open-condition-criterion-http", variant(rec_open_gate, params=cond(criterion="http://procurement.example/ns/criterion/x")), {},
     ["P-70", "P-80", "ST-12"] + D5, "schema:params"),
    ("open-condition-unpinned-practice-type", variant(rec_wait_practice, versions={k: v for k, v in rec_wait_practice["versions"].items() if k != "practices"}), {},
     ["P-71", "ST-10", "PR-3"] + D5, "schema:params"),
    ("reason-sub-code-unknown-parent", variant(rec_cancel_subcode, params={"reason": "busy:" + PROC + "reason/busy"}), {},
     ["P-71", "P-85"] + D5, "schema:params"),
    ("reason-sub-code-not-uri", variant(rec_cancel_subcode, params={"reason": "other:busy"}), {},
     ["P-70", "P-71"] + D5, "schema:params"),
    ("practice-param-text-too-long", variant(rec_inspection, params={"note_code": "n" * 300}), {},
     ["P-17", "P-80"] + D5, "schema:params"),
    ("correlation-257-items", variant(rec_promise, correlation=[["https://a2a-protocol.org/context-id", "ctx-%d" % i] for i in range(257)]), {},
     ["P-7", "P-16", "SEC-18"] + D4, "limit_exceeded:items"),
    ("params-list-257-items", variant(rec_inspection, params={"sample_ids": ["lot-%d" % i for i in range(257)]}), {},
     ["P-7", "P-80", "SEC-18"] + D4, "limit_exceeded:items"),
    ("author-256-bytes", variant(rec_comment, author="party:acme:" + "a" * 245), {"actor": ["human", "access_binding"]},
     ["P-67", "P-72"] + D4, "limit_exceeded:string"),
    ("author-empty", variant(rec_comment, author=""), {"actor": ["human", "access_binding"]},
     ["P-67", "P-72"] + D4, "limit_exceeded:string"),
    ("producer-version-256-bytes", variant(rec_promise, producer=dict(rec_promise["producer"], version="v" * 256)), {},
     ["P-15", "C-23"] + D4, "limit_exceeded:string"),
    ("correlation-id-1025-bytes", variant(rec_promise, correlation=[["https://a2a-protocol.org/context-id", "c" * 1025]]), {},
     ["P-16"] + D4, "limit_exceeded:string"),
    ("visibility-search-true", variant(rec_consent, visibility=vis("work", search=True)), {"understood": [CONSENT]},
     ["P-77", "EV-21"], "schema:required_field"),
    ("visibility-agent-context-true", variant(rec_obs, visibility=vis("work", agent_context=True)), AUTO,
     ["P-77", "EV-21"], "schema:required_field"),
    ("audience-outside-vocabulary", variant(rec_obs, visibility=vis("everyone")), AUTO,
     ["P-77", "EV-21", "EV-24"], "schema:required_field"),
    ("visibility-unknown-key", variant(rec_obs, visibility=vis("work", index=False)), AUTO,
     ["P-10", "P-77"], "schema:unknown_core_field"),
    ("relation-unknown-key", variant(rec_obs, relations=[dict(rec_obs["relations"][0], weight=1)]), AUTO,
     ["P-73", "C-25"], "schema:unknown_core_field"),
    ("authority-unknown-key", variant(rec_promise, authority=dict(rec_promise["authority"], scope="all")), {},
     ["P-10", "P-13"], "schema:unknown_core_field"),
    ("producer-unknown-key", variant(rec_promise, producer=dict(rec_promise["producer"], temperature=0)), {},
     ["P-10", "P-15"], "schema:unknown_core_field"),
    ("evidence-unknown-key", variant(rec_act, evidence=[dict(rec_act["evidence"][0], confidence=93)]), {},
     ["EV-3", "C-16"], "schema:unknown_core_field"),
    ("body-unknown-key", variant(rec_amend, body=[dict(rec_amend["body"][0], media_type="text/plain"), rec_amend["body"][1]]), {},
     ["P-17", "P-68"], "schema:unknown_core_field"),
    ("versions-unknown-key", variant(rec_comment, versions=dict(rec_comment["versions"], kernel="0.3")), {},
     ["P-18"], "schema:unknown_core_field"),
] + [
    ("endpoint-" + name, variant(rec_act, relations=[rel]), {}, ["P-73", "C-25"], "schema:relation")
    for name, rel in (
        ("engaged-in-source-work", {"rel": "engaged_in", "source": ["work", W1], "target": ["work", W1]}),
        ("concerns-source-party", {"rel": "concerns", "source": ["party", BUYER], "target": ["work", W1]}),
        ("part-of-target-record", {"rel": "part_of", "source": ["work", W1], "target": ["record", X]}),
        ("serves-target-work", {"rel": "serves", "target": ["work", W1]}),
        ("supersedes-with-source", {"rel": "supersedes", "source": ["record", X], "target": ["record", X]}),
        ("derived-from-target-party", {"rel": "derived_from", "target": ["party", BUYER], "qualifier": ROLE + "fulfills"}),
        ("on-behalf-of-target-work", {"rel": "on_behalf_of", "source": ["party", BUYER], "target": ["work", W1]}),
        ("references-target-work", {"rel": "references", "target": ["work", W1]}),
        ("three-elements", {"rel": "references", "target": ["record", X, "extra"]}),
        ("qualifier-not-text", {"rel": "references", "target": ["record", X], "qualifier": 7}),
    )
] + [
    ("declaration-without-authority-" + name, family_declaration(name), {}, ["P-13", "P-83", "C-32", rule], "authority_missing")
    for name, rule in AUTHORITY_FAMILIES
]
CDDL_FAIL = ("schema:empty", "schema:relation", "schema:required_field", "schema:unknown_core_field",
             "schema:ext_key", "schema:type_uri", "schema:kind", "limit_exceeded:", "capacity_missing")
CDDL_FAIL_CASES = {"params-map-value", "practice-param-text-too-long"}
CDDL_PASS_CASES = {"core-qualifier-on-references"}
DECODER_REASONS = ("schema:empty", "schema:relation", "schema:required_field", "schema:unknown_core_field",
                   "schema:ext_key", "schema:type_uri", "schema:kind", "limit_exceeded:items",
                   "limit_exceeded:string", "limit_exceeded:depth")
out_rej = []
for name, rec, kw, rules, reason in rejects:
    b = enc(rec)
    c = ctx(rec, **kw)
    cddl = "fail" if (reason.startswith(CDDL_FAIL) or name in CDDL_FAIL_CASES) and name not in CDDL_PASS_CASES else "pass"
    if not reason.startswith(DECODER_REASONS):
        assert semantic(rec, c) == ("reject", reason), (name, semantic(rec, c))
    write_cbor("SignedRecord", "reject-" + name, b, cddl)
    out_rej.append({"id": "record-reject/" + name, "rules": rules, "hex": b.hex(), "decoded": decoded(b, rec),
                    "context": c, "cddl": cddl, "expect": {"outcome": "reject", "reason": reason}})

write_json("records-reject.json", {
    "file": "records-reject.json",
    "notes": ["each case is a single-field mutation of a records.json example; hex is canonical CBOR, so rejection is semantic or schema-level, never encoding-level",
              "cddl = fail means work-record.cddl alone rejects the bytes; cddl = pass means a kernel rule rejects them",
              "context holds verifier inputs that are not record bytes (origin, actor_type as the envelope ActorTypeAnnotation with one entry per on_behalf_of party, understood_extensions, recorded_at)"],
    "cases": out_rej})

V2 = dict(rec_comment["versions"], protocol=[2, 0])
v2_new_field = variant(rec_comment, versions=V2)
v2_new_field["priority"] = 3
v2_new_kind = variant(rec_comment, kind="event", versions=V2)
quarantine = [
    ("critical-ext-not-understood", rec_consent, {},
     ["P-19", "P-69", "C-5"],
     "Same bytes as record/claim-critical-ext-understood; this verifier does not understand the critical extension.",
     "extension_critical_unknown"),
    ("one-of-two-critical-not-understood", variant(rec_consent, critical=two_critical), {"understood": [CONSENT]},
     ["P-19", "P-69"],
     "Two critical extensions, the verifier understands only one.",
     "extension_critical_unknown"),
    ("protocol-version-unknown",
     variant(rec_promise, authority=None, versions=dict(rec_promise["versions"], protocol=[2, 0])), {},
     ["T-4", "P-18", "P-19", "P-87"],
     "Protocol 2.0 has no rule set in this verifier; the record is quarantined before any other rule, so the missing authority is not judged.",
     "protocol_version_unknown"),
    ("protocol-version-unknown-new-field", v2_new_field, {},
     ["T-4", "P-18", "P-87"] + D7,
     "A protocol 2.0 record with a top-level field protocol 1.0 does not define; the decoder reads versions.protocol first, so the field is not judged as unknown.",
     "protocol_version_unknown"),
    ("protocol-version-unknown-new-kind", v2_new_kind, {},
     ["T-4", "P-9", "P-87"] + D7,
     "A protocol 2.0 record of a kind protocol 1.0 does not define; it is quarantined, not rejected as schema:kind.",
     "protocol_version_unknown"),
]
out_q = []
for name, rec, kw, rules, purpose, reason in quarantine:
    b = enc(rec)
    c = ctx(rec, **kw)
    assert semantic(rec, c) == ("quarantine", reason), name
    rid = [-16, sha(b)]
    cddl = "pass" if rec["versions"]["protocol"] in KNOWN_PROTOCOLS else "fail"
    write_cbor("SignedRecord", "quarantine-" + name, b, cddl)
    env, eb, leaf = envelope(rec, c, rid, ["quarantined", reason])
    write_cbor("LedgerEnvelope", "quarantine-envelope-" + name, eb, "pass")
    out_q.append({"id": "record-quarantine/" + name, "rules": rules, "purpose": purpose,
                  "hex": b.hex(), "decoded": decoded(b), "context": c, "record_digest": enc(rid).hex(),
                  "cddl": cddl,
                  "envelope": {"rules": ENVELOPE_RULES, "diag": diag(env), "hex": eb.hex(), "decoded": decoded(eb),
                               "leaf_hash": leaf.hex(), "cddl": "pass"},
                  "expect": {"outcome": "quarantine", "reason": reason}})

write_json("records-quarantine.json", {
    "file": "records-quarantine.json",
    "notes": ["a quarantined record is still written to the ledger; its envelope carries ingest [\"quarantined\", reason] and continues the records.json chain"],
    "cases": out_q})

if CBOR_OUT is not None:
    with open(os.path.join(CBOR_OUT, "manifest"), "w") as f:
        f.write("\n".join(manifest) + "\n")
