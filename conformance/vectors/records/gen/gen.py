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
            raise Reject("non_canonical_cbor:indefinite_length" if ai == 31 else "malformed_cbor:reserved_ai")
        if pos + size > len(data):
            raise Reject("malformed_cbor:truncated")
        n = int.from_bytes(data[pos:pos + size], "big")
        pos += size
        if n < {1: 24, 2: 0x100, 4: 0x10000, 8: 0x100000000}[size]:
            raise Reject("non_canonical_cbor:non_preferred_argument")
        return n

    def item(depth):
        nonlocal pos
        if depth > MAX_DEPTH:
            raise Reject("limit_exceeded:depth")
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
            return [item(depth + 1) for _ in range(n)]
        if major == 5:
            if n > MAX_ITEMS:
                raise Reject("limit_exceeded:items")
            out, prev = {}, None
            for _ in range(n):
                start = pos
                k = item(depth + 1)
                kb = bytes(data[start:pos])
                if prev is not None:
                    if kb == prev:
                        raise Reject("non_canonical_cbor:duplicate_map_key")
                    if kb < prev:
                        raise Reject("non_canonical_cbor:unsorted_map_keys")
                prev = kb
                out[k if not isinstance(k, list) else tuple(k)] = item(depth + 1)
            return out
        if major == 6:
            if n not in allowed_tags:
                raise Reject("non_canonical_cbor:tag_not_allowed")
            return Tag(n, item(depth + 1))
        raise Reject("malformed_cbor")

    v = item(1)
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


def decoded(b):
    return project(check(b))


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
CORE = "https://suiss.app/ns/work/"
DECLARATION = CORE + "declaration/"
ACT = CORE + "act/"
CLAIM = CORE + "claim/"
EVIDENCE = CORE + "evidence/"
ROLE = CORE + "derived_from/"
PROC = "https://procurement.example/ns/"
CLINIC = "https://clinic.example/ns/"
LEDGER = label("ledger-genesis")
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
                       "gate_form": {"approval", "pre_action_review", "delivery_acceptance"}},
}
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
    ("depth-16", (b"\x81" * 15 + b"\x00").hex(), "accept", None, "P-7"),
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
    ("array-257-items", big_array(257).hex(), "reject", "limit_exceeded:items", "P-7"),
    ("depth-17", (b"\x81" * 16 + b"\x00").hex(), "reject", "limit_exceeded:depth", "P-7"),
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


def semantic(rec, ctx):
    see = rec["visibility"]["see"]
    parties = see[1] if isinstance(see, list) else []
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
    if rec["kind"] == "declaration" and "authority" not in rec:
        return ("reject", "authority_missing")
    if rec["type"].startswith(CORE):
        if rec["type"] not in CORE_TYPES:
            return ("reject", "unmapped_extension_value")
    elif not rec["type"].startswith(tuple(rec["versions"].get("practices", {}))):
        return ("reject", "unmapped_extension_value")
    for r in rec.get("relations", []):
        q = r.get("qualifier", "")
        if r["rel"] == "derived_from" and q.startswith(CORE) and q not in CORE_ROLES:
            return ("reject", "unmapped_extension_value")
    for e in rec.get("evidence", []):
        if e["type"].startswith(CORE) and e["type"] not in CORE_EVIDENCE:
            return ("reject", "unmapped_extension_value")
    params = rec.get("params", {})
    if "effective_at" in params and rec["kind"] != "declaration":
        return ("reject", "schema:params")
    if rec["type"].startswith(DECLARATION):
        allowed = PARAMS.get(rec["type"][len(DECLARATION):], {})
        for k, v in params.items():
            if k != "effective_at" and (k not in allowed or v not in allowed[k]):
                return ("reject", "schema:params")
    if params.get("effective_at", ctx.get("recorded_at", 0)) < ctx.get("recorded_at", 0):
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


def ctx(rec, origin="direct", understood=(), actor=None, recorded_at=None):
    c = {"origin": origin,
         "actor_type": {"author": actor or [ACTOR[rec["author"]], "access_binding"]},
         "understood_extensions": list(understood)}
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
]

envelope_state = {"prev": [-16, b"\x00" * 32], "pos": 41, "recorded_at": 1792109100000}


def envelope(rec, c, rid, ingest):
    s = envelope_state
    env = {
        "record": rid,
        "ledger": LEDGER,
        "pos": s["pos"],
        "recorded_at": s["recorded_at"],
        "prev": s["prev"],
        "actor_type": {"author": c["actor_type"]["author"]},
        "ingest": ingest,
    }
    if "on_behalf_of" in rec:
        env["actor_type"]["on_behalf_of"] = [["organization", "access_binding"] for _ in rec["on_behalf_of"]]
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


ENVELOPE_RULES = ["P-11", "P-12", "P-21", "P-67", "P-75", "P-76"]
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
              "context holds verifier inputs that are not record bytes: origin, the author actor type from the Access binding, understood_extensions, and recorded_at when the record carries params.effective_at",
              "prev of the first envelope is the all-zero placeholder until suiss-ledger fixes the genesis rule",
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
    {"id": "digest/body-commit-0x02", "rules": ["P-5", "P-17", "P-68"],
     "note": "commit = SHA-256(0x02 || salt[32] || det-CBOR([name, media_type, content])); the salt is fixed here and comes from the Rng port in production",
     "prefix_hex": "02", "salt_hex": body_salt.hex(),
     "part": {"name": "terms", "media_type": "application/cbor", "content_hex": body_content.hex()},
     "part_cbor_hex": body_input.hex(),
     "digest_hex": sha(b"\x02" + body_salt + body_input).hex()},
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
]
CDDL_FAIL = ("schema:empty", "schema:relation", "schema:required_field", "schema:unknown_core_field",
             "schema:ext_key", "schema:type_uri", "schema:kind", "limit_exceeded:")
CDDL_FAIL_CASES = {"params-map-value"}
out_rej = []
for name, rec, kw, rules, reason in rejects:
    b = enc(rec)
    c = ctx(rec, **kw)
    cddl = "fail" if reason.startswith(CDDL_FAIL) or name in CDDL_FAIL_CASES else "pass"
    if cddl == "pass":
        assert semantic(rec, c) == ("reject", reason), (name, semantic(rec, c))
    write_cbor("SignedRecord", "reject-" + name, b, cddl)
    out_rej.append({"id": "record-reject/" + name, "rules": rules, "hex": b.hex(), "decoded": decoded(b),
                    "context": c, "cddl": cddl, "expect": {"outcome": "reject", "reason": reason}})

write_json("records-reject.json", {
    "file": "records-reject.json",
    "notes": ["each case is a single-field mutation of a records.json example; hex is canonical CBOR, so rejection is semantic or schema-level, never encoding-level",
              "cddl = fail means work-record.cddl alone rejects the bytes; cddl = pass means a kernel rule rejects them",
              "context holds verifier inputs that are not record bytes (origin, author actor type, understood_extensions, recorded_at)"],
    "cases": out_rej})

quarantine = [
    ("critical-ext-not-understood", rec_consent, {},
     ["P-19", "P-69", "C-5"],
     "Same bytes as record/claim-critical-ext-understood; this verifier does not understand the critical extension."),
    ("one-of-two-critical-not-understood", variant(rec_consent, critical=two_critical), {"understood": [CONSENT]},
     ["P-19", "P-69"],
     "Two critical extensions, the verifier understands only one."),
]
out_q = []
for name, rec, kw, rules, purpose in quarantine:
    b = enc(rec)
    c = ctx(rec, **kw)
    assert semantic(rec, c) == ("quarantine", "extension_critical_unknown"), name
    rid = [-16, sha(b)]
    write_cbor("SignedRecord", "quarantine-" + name, b, "pass")
    env, eb, leaf = envelope(rec, c, rid, ["quarantined", "extension_critical_unknown"])
    write_cbor("LedgerEnvelope", "quarantine-envelope-" + name, eb, "pass")
    out_q.append({"id": "record-quarantine/" + name, "rules": rules, "purpose": purpose,
                  "hex": b.hex(), "decoded": decoded(b), "context": c, "record_digest": enc(rid).hex(),
                  "cddl": "pass",
                  "envelope": {"rules": ENVELOPE_RULES, "diag": diag(env), "hex": eb.hex(), "decoded": decoded(eb),
                               "leaf_hash": leaf.hex(), "cddl": "pass"},
                  "expect": {"outcome": "quarantine", "reason": "extension_critical_unknown"}})

write_json("records-quarantine.json", {
    "file": "records-quarantine.json",
    "notes": ["a quarantined record is still written to the ledger; its envelope carries ingest [\"quarantined\", reason] and continues the records.json chain"],
    "cases": out_q})

if CBOR_OUT is not None:
    with open(os.path.join(CBOR_OUT, "manifest"), "w") as f:
        f.write("\n".join(manifest) + "\n")
