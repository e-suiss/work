# P-5 P-11 P-67 P-72
import base64
import hashlib
import hmac
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


# P-6 P-75 P-76
ED_P = 2 ** 255 - 19
ED_L = 2 ** 252 + 27742317777372353535851937790883648493
ED_D = -121665 * pow(121666, ED_P - 2, ED_P) % ED_P


def _ed_add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    p, q = (y1 - x1) * (y2 - x2) % ED_P, (y1 + x1) * (y2 + x2) % ED_P
    r, s = 2 * t1 * t2 * ED_D % ED_P, 2 * z1 * z2 % ED_P
    e, f, g, h = q - p, s - r, s + r, q + p
    return (e * f % ED_P, g * h % ED_P, f * g % ED_P, e * h % ED_P)


def _ed_mul(n, point):
    out = (0, 1, 1, 0)
    while n:
        if n & 1:
            out = _ed_add(out, point)
        point = _ed_add(point, point)
        n >>= 1
    return out


def _ed_base():
    y = 4 * pow(5, ED_P - 2, ED_P) % ED_P
    x2 = (y * y - 1) * pow(ED_D * y * y + 1, ED_P - 2, ED_P) % ED_P
    x = pow(x2, (ED_P + 3) // 8, ED_P)
    if (x * x - x2) % ED_P:
        x = x * pow(2, (ED_P - 1) // 4, ED_P) % ED_P
    x = ED_P - x if x & 1 else x
    return (x, y, 1, x * y % ED_P)


def _ed_point(point):
    x, y, z, _ = point
    zi = pow(z, ED_P - 2, ED_P)
    return ((y * zi % ED_P) | ((x * zi % ED_P & 1) << 255)).to_bytes(32, "little")


def ed25519(seed, message):
    h = hashlib.sha512(seed).digest()
    a = (int.from_bytes(h[:32], "little") & ((1 << 254) - 8)) | (1 << 254)
    public = _ed_point(_ed_mul(a, _ed_base()))
    r = int.from_bytes(hashlib.sha512(h[32:] + message).digest(), "little") % ED_L
    big_r = _ed_point(_ed_mul(r, _ed_base()))
    k = int.from_bytes(hashlib.sha512(big_r + public + message).digest(), "little") % ED_L
    return public, big_r + ((r + k * a) % ED_L).to_bytes(32, "little")


# P-6 P-7 Access CR-9
P256_P = 2 ** 256 - 2 ** 224 + 2 ** 192 + 2 ** 96 - 1
P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
P256_G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
          0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


def _p256_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    (x1, y1), (x2, y2) = a, b
    if x1 == x2 and (y1 + y2) % P256_P == 0:
        return None
    if a == b:
        m = (3 * x1 * x1 - 3) * pow(2 * y1, P256_P - 2, P256_P) % P256_P
    else:
        m = (y2 - y1) * pow(x2 - x1, P256_P - 2, P256_P) % P256_P
    x3 = (m * m - x1 - x2) % P256_P
    return (x3, (m * (x1 - x3) - y1) % P256_P)


def _p256_mul(n, point):
    out = None
    while n:
        if n & 1:
            out = _p256_add(out, point)
        point = _p256_add(point, point)
        n >>= 1
    return out


def p256_public(x):
    px, py = _p256_mul(x, P256_G)
    return b"\x04" + px.to_bytes(32, "big") + py.to_bytes(32, "big")


def _rfc6979_k(x, h1):
    xo = x.to_bytes(32, "big")
    ho = (int.from_bytes(h1, "big") % P256_N).to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + xo + ho, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + xo + ho, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        t = int.from_bytes(v, "big")
        if 1 <= t < P256_N:
            return t
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def p256_sign(x, message, low_s=True):
    h1 = hashlib.sha256(message).digest()
    e = int.from_bytes(h1, "big")
    k = _rfc6979_k(x, h1)
    r = _p256_mul(k, P256_G)[0] % P256_N
    s = pow(k, P256_N - 2, P256_N) * (e + r * x) % P256_N
    if low_s and s > P256_N // 2:
        s = P256_N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


RFC6979_X = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
assert p256_public(RFC6979_X).hex() == ("0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
                                        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299")
assert p256_sign(RFC6979_X, b"sample", low_s=False).hex() == (
    "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
    "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8")
assert p256_sign(RFC6979_X, b"test", low_s=False).hex() == (
    "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367"
    "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083")


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
    "acknowledgement redact"
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
# P-111
REDACT_REASONS = {"personal_data", "secret_exposure", "legal_order", "author_request"}
REDACT_KEYS = {"target", "parts", "reason"}
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


# P-111 P-68 P-72
def part_name_ok(v):
    return (isinstance(v, str) and 1 <= len(v) <= 64 and "a" <= v[0] <= "z"
            and all(c in "abcdefghijklmnopqrstuvwxyz0123456789_" for c in v))


def redact_params_ok(params):
    if set(params) != REDACT_KEYS:
        return False
    target, parts = params["target"], params["parts"]
    return (isinstance(target, list) and target[:1] == [-16]
            and isinstance(parts, list) and parts[:1] != [-16] and len(parts) >= 1
            and all(part_name_ok(p) for p in parts) and ordered(parts)
            and isinstance(params["reason"], str) and params["reason"] in REDACT_REASONS)


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
    if name == "redact":
        return redact_params_ok(params)
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
    if len(ctx["actor_type"].get("evidence", [])) != len(rec.get("evidence", [])):
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
    if rec["type"] == DECLARATION + "redact" and any(r["rel"] == "supersedes" for r in rec.get("relations", [])):
        return ("reject", "schema:relation")
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


def presenter_entry(e):
    return [ACTOR.get(e.get("presenter") if isinstance(e, dict) else None, "organization"), "access_binding"]


# EV-35
def ctx(rec, origin="direct", understood=(), actor=None, recorded_at=None, rings=None, presenters=None):
    actors = {"author": actor or [ACTOR[rec["author"]], "access_binding"]}
    rings = len(rec.get("on_behalf_of", [])) if rings is None else rings
    if rings:
        actors["on_behalf_of"] = [["organization", "access_binding"] for _ in range(rings)]
    if presenters is None:
        presenters = [presenter_entry(e) for e in rec.get("evidence", [])]
    if presenters:
        actors["evidence"] = presenters
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

# P-111 P-25 P-79
PROMISE_ID = [-16, sha(enc(rec_promise))]
rec_redact = {
    "kind": "declaration",
    "type": DECLARATION + "redact",
    "author": ALICE,
    "capacity": "own",
    "basis": [],
    "visibility": vis(),
    "ledger": LEDGER,
    "concerns": [W1],
    "authority": {"proof": "decision_receipt", "digest": label("access:decision-receipt:7")},
    "params": {"target": PROMISE_ID, "parts": ["terms"], "reason": "personal_data"},
    "versions": {"protocol": [1, 0], "schema": label("schema:declaration.redact")},
}
REDACT_ID = [-16, sha(enc(rec_redact))]
rec_redact_absent = dict(rec_redact, params=dict(rec_redact["params"], target=label("record:absent"),
                                                 reason="legal_order"))
rec_redact_unknown_part = dict(rec_redact, params=dict(rec_redact["params"], parts=["note", "terms"],
                                                       reason="author_request"))
rec_after_redact = {
    "kind": "declaration",
    "type": DECLARATION + "amend",
    "author": ALICE,
    "capacity": "own",
    "basis": [REDACT_ID],
    "visibility": vis(),
    "ledger": LEDGER,
    "concerns": [W1],
    "relations": [{"rel": "supersedes", "target": ["record", REDACT_ID]}],
    "authority": {"proof": "decision_receipt", "digest": label("access:decision-receipt:8")},
    "versions": {"protocol": [1, 0], "schema": label("schema:declaration.amend")},
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
    ("declaration-redact", rec_redact, {},
     ["P-111", "P-25", "P-79", "P-80", "P-83", "P-92"],
     "Redaction of the terms part of the promise at position 1, named by its record ID; the reason class is in params, so it stays readable after the redaction."),
    ("declaration-redact-target-absent", rec_redact_absent, {},
     ["P-111", "P-86"],
     "Redaction naming a record this ledger does not hold; it is admitted and derivation gives it no effect (unknown_target)."),
    ("declaration-redact-part-unknown", rec_redact_unknown_part, {},
     ["P-111"],
     "Redaction naming a part the promise body does not commit; it is admitted and derivation gives it no effect (unknown_target)."),
    ("declaration-supersedes-redact", rec_after_redact, {},
     ["P-111", "P-24"],
     "Amendment superseding the redaction; it is admitted, restores no part and derivation gives it no effect (terminal_outcome)."),
]

# P-6 P-7 P-75 P-76 P-102 P-105
RFC8032_SEEDS = (bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
                 bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
                 bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"))
RECORD_CONTENT_TYPE = "application/work-record+cbor"
SIGNERS = {
    AGENT: {"id": "agent-ed25519", "alg": -19, "kid": b"\x11" * 32, "seed": RFC8032_SEEDS[0],
            "source": "RFC 8032 section 7.1 test 1"},
    SYS: {"id": "system-ed25519", "alg": -19, "kid": b"\x12" * 32, "seed": RFC8032_SEEDS[1],
          "source": "RFC 8032 section 7.1 test 2"},
    SUPPLIER: {"id": "supplier-esp256", "alg": -9, "kid": b"\x22" * 32, "x": RFC6979_X,
               "source": "RFC 6979 appendix A.2.5"},
}


def public_key(signer):
    if signer["alg"] == -19:
        return ed25519(signer["seed"], b"")[0]
    return p256_public(signer["x"])


def protected_header(alg, kid):
    return enc({1: alg, 3: RECORD_CONTENT_TYPE, 4: kid})


def sig_structure(protected, payload):
    return enc(["Signature1", protected, b"", payload])


def raw_sign(signer, message):
    if signer["alg"] == -19:
        return ed25519(signer["seed"], message)[1]
    return p256_sign(signer["x"], message)


def sign1(signer, payload, alg=None):
    protected = protected_header(alg or signer["alg"], signer["kid"])
    return protected, raw_sign(signer, sig_structure(protected, payload))


def cose_bytes(protected, payload, signature):
    return enc(Tag(18, [protected, {}, payload, signature]))


# P-116
AUTH_CONTEXT_LABEL = b"suiss/auth-context/v1"
AUTH_REALM = "https://acme.suiss.example"
AUTH_TIME = 1792109000000


def auth_context_payload(rid):
    return {"v": 1, "realm": AUTH_REALM, "session_ref": label("access:session:alice"), "aal": "aal2",
            "assurance_flags": ["human_presence", "phishing_resistant", "uv"], "auth_time": AUTH_TIME,
            "ais_digest": label("access:ais:alice"), "content_type": RECORD_CONTENT_TYPE, "content_digest": rid}


def auth_context_digest(rid):
    return sha(AUTH_CONTEXT_LABEL + b"\x00" + enc(auth_context_payload(rid)))


signed_records = []
envelope_state = {"prev": [-16, GENESIS_LEAF], "pos": 1, "recorded_at": 1792109100000}


def envelope(rec, c, rid, ingest, name):
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
        env["auth_context"] = {"ref": [-16, auth_context_digest(rid)], "assurance": "aal2", "step_up": False}
    else:
        payload = enc(rec)
        protected, signature = sign1(SIGNERS[rec["author"]], payload)
        cose = cose_bytes(protected, payload, signature)
        check(cose, allowed_tags=(18,))
        signed_records.append({"name": name, "author": rec["author"], "payload": payload, "protected": protected,
                               "signature": signature, "cose": cose})
        env["proof_commit"] = [-16, sha(cose)]
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
    env, eb, leaf = envelope(rec, c, rid, "admitted", "record/" + name)
    write_cbor("LedgerEnvelope", "envelope-" + name, eb, "pass")
    out_envs.append({"id": "envelope/" + name, "rules": ENVELOPE_RULES,
                     "diag": diag(env), "hex": eb.hex(), "decoded": decoded(eb), "leaf_hash": leaf.hex(),
                     "cddl": "pass", "expect": {"outcome": "accept"}})

write_json("records.json", {
    "file": "records.json",
    "notes": ["record_digest = det-CBOR(Digest) of SHA-256(det-CBOR(SignedRecord)), no prefix",
              "leaf_hash = SHA-256(0x00 || det-CBOR(LedgerEnvelope))",
              "proof_commit = SHA-256 of the full tagged WorkRecordCose bytes as received; cose-sign1.json holds those bytes for every envelope that carries proof_commit",
              "Digest values labelled work-vector:* are SHA-256 of ASCII placeholder strings, not real objects",
              "auth_context.ref of a human author's envelope is Access's digest SHA-256(\"suiss/auth-context/v1\" || 0x00 || det-CBOR(auth-context)) of the Access auth-context payload bound to the record: v 1, realm https://acme.suiss.example, session_ref work-vector:access:session:alice, aal aal2, assurance_flags [human_presence, phishing_resistant, uv], auth_time 1792109000000, ais_digest work-vector:access:ais:alice, content_type application/work-record+cbor, content_digest the record digest (P-116)",
              "context holds verifier inputs that are not record bytes: origin, actor_type exactly as the envelope ActorTypeAnnotation (author, one entry per on_behalf_of party and one per evidence presenter in evidence order), understood_extensions, and recorded_at when the record carries params.effective_at",
              "ledger is the LedgerID of genesis.json genesis/accept; the first envelope is at pos 1 and its prev is the genesis leaf hash (P-100)",
              "PartyRef values are placeholder text until the Access Party reference byte form is fixed"],
    "records": out_recs, "envelopes": out_envs})

body_salt = bytes(range(32))
second_salt = bytes(range(32, 64))
LARGE_PART = 65536
LARGE_NAME, LARGE_MEDIA = "attachment", "application/octet-stream"


def large_content(n):
    return b"\x61" * n


def large_part(n):
    return {"name": LARGE_NAME, "media_type": LARGE_MEDIA, "content": {"fill_hex": "61", "fill_count": n}}


def large_input(n):
    content = large_content(n)
    third = content if n <= LARGE_PART else [-16, sha(content)]
    return enc([LARGE_NAME, LARGE_MEDIA, third])


def body_commit(salt, n):
    return sha(b"\x03" + salt + large_input(n))


PROOF_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
PROOF_KID = b"\x11" * 32
proof_payload = bytes.fromhex(out_recs[0]["hex"])
proof_protected = enc({1: -19, 3: "application/work-record+cbor", 4: PROOF_KID})
proof_public, proof_signature = ed25519(PROOF_SEED, enc(["Signature1", proof_protected, b"", proof_payload]))
proof_cose = enc(Tag(18, [proof_protected, {}, proof_payload, proof_signature]))
assert proof_cose == signed_records[0]["cose"]
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
    {"id": "digest/body-commit-64kib", "rules": ["P-68", "P-101", "P-104"],
     "note": "content of exactly 65536 bytes is committed as itself (P-104 item 2)",
     "salt_hex": body_salt.hex(), "part": large_part(LARGE_PART), "content_form": "bytes",
     "digest_hex": body_commit(body_salt, LARGE_PART).hex()},
    {"id": "digest/body-commit-64kib-plus-1", "rules": ["P-68", "P-101", "P-104"],
     "note": "content above 65536 bytes is committed by its unprefixed SHA-256 Digest: det-CBOR([name, media_type, [-16, SHA-256(content)]]) (P-104 item 1)",
     "salt_hex": body_salt.hex(), "part": large_part(LARGE_PART + 1), "content_form": "digest",
     "content_digest_hex": sha(large_content(LARGE_PART + 1)).hex(),
     "part_cbor_hex": large_input(LARGE_PART + 1).hex(),
     "digest_hex": body_commit(body_salt, LARGE_PART + 1).hex()},
    {"id": "digest/body-commit-64kib-plus-1-second-salt", "rules": ["P-68", "P-104"],
     "note": "the same large content under another salt gives another commitment (P-68 item 2, P-104 item 4)",
     "salt_hex": second_salt.hex(), "part": large_part(LARGE_PART + 1), "content_form": "digest",
     "digest_hex": body_commit(second_salt, LARGE_PART + 1).hex()},
    {"id": "digest/body-commit-narrowed-limit", "rules": ["P-7", "P-104"],
     "note": "an installation that narrows the string limit commits the 65536-byte part exactly as digest/body-commit-64kib; the threshold is the protocol constant 65536 (P-104 item 3)",
     "context": {"string_limit": 4096}, "same_as": "digest/body-commit-64kib",
     "salt_hex": body_salt.hex(), "part": large_part(LARGE_PART), "content_form": "bytes",
     "digest_hex": body_commit(body_salt, LARGE_PART).hex()},
    {"id": "digest/proof-commit", "rules": ["P-6", "P-75", "P-76", "P-79", "P-102"],
     "note": "proof_commit = SHA-256 of the full tagged COSE_Sign1 bytes as received, no prefix; the payload is the records.json record/declaration-promise-for-principal hex, signed with the RFC 8032 section 7.1 test 1 Ed25519 key under kid h'11' * 32",
     "input": "records.json record/declaration-promise-for-principal hex",
     "public_key_hex": proof_public.hex(), "kid_hex": PROOF_KID.hex(),
     "cose_hex": proof_cose.hex(), "record_id_hex": sha(proof_payload).hex(),
     "digest_hex": sha(proof_cose).hex(), "prefix": None},
    {"id": "digest/wrong-alg-label", "rules": ["P-5", "P-67", "Access CR-1"],
     "encoded_digest_hex": enc([-44, sha(b"")]).hex(), "cddl": "fail",
     "expect": {"outcome": "reject", "reason": "schema:digest_alg"}},
    {"id": "digest/short-value", "rules": ["P-5", "P-67"],
     "encoded_digest_hex": enc([-16, sha(b"")[:31]]).hex(), "cddl": "fail",
     "expect": {"outcome": "reject", "reason": "schema:digest_length"}},
]
for case in [c for c in digest_cases if c.get("cddl") == "fail"]:
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
              "the kernel picks the envelope schema by pos: 0 is GenesisEnvelope, above 0 is ActivationEnvelope when the map carries activation and LedgerEnvelope otherwise (P-100 item 6, P-110 item 3)"],
    "cases": genesis_cases})


# P-110 P-100 P-108 OP-28
def walk_reason(m, schema):
    keys = sorted(m, key=enc)
    i = 0
    for name, needed in schema:
        if i < len(keys) and enc(keys[i]) < enc(name):
            return "schema:unknown_core_field"
        if i < len(keys) and keys[i] == name:
            i += 1
        elif needed:
            return "schema:required_field"
    return "schema:unknown_core_field" if i < len(keys) else None


ACTIVATION_SCHEMA = [("pos", True), ("prev", True), ("ledger", True), ("activation", True),
                     ("recorded_at", True), ("auth_context", True)]
ACTIVATED_SCHEMA = [("schema", True), ("protocol", True)]
GENESIS_SCHEMA = [("pos", True), ("nonce", True), ("versions", True), ("recorded_at", True)]


def activation_reason(e):
    if e["pos"] == 0:
        return walk_reason(e, GENESIS_SCHEMA)
    return walk_reason(e, ACTIVATION_SCHEMA) or walk_reason(e["activation"], ACTIVATED_SCHEMA)


ACTIVATION_RULES = ["P-110", "P-100", "P-11", "P-21", "P-27", "OP-28"]
OPERATOR_CONTEXT = {"ref": label("access:auth-context:operator"), "assurance": "aal3", "step_up": True}
ACTIVATION_AT = 1792109050000


def activation_of(protocol, schema, prev=None, pos=1, ledger=None):
    return {"activation": {"protocol": protocol, "schema": schema}, "ledger": ledger or LEDGER, "pos": pos,
            "prev": prev or [-16, GENESIS_LEAF], "recorded_at": ACTIVATION_AT, "auth_context": OPERATOR_CONTEXT}


def activation_json(a):
    return {"protocol": a["protocol"], "schema": [-16, a["schema"][1].hex()]}


ACTIVATION = activation_of([1, 1], label("schema:protocol-1.1"))
ACTIVATION_BYTES = enc(ACTIVATION)
ACTIVATION_LEAF = sha(b"\x00" + ACTIVATION_BYTES)
assert activation_reason(ACTIVATION) is None
write_cbor("ActivationEnvelope", "activation-accept", ACTIVATION_BYTES, "pass")
activation_cases = [{
    "id": "activation/accept", "rules": ACTIVATION_RULES,
    "purpose": "An activation of protocol 1.1 right after the genesis of genesis.json; this kernel carries no 1.1 rule set, so the sequence rule cannot check its schema digest, a work-vector placeholder.",
    "diag": diag(ACTIVATION), "hex": ACTIVATION_BYTES.hex(), "decoded": decoded(ACTIVATION_BYTES),
    "entry_id": sha(ACTIVATION_BYTES).hex(), "leaf_hash": ACTIVATION_LEAF.hex(), "cddl": "pass",
    "expect": {"outcome": "accept", "decoded": decoded(ACTIVATION_BYTES)}}]
practices_version = dict(ACTIVATION["activation"], practices={PROC: label("practice:procurement:2.1.0")})
activation_rejects = [
    ("pos-0", variant(ACTIVATION, pos=0), ["P-110", "P-100"], "pass", "schema:unknown_core_field",
     "An activation at position 0 is read as the genesis, whose schema has no activation key."),
    ("auth-context-missing", variant(ACTIVATION, auth_context=None), ["P-110", "P-21"], "fail",
     "schema:required_field", "An activation without the operator's Access context."),
    ("prev-missing", variant(ACTIVATION, prev=None), ["P-110", "P-11"], "fail", "schema:required_field",
     "An activation without prev; it continues the chain like any later entry."),
    ("ledger-missing", variant(ACTIVATION, ledger=None), ["P-110", "P-11"], "fail", "schema:required_field",
     "An activation without its ledger."),
    ("record-present", variant(ACTIVATION, record=label("record:activation")), ["P-110"], "fail",
     "schema:unknown_core_field", "An activation carrying a record digest; it is not a record."),
    ("practices-present", variant(ACTIVATION, activation=practices_version), ["P-110", "PR-13"], "fail",
     "schema:unknown_core_field", "An activated version carrying practices; a Practice is adopted by practice_adoption."),
]
for name, a, rules, cddl, reason, purpose in activation_rejects:
    b = enc(a)
    check(b)
    assert activation_reason(a) == reason, (name, activation_reason(a))
    write_cbor("ActivationEnvelope", "activation-reject-" + name, b, cddl)
    activation_cases.append({"id": "activation-reject/" + name, "rules": rules, "purpose": purpose,
                             "diag": diag(a), "hex": b.hex(), "decoded": decoded(b, a), "cddl": cddl,
                             "expect": {"outcome": "reject", "reason": reason}})


def accepted_sequence(entries):
    out = []
    for b in entries:
        e = check(b)
        version = e["versions"] if e["pos"] == 0 else e["activation"]
        out.append({"position": e["pos"], "protocol": version["protocol"],
                    "schema": [-16, version["schema"][1].hex()]})
    return {"outcome": "accept", "activations": out}


wrong_genesis = enc(dict(GENESIS, versions={"protocol": [1, 0], "schema": label("schema:not-protocol-1.0")}))
same_version = enc(activation_of([1, 0], CDDL_DIGEST))
older_version = enc(activation_of([0, 9], label("schema:protocol-0.9")))
back_in_place = enc(activation_of([1, 2], label("schema:protocol-1.2"), prev=[-16, ACTIVATION_LEAF]))
MISMATCH = {"outcome": "reject", "reason": "envelope_mismatch:activation"}
sequences = [
    ("sequence/genesis", [GENESIS_BYTES], ["P-110", "P-100"], accepted_sequence([GENESIS_BYTES]),
     "The genesis alone is the first activation; its schema is the protocol 1.0 CDDL digest."),
    ("sequence/genesis-then-activation", [GENESIS_BYTES, ACTIVATION_BYTES], ["P-110", "P-87"],
     accepted_sequence([GENESIS_BYTES, ACTIVATION_BYTES]),
     "A later version this kernel does not know passes the sequence rule; its records are quarantined by P-87."),
    ("sequence-reject/same-version", [GENESIS_BYTES, same_version], ["P-110", "OP-28"], MISMATCH,
     "Activating the version that is already active."),
    ("sequence-reject/older-version", [GENESIS_BYTES, older_version], ["P-110", "OP-28"], MISMATCH,
     "Activating an older version; going back needs a new version value."),
    ("sequence-reject/genesis-schema", [wrong_genesis], ["P-110", "P-100"], MISMATCH,
     "A genesis of protocol 1.0 whose schema is not the protocol 1.0 CDDL digest."),
    ("sequence-reject/position-not-rising", [GENESIS_BYTES, ACTIVATION_BYTES, back_in_place], ["P-110"],
     MISMATCH, "A later activation at the position of the one before it."),
    ("sequence-reject/no-genesis", [ACTIVATION_BYTES], ["P-110", "P-100"], MISMATCH,
     "A sequence whose first entry is not a genesis."),
]
sequence_cases = [{"id": i, "rules": r, "purpose": p, "entries": [b.hex() for b in es], "expect": x}
                  for i, es, r, x, p in sequences]
genesis_point = {"ledger": [-16, LEDGER[1].hex()], "prev": [-16, GENESIS_LEAF.hex()]}
verify_cases = [
    {"id": "verify/activation", "rules": ["P-110", "P-108", "T-95"],
     "purpose": "The activation verified after the genesis: it names the ledger and the genesis leaf, its record bytes are its envelope bytes, and the next entry continues from its leaf.",
     "at": genesis_point, "envelope": ACTIVATION_BYTES.hex(), "record": ACTIVATION_BYTES.hex(),
     "expect": {"outcome": "accept", "record": [-16, sha(ACTIVATION_BYTES).hex()], "binding": "auth_context",
                "ledger": [-16, LEDGER[1].hex()], "position": 1, "recorded_at": ACTIVATION_AT,
                "activation": activation_json(ACTIVATION["activation"]), "leaf": [-16, ACTIVATION_LEAF.hex()],
                "next": {"ledger": [-16, LEDGER[1].hex()], "prev": [-16, ACTIVATION_LEAF.hex()]}}},
    {"id": "verify-reject/prev", "rules": ["P-110", "P-108"],
     "purpose": "The activation after a chain point whose leaf is not its prev.",
     "at": dict(genesis_point, prev=[-16, ACTIVATION_LEAF.hex()]), "envelope": ACTIVATION_BYTES.hex(),
     "record": ACTIVATION_BYTES.hex(), "expect": {"outcome": "reject", "reason": "envelope_mismatch:prev"}},
    {"id": "verify-reject/ledger", "rules": ["P-110", "P-108"],
     "purpose": "The activation after the chain point of another ledger.",
     "at": dict(genesis_point, ledger=[-16, label("ledger:other")[1].hex()]), "envelope": ACTIVATION_BYTES.hex(),
     "record": ACTIVATION_BYTES.hex(), "expect": {"outcome": "reject", "reason": "envelope_mismatch:ledger"}},
    {"id": "verify-reject/record", "rules": ["P-110", "P-108"],
     "purpose": "The activation stored with record bytes other than its envelope bytes.",
     "at": genesis_point, "envelope": ACTIVATION_BYTES.hex(), "record": GENESIS_BYTES.hex(),
     "expect": {"outcome": "reject", "reason": "envelope_mismatch:record"}},
]
write_json("activation.json", {
    "file": "activation.json",
    "notes": ["an ActivationEnvelope is an authorless log entry the sequencer writes to activate a protocol version after the genesis, which is the first activation; its identifier is SHA-256(det-CBOR(ActivationEnvelope)) without prefix and its leaf hash SHA-256(0x00 || det-CBOR(ActivationEnvelope)) (P-110 items 1, 4)",
              "cases are decode_envelope inputs; expect is the binding answer, the decoded projection for an accepted case",
              "sequences are check_activations inputs, the envelope bytes of a ledger's activations in log order with the genesis first; expect is the binding answer",
              "verify cases are verify_entry inputs after the chain point at with no COSE_Sign1 and no keys; expect is the binding answer",
              "the activation names the LedgerID of genesis.json genesis/accept; schema digests labelled work-vector:* are placeholders of versions this kernel does not know"],
    "cases": activation_cases, "sequences": sequence_cases, "verify": verify_cases})


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
    ("actor-type-presenter-missing", rec_act, {"presenters": []},
     ["EV-35", "P-12"], "envelope_mismatch:actor_type"),
    ("actor-type-presenter-extra", rec_act, {"presenters": [["organization", "access_binding"]] * 2},
     ["EV-35", "P-12"], "envelope_mismatch:actor_type"),
    ("actor-type-presenter-without-evidence", rec_promise, {"presenters": [["organization", "access_binding"]]},
     ["EV-35", "P-12"], "envelope_mismatch:actor_type"),
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
] + [
    ("redact-" + name, variant(rec_redact, **changes), {}, ["P-111"] + rules, reason)
    for name, changes, rules, reason in (
        ("parts-empty", {"params": dict(rec_redact["params"], parts=[])}, ["P-92"], "schema:params"),
        ("parts-unsorted", {"params": dict(rec_redact["params"], parts=["terms", "note"])}, ["P-92", "P-72"],
         "schema:params"),
        ("parts-repeated", {"params": dict(rec_redact["params"], parts=["terms", "terms"])}, ["P-92", "P-72"],
         "schema:params"),
        ("part-name-invalid", {"params": dict(rec_redact["params"], parts=["Terms"])}, ["P-92", "P-68"],
         "schema:params"),
        ("reason-unknown", {"params": dict(rec_redact["params"], reason="takedown")}, ["P-92"], "schema:params"),
        ("target-not-digest", {"params": dict(rec_redact["params"], target="record:declaration-promise")},
         ["P-92", "P-79"], "schema:params"),
        ("effective-at", {"params": dict(rec_redact["params"], effective_at=1792195200000)}, ["P-92", "P-80"],
         "schema:params"),
        ("authority-missing", {"authority": None}, ["P-13", "P-83"], "authority_missing"),
        ("supersedes", {"relations": [{"rel": "supersedes", "target": ["record", PROMISE_ID]}]}, ["P-24"],
         "schema:relation"),
    )
]
CDDL_FAIL = ("schema:empty", "schema:relation", "schema:required_field", "schema:unknown_core_field",
             "schema:ext_key", "schema:type_uri", "schema:kind", "limit_exceeded:", "capacity_missing")
CDDL_FAIL_CASES = {"params-map-value", "practice-param-text-too-long", "redact-parts-empty"}
CDDL_PASS_CASES = {"core-qualifier-on-references", "redact-supersedes"}
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
              "context holds verifier inputs that are not record bytes (origin, actor_type as the envelope ActorTypeAnnotation with one entry per on_behalf_of party and one per evidence presenter, understood_extensions, recorded_at)"],
    "cases": out_rej})

V2 = dict(rec_comment["versions"], protocol=[2, 0])
v2_new_field = variant(rec_comment, versions=V2)
v2_new_field["priority"] = 3
v2_new_kind = variant(rec_comment, kind="event", versions=V2)
quarantine = [
    ("critical-ext-not-understood", variant(rec_consent, body=[{"part": "note", "commit": label("body:note:care:quarantine")}]), {},
     ["P-19", "P-69", "C-5", "P-109"],
     "The care note Claim of record/claim-critical-ext-understood with another body commitment, so the golden ledger holds no record twice; this verifier does not understand the critical extension.",
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
    env, eb, leaf = envelope(rec, c, rid, ["quarantined", reason], "record-quarantine/" + name)
    write_cbor("LedgerEnvelope", "quarantine-envelope-" + name, eb, "pass")
    out_q.append({"id": "record-quarantine/" + name, "rules": rules, "purpose": purpose,
                  "hex": b.hex(), "decoded": decoded(b), "context": c, "record_digest": enc(rid).hex(),
                  "cddl": cddl,
                  "envelope": {"rules": ENVELOPE_RULES, "diag": diag(env), "hex": eb.hex(), "decoded": decoded(eb),
                               "leaf_hash": leaf.hex(), "cddl": "pass"},
                  "expect": {"outcome": "quarantine", "reason": reason}})

# P-109
ledger_records = [r["hex"] for r in out_recs] + [q["hex"] for q in out_q]
assert len(set(ledger_records)) == len(ledger_records), "golden ledger records must have unique bytes"

write_json("records-quarantine.json", {
    "file": "records-quarantine.json",
    "notes": ["a quarantined record is still written to the ledger; its envelope carries ingest [\"quarantined\", reason] and continues the records.json chain",
              "no record of records.json or records-quarantine.json repeats the bytes of another, so the golden ledger stores each once (P-109)"],
    "cases": out_q})

# P-48 P-49 P-51 P-52
PROV_PREFIX = {"party": CORE + "party/", "record": CORE + "record/", "work": CORE}
AS2 = "https://www.w3.org/ns/activitystreams"
FORGEFED = "https://forgefed.org/ns"
UNRESERVED = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
BASIS_ROLE = ROLE + "basis"
AS2_ACTIVITIES = {
    "request": ("Offer", AS2), "counter": ("Offer", AS2), "promise": ("Accept", AS2),
    "decline": ("Reject", AS2), "promise_conditional": ("TentativeAccept", AS2),
    "revoke_request": ("Undo", AS2), "revoke_promise": ("Undo", AS2),
    "revoke_statement": ("Undo", AS2), "revoke_acceptance": ("Undo", AS2),
    "assign": ("Assign", FORGEFED), "amend": ("Update", AS2),
}


def party_ref(p):
    return "party:" + "".join(chr(b) if b in UNRESERVED else "%%%02X" % b for b in p.encode())


def record_ref(d):
    return "record:" + d[1].hex()


def prov_document(rec, rid, actors, withheld):
    me = record_ref(rid)
    act = rec["kind"] == "act"
    hidden = {w[1] for w in withheld}
    entities, agents, statements = {}, {}, {}
    count = [0]

    def emit(kind, body):
        count[0] += 1
        statements.setdefault(kind, {})["_:s%d" % count[0]] = body

    def agent(p, entry):
        agents.setdefault(party_ref(p), {"work:actorType": entry[0], "work:actorTypeSource": entry[1]})

    def visible(d):
        return d[1] not in hidden

    node = {"work:kind": rec["kind"], "work:type": rec["type"]}
    if not act:
        entities[me] = node
    agent(rec["author"], actors["author"])
    author = party_ref(rec["author"])
    relations = rec.get("relations", [])
    if act:
        plans = [r["target"][1] for r in relations
                 if r["rel"] == "derived_from" and "source" not in r and r["target"][0] == "record"
                 and r["qualifier"] == ROLE + "fulfills" and visible(r["target"][1])]
        for plan in plans:
            entities[record_ref(plan)] = {"prov:type": "prov:Plan"}
            emit("wasAssociatedWith", {"prov:activity": me, "prov:agent": author, "prov:plan": record_ref(plan)})
        if not plans:
            emit("wasAssociatedWith", {"prov:activity": me, "prov:agent": author})
    else:
        emit("wasAttributedTo", {"prov:entity": me, "prov:agent": author})
    previous = rec["author"]
    for p, entry in zip(rec.get("on_behalf_of", []), actors.get("on_behalf_of", [])):
        agent(p, entry)
        emit("actedOnBehalfOf", {"prov:delegate": party_ref(previous), "prov:responsible": party_ref(p)})
        previous = p
    for b in rec.get("basis", []):
        if not visible(b):
            continue
        if act:
            emit("used", {"prov:activity": me, "prov:entity": record_ref(b), "work:role": BASIS_ROLE})
        else:
            emit("wasDerivedFrom", {"prov:generatedEntity": me, "prov:usedEntity": record_ref(b),
                                    "work:role": BASIS_ROLE})
    references = []
    for r in relations:
        target = r["target"]
        if r["rel"] == "derived_from" and target[0] == "record":
            source = r.get("source")
            if not visible(target[1]) or (source is not None and not visible(source[1])):
                continue
            if source is None and act:
                if r["qualifier"] != ROLE + "fulfills":
                    emit("used", {"prov:activity": me, "prov:entity": record_ref(target[1]),
                                  "work:role": r["qualifier"]})
            else:
                emit("wasDerivedFrom", {"prov:generatedEntity": me if source is None else record_ref(source[1]),
                                        "prov:usedEntity": record_ref(target[1]), "work:role": r["qualifier"]})
        elif r["rel"] == "supersedes" and visible(target[1]):
            emit("wasDerivedFrom", {"prov:generatedEntity": me, "prov:usedEntity": record_ref(target[1]),
                                    "prov:type": "prov:Revision"})
            emit("wasInvalidatedBy", {"prov:entity": record_ref(target[1])})
        elif r["rel"] == "references" and act and "source" not in r and target[0] == "external":
            if target[1] not in references:
                references.append(target[1])
            ref = "_:ref%d" % (references.index(target[1]) + 1)
            entities[ref] = {"prov:type": "work:Reference", "work:ref": target[1]}
            emit("wasGeneratedBy", {"prov:entity": ref, "prov:activity": me})
    doc = {"prefix": PROV_PREFIX, "agent": agents}
    if act:
        doc["activity"] = {me: node}
    if entities:
        doc["entity"] = entities
    doc.update(statements)
    return doc


def as2_activity(rec):
    if rec["kind"] != "declaration":
        return None
    if any(r["rel"] == "supersedes" for r in rec.get("relations", [])):
        found = ("Update", AS2)
    elif rec["type"] == DECLARATION + "open_condition":
        information = rec["params"]["condition_type"] == CORE + "condition/information"
        found = ("Question", AS2) if information else None
    elif rec["type"].startswith(DECLARATION):
        found = AS2_ACTIVITIES.get(rec["type"][len(DECLARATION):])
    else:
        found = None
    return None if found is None else {"type": found[0], "vocabulary": found[1]}


def mapping_context(c, withheld=()):
    actors = {k: v for k, v in c["actor_type"].items() if k != "evidence"}
    out = {"actor_type": actors}
    if withheld:
        out["withheld"] = [[-16, w[1].hex()] for w in withheld]
    return out


information_wait = variant(rec_open_gate, params=dict(FAMILY_PARAMS["open_condition"]))
mapping_only = [
    ("declaration-request", variant(rec_promise, type=DECLARATION + "request", relations=None),
     ["P-51", "CM-17"], "A request maps to an AS2 Offer."),
    ("declaration-counter", variant(rec_promise, type=DECLARATION + "counter"),
     ["P-51", "CM-17"], "A counter-offer maps to a new AS2 Offer."),
    ("declaration-promise-conditional", variant(rec_promise, type=DECLARATION + "promise_conditional"),
     ["P-51", "CM-17"], "A conditional yes maps to an AS2 TentativeAccept."),
    ("declaration-revoke-promise", variant(rec_decline, type=DECLARATION + "revoke_promise", params=None,
                                           visibility=vis()),
     ["P-51", "CM-35"], "A revocation request maps to an AS2 Undo."),
    ("declaration-assign", variant(rec_decline, type=DECLARATION + "assign", params=None, visibility=vis()),
     ["P-51", "CM-17"], "An assignment maps to the ForgeFed Assign activity."),
    ("declaration-open-condition-information", information_wait,
     ["P-51", "ST-10", "ST-12"], "A wait for information maps to an AS2 Question."),
    ("act-basis-roles-and-reference", variant(rec_act, basis=[label("record:commitment.request:supplier")],
                                              relations=[
        {"rel": "derived_from", "target": ["record", label("record:commitment.promise:supplier")],
         "qualifier": ROLE + "fulfills"},
        {"rel": "derived_from", "target": ["record", label("record:work-order:supplier")],
         "qualifier": ROLE + "source"},
        {"rel": "references", "target": ["external", "https://erp.example/deliveries/D-17"]}]),
     ["P-49", "C-27", "C-29"],
     "An Act with a basis, the fulfilled promise as its PROV plan, a source it used and an external object it produced."),
    ("claim-derived-from-source", variant(rec_obs, relations=[
        {"rel": "derived_from", "target": ["record", label("record:sensor-reading:dock-3")],
         "qualifier": ROLE + "source"},
        {"rel": "derived_from", "source": ["record", label("record:sensor-reading:dock-3")],
         "target": ["record", label("record:sensor-calibration:dock-3")], "qualifier": ROLE + "source"}]),
     ["P-49", "C-27"], "A Claim derived from a source record, and a lineage between two other records it states."),
]
mapping_cases = []
for r in out_recs:
    rec = check(bytes.fromhex(r["hex"]))
    mapping_cases.append((r["id"], r["hex"], rec, r["context"], [], ["P-49", "P-51"]))
mapping_cases.append(("withheld/declaration-promise-for-principal", out_recs[0]["hex"],
                      check(bytes.fromhex(out_recs[0]["hex"])), out_recs[0]["context"],
                      [label("record:commitment.request")], ["P-49", "EV-12"]))
mapping_records = []
for name, rec, rules, purpose in mapping_only:
    b = enc(rec)
    c = ctx(rec, **({"origin": "automation"} if rec["author"] == SYS else {}))
    assert semantic(rec, c) == ("accept", None), (name, semantic(rec, c))
    write_cbor("SignedRecord", "mapping-" + name, b, "pass")
    mapping_cases.append(("mapping/" + name, b.hex(), rec, c, [], rules))
    mapping_records.append(purpose)
out_map = []
for case_id, hx, rec, c, withheld, rules in mapping_cases:
    rid = [-16, sha(bytes.fromhex(hx))]
    expect = {"outcome": "accept", "prov": prov_document(rec, rid, c["actor_type"], withheld),
              "as2": as2_activity(rec)}
    out_map.append({"id": case_id, "rules": rules, "hex": hx, "context": mapping_context(c, withheld),
                    "expect": expect})
unknown = next(q for q in out_q if q["expect"]["reason"] == "protocol_version_unknown")
out_map.append({"id": unknown["id"], "rules": ["P-49", "P-87"], "hex": unknown["hex"],
                "context": mapping_context(unknown["context"]), "expect": unknown["expect"]})
reimport = []
for case in out_map[:1]:
    for key in ("prov", "as2"):
        text = json.dumps(case["expect"][key], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        try:
            check(text)
            raise SystemExit("an export document decodes as CBOR")
        except Reject as e:
            reason = str(e)
        reimport.append({"id": "reimport/" + key + "/" + case["id"], "rules": ["P-48", "P-52"],
                         "hex": text.hex(), "expect": {"outcome": "reject", "reason": reason}})
write_json("mapping.json", {
    "file": "mapping.json",
    "notes": ["P-49 PROV-JSON and P-51 ActivityStreams 2.0 mappings of one record, computed from its signed fields only: the expect of a case is the answer of map_record for its hex and context",
              "context.actor_type is the envelope ActorTypeAnnotation without its evidence entries; context.withheld lists the records the viewer may not see, and every statement naming one is left out (EV-12, P-49)",
              "identifiers: record:<record id hex>, party:<PartyRef percent-encoded outside the RFC 3986 unreserved set>, _:s<n> for statements in emission order, _:ref<n> for external objects an Act produced",
              "an Act is a prov:Activity, a Declaration or Claim a prov:Entity; the author is wasAssociatedWith (Act) or wasAttributedTo; each on_behalf_of ring is actedOnBehalfOf from the previous party; basis is used (Act) or wasDerivedFrom with the basis role; a derived_from record target is used (Act) or wasDerivedFrom with its role, and the fulfills target of an Act is the prov:Plan of its association; supersedes is a prov:Revision plus wasInvalidatedBy of the older record; an external object an Act references is wasGeneratedBy the Act",
              "as2 is the activity of a Declaration: a record carrying supersedes is an Update; otherwise request and counter are Offer, promise Accept, decline Reject, promise_conditional TentativeAccept, the four revocation requests Undo, assign the ForgeFed Assign, and open_condition of the core information type Question; every other record maps to null",
              "reimport cases are export documents given back as record bytes: neither is a record (P-48 JSON-LD and AS2 canonical form REJECT, P-52)"],
    "cases": out_map, "reimport": reimport})

# P-6 P-7 P-32 P-102 P-103 P-105 P-106 Access CR-9
AGENT_ES256 = {"id": "agent-es256", "alg": -7, "kid": b"\x21" * 32, "x": RFC6979_X,
               "source": "RFC 6979 appendix A.2.5"}
COSE_KEYS = [(AGENT, SIGNERS[AGENT]), (AGENT, AGENT_ES256), (SYS, SIGNERS[SYS]), (SUPPLIER, SIGNERS[SUPPLIER])]


def key_entry(party, signer):
    return {"id": signer["id"], "party": party, "alg": signer["alg"], "kid_hex": signer["kid"].hex(),
            "public_key_hex": public_key(signer).hex(), "source": signer["source"]}


def cose_case(case_id, rules, author, cose, expect, **extra):
    check(cose, allowed_tags=(18,))
    case = {"id": case_id, "rules": rules, "author": author}
    case.update(extra)
    case.update({"cose_hex": cose.hex(), "expect": expect})
    return case


SIGNED_ENVELOPES = {e["id"].split("/", 1)[1]: e for e in out_envs}
cose_cases = []
for sr in signed_records:
    family, name = sr["name"].split("/", 1)
    rid = sha(sr["payload"]).hex()
    extra = {"payload": sr["name"] + " hex", "key": SIGNERS[sr["author"]]["id"],
             "protected_hex": sr["protected"].hex(), "signature_hex": sr["signature"].hex(),
             "record_id_hex": rid, "proof_commit_hex": sha(sr["cose"]).hex()}
    if family == "record":
        extra["envelope"] = "records.json envelope/" + name
        rules = ["P-6", "P-75", "P-76", "P-79", "P-102", "P-105"]
    else:
        extra["envelope"] = "records-quarantine.json " + sr["name"] + " envelope"
        rules = ["P-6", "P-75", "P-79", "P-102", "P-106"]
    cose_cases.append(cose_case("cose-sign1/" + ("" if family == "record" else "quarantine-") + name, rules,
                                sr["author"], sr["cose"], {"outcome": "accept"}, **extra))

first_signed = signed_records[0]
first_payload = first_signed["payload"]
es256_protected, es256_signature = sign1(AGENT_ES256, first_payload)
es256_cose = cose_bytes(es256_protected, first_payload, es256_signature)
cose_cases.append(cose_case(
    "cose-sign1/container-es256", ["P-6", "P-7", "P-79", "Access CR-9"], AGENT, es256_cose, {"outcome": "accept"},
    purpose="The first records.json record in a second container: ES256 under the agent's second key instead of Ed25519. The container is not semantic: the record ID is the same, only proof_commit differs (P-6 item 4).",
    payload=first_signed["name"] + " hex", key=AGENT_ES256["id"], protected_hex=es256_protected.hex(),
    signature_hex=es256_signature.hex(), record_id_hex=sha(first_payload).hex(),
    proof_commit_hex=sha(es256_cose).hex(), same_record_as="cose-sign1/declaration-promise-for-principal"))

supplier_signed = next(sr for sr in signed_records if sr["author"] == SUPPLIER)
s_payload, s_protected = supplier_signed["payload"], supplier_signed["protected"]
s_r, s_s = supplier_signed["signature"][:32], int.from_bytes(supplier_signed["signature"][32:], "big")
ed_protected, ed_signature = first_signed["protected"], first_signed["signature"]
ed_s = int.from_bytes(ed_signature[32:], "little")
NON_CANONICAL_ONE = (ED_P + 1).to_bytes(32, "little")
IDENTITY = (1).to_bytes(32, "little")
tampered = first_payload[:-1] + bytes([first_payload[-1] ^ 1])
foreign_protected, foreign_signature = sign1(SIGNERS[AGENT], s_payload)
wrong_type = enc({1: -19, 3: "application/cbor", 4: SIGNERS[AGENT]["kid"]})
unknown_kid = protected_header(-19, b"\x33" * 32)
ed_on_p256 = protected_header(-19, SIGNERS[SUPPLIER]["kid"])
P_103 = ["P-7", "P-103", "Access CR-9"]
cose_rejects = [
    ("ed25519-small-order-r", P_103, AGENT, cose_bytes(ed_protected, first_payload, IDENTITY + bytes(32)),
     "signature:invalid", "R is the identity point, of small order; S is zero and reduced."),
    ("ed25519-non-canonical-r", ["P-7", "Access CR-9"], AGENT,
     cose_bytes(ed_protected, first_payload, NON_CANONICAL_ONE + ed_signature[32:]),
     "signature:non_canonical_ed25519", "R encodes y = p + 1, a non-canonical encoding of the identity."),
    ("ed25519-unreduced-s", ["P-7", "Access CR-9"], AGENT,
     cose_bytes(ed_protected, first_payload, ed_signature[:32] + (ed_s + ED_L).to_bytes(32, "little")),
     "signature:non_canonical_ed25519", "S + L in place of S: the same equation, an unreduced scalar."),
    ("ed25519-short-signature", P_103, AGENT, cose_bytes(ed_protected, first_payload, ed_signature[:63]),
     "signature:invalid", "A 63-byte Ed25519 signature."),
    ("ed25519-changed-payload", ["P-6"], AGENT, cose_bytes(ed_protected, tampered, ed_signature),
     "signature:invalid", "The last payload byte flipped under the original signature."),
    ("esp256-high-s", ["P-7", "Access CR-9"], SUPPLIER,
     cose_bytes(s_protected, s_payload, s_r + (P256_N - s_s).to_bytes(32, "big")),
     "signature:high_s", "n - s in place of the low s: valid ECDSA, but high-S on a Work record."),
    ("esp256-r-zero", P_103, SUPPLIER, cose_bytes(s_protected, s_payload, bytes(32) + s_s.to_bytes(32, "big")),
     "signature:invalid", "ECDSA r = 0, outside 1..n-1."),
    ("esp256-r-equals-n", P_103, SUPPLIER,
     cose_bytes(s_protected, s_payload, P256_N.to_bytes(32, "big") + s_s.to_bytes(32, "big")),
     "signature:invalid", "ECDSA r = n, outside 1..n-1."),
    ("esp256-s-zero", P_103, SUPPLIER, cose_bytes(s_protected, s_payload, s_r + bytes(32)),
     "signature:invalid", "ECDSA s = 0, outside 1..n-1."),
    ("kid-unknown", ["P-6", "Access CR-55"], AGENT,
     cose_bytes(unknown_kid, first_payload, raw_sign(SIGNERS[AGENT], sig_structure(unknown_kid, first_payload))),
     "signature:kid_unknown", "A kid with no key bound to the author."),
    ("alg-key-mismatch", ["P-6", "Access CR-7"], SUPPLIER,
     cose_bytes(ed_on_p256, s_payload, raw_sign(SIGNERS[AGENT], sig_structure(ed_on_p256, s_payload))),
     "signature:alg_not_allowed", "Ed25519 in the header with the kid of a P-256 key."),
    ("content-type-outside-profile", ["P-102", "P-6"], AGENT,
     cose_bytes(wrong_type, first_payload, raw_sign(SIGNERS[AGENT], sig_structure(wrong_type, first_payload))),
     "signature:header_profile", "Content type application/cbor instead of application/work-record+cbor."),
    ("author-not-key-owner", ["P-105", "P-6"], AGENT, cose_bytes(foreign_protected, s_payload, foreign_signature),
     "signature:kid_unknown", "The supplier's record signed with the agent's key and checked against the agent's keys: the record's author is not the key owner."),
    ("untagged", ["P-6", "P-72"], AGENT, cose_bytes(ed_protected, first_payload, ed_signature)[1:],
     "schema:container", "The first records.json container without tag 18."),
]
for name, rules, author, cose, reason, purpose in cose_rejects:
    if name == "untagged":
        case = {"id": "cose-sign1-reject/" + name, "rules": rules, "author": author, "purpose": purpose,
                "cose_hex": cose.hex(), "expect": {"outcome": "reject", "reason": reason}}
    else:
        case = cose_case("cose-sign1-reject/" + name, rules, author, cose,
                         {"outcome": "reject", "reason": reason}, purpose=purpose)
    cose_cases.append(case)
key_rejects = [
    {"id": "key-reject/ed25519-non-canonical", "rules": ["P-7", "Access CR-9"], "alg": -19,
     "public_key_hex": NON_CANONICAL_ONE.hex(), "expect": {"outcome": "reject", "reason": "signature:non_canonical_ed25519"}},
    {"id": "key-reject/ed25519-identity", "rules": ["P-7", "Access CR-9", "Access CR-53"], "alg": -19,
     "public_key_hex": IDENTITY.hex(), "expect": {"outcome": "reject", "reason": "signature:small_order_key"}},
]
write_json("cose-sign1.json", {
    "file": "cose-sign1.json",
    "notes": ["cose_hex is the full tagged WorkRecordCose; protected header {1: alg, 3: \"application/work-record+cbor\", 4: kid}, unprotected header empty (P-102)",
              "a case is checked against the keys whose party is the case author, with Ed25519, ESP256 and ES256 allowed by policy; a valid signature names the record by record_id_hex = SHA-256(payload) and its envelope carries proof_commit_hex = SHA-256(cose_hex) (P-75, P-79)",
              "Ed25519 signatures follow RFC 8032; ECDSA P-256 signatures are RFC 6979 deterministic with SHA-256 and low-S, as Work produces them (P-7)",
              "the signed payloads are the records.json and records-quarantine.json records; a protocol 2.0 record's signature is valid and its author is not read (P-106)",
              "key IDs are placeholders until Access fixes the kid derivation; COSE code points -19 and -9 follow Access (OQ-34)"],
    "keys": [key_entry(party, signer) for party, signer in COSE_KEYS],
    "cases": cose_cases,
    "key_cases": key_rejects})


# P-11 P-100 P-101 T-4 T-64
def merkle_root(leaves):
    if not leaves:
        return sha(b"")
    if len(leaves) == 1:
        return sha(b"\x00" + leaves[0])
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return sha(b"\x01" + merkle_root(leaves[:k]) + merkle_root(leaves[k:]))


def merkle_split(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def inclusion_path(m, leaves):
    if len(leaves) <= 1:
        return []
    k = merkle_split(len(leaves))
    if m < k:
        return inclusion_path(m, leaves[:k]) + [merkle_root(leaves[k:])]
    return inclusion_path(m - k, leaves[k:]) + [merkle_root(leaves[:k])]


def consistency_path(m, leaves, whole=True):
    n = len(leaves)
    if m == 0:
        return []
    if m == n:
        return [] if whole else [merkle_root(leaves)]
    k = merkle_split(n)
    if m <= k:
        return consistency_path(m, leaves[:k], whole) + [merkle_root(leaves[k:])]
    return consistency_path(m - k, leaves[k:], False) + [merkle_root(leaves[:k])]


log_leaves = [GENESIS_BYTES] + [bytes.fromhex(e["hex"]) for e in out_envs] + \
    [bytes.fromhex(q["envelope"]["hex"]) for q in out_q]
LOG_SIZE = len(log_leaves)
leaf_hashes = [sha(b"\x00" + leaf) for leaf in log_leaves]
assert leaf_hashes[0] == GENESIS_LEAF and [h.hex() for h in leaf_hashes[1:1 + len(out_envs)]] == [e["leaf_hash"] for e in out_envs]
roots = {n: merkle_root(log_leaves[:n]) for n in range(LOG_SIZE + 1)}
MERKLE_RULES = ["P-11", "P-100", "P-101", "T-4"]


def inclusion_case(m, n, path=None, root=None, expect=None, case_id=None):
    return {"id": case_id or "inclusion/%d-of-%d" % (m, n), "rules": MERKLE_RULES, "index": m, "size": n,
            "leaf_hash_hex": leaf_hashes[min(m, LOG_SIZE - 1)].hex(),
            "path_hex": [h.hex() for h in (inclusion_path(m, log_leaves[:n]) if path is None else path)],
            "root_hex": (roots[n] if root is None else root).hex(), "expect": expect or {"outcome": "accept"}}


def consistency_case(m, n, path=None, second=None, expect=None, case_id=None):
    return {"id": case_id or "consistency/%d-to-%d" % (m, n), "rules": MERKLE_RULES, "first": m, "second": n,
            "first_root_hex": roots[min(m, LOG_SIZE)].hex(),
            "second_root_hex": (roots[min(n, LOG_SIZE)] if second is None else second).hex(),
            "path_hex": [h.hex() for h in (consistency_path(m, log_leaves[:n]) if path is None else path)],
            "expect": expect or {"outcome": "accept"}}


def proof_reject(code):
    return {"outcome": "reject", "reason": code}


inclusion_cases = [inclusion_case(m, LOG_SIZE) for m in range(LOG_SIZE)] + [inclusion_case(0, 1), inclusion_case(5, 8)]
full_path = inclusion_path(5, log_leaves)
inclusion_cases += [
    inclusion_case(16, LOG_SIZE, root=roots[16], expect=proof_reject("proof-mismatch"), case_id="inclusion-reject/root-of-another-size"),
    inclusion_case(LOG_SIZE, LOG_SIZE, path=[], expect=proof_reject("proof-range"), case_id="inclusion-reject/index-at-size"),
    inclusion_case(5, LOG_SIZE, path=full_path[:-1], expect=proof_reject("proof-length"), case_id="inclusion-reject/path-too-short"),
    inclusion_case(5, LOG_SIZE, path=full_path + [roots[1]], expect=proof_reject("proof-length"), case_id="inclusion-reject/path-too-long"),
]
consistency_cases = [consistency_case(m, LOG_SIZE) for m in (0, 1, 5, 8, 12, 16, 17)] + [consistency_case(3, 7)]
consistency_cases += [
    consistency_case(5, LOG_SIZE, second=roots[16], expect=proof_reject("proof-mismatch"), case_id="consistency-reject/wrong-second-root"),
    consistency_case(LOG_SIZE, 16, path=[], expect=proof_reject("proof-range"), case_id="consistency-reject/first-above-second"),
    consistency_case(8, LOG_SIZE, path=consistency_path(8, log_leaves) + [roots[1]], expect=proof_reject("proof-length"), case_id="consistency-reject/path-too-long"),
]


def note_key_id(name, kind, key):
    return sha(name.encode() + bytes([0x0a, kind]) + key)[:4]


def b64(b):
    return base64.b64encode(b).decode()


def vkey(name, kind, key):
    return "%s+%s+%s" % (name, note_key_id(name, kind, key).hex(), b64(bytes([kind]) + key))


def note_line(name, raw):
    return "— %s %s\n" % (name, b64(raw))


ORIGIN = "work.example/ledger/" + LEDGER[1].hex()
LOG_SEED = RFC8032_SEEDS[2]
WITNESS = "witness.example/w1"
WITNESS_SEED = sha(b"work-vector:witness-seed:w1")
log_public = ed25519(LOG_SEED, b"")[0]
witness_public = ed25519(WITNESS_SEED, b"")[0]
COSIGNED_AT = 1792109120


PROFILE = ["durability quorum", "time_sources independent", "witness independent 2"]


def checkpoint_body(size, root, profile=PROFILE):
    return "%s\n%d\n%s\n" % (ORIGIN, size, b64(root)) + "".join(line + "\n" for line in profile)


def log_signature(body):
    return note_line(ORIGIN, note_key_id(ORIGIN, 0x01, log_public) + ed25519(LOG_SEED, body.encode())[1])


def cosignature(body, at, signed_at=None):
    message = ("cosignature/v1\ntime %d\n%s" % (at if signed_at is None else signed_at, body)).encode()
    raw = note_key_id(WITNESS, 0x04, witness_public) + at.to_bytes(8, "big") + ed25519(WITNESS_SEED, message)[1]
    return note_line(WITNESS, raw)


body = checkpoint_body(LOG_SIZE, roots[LOG_SIZE])
signed_note = body + "\n" + log_signature(body) + cosignature(body, COSIGNED_AT)
checkpoint_cases = [
    {"id": "checkpoint/log-and-witness", "rules": ["P-11", "P-20", "T-4", "T-64", "OP-33"], "origin": ORIGIN,
     "note": signed_note,
     "expect": {"outcome": "accept", "size": LOG_SIZE, "root_hex": roots[LOG_SIZE].hex(),
                "cosignatures": [{"name": WITNESS, "timestamp": COSIGNED_AT}]}},
    {"id": "checkpoint/log-only", "rules": ["P-11", "T-4", "T-64"], "origin": ORIGIN,
     "note": body + "\n" + log_signature(body),
     "expect": {"outcome": "accept", "size": LOG_SIZE, "root_hex": roots[LOG_SIZE].hex(), "cosignatures": []}},
    {"id": "checkpoint-reject/size-changed", "rules": ["P-11", "T-4", "T-64"], "origin": ORIGIN,
     "note": checkpoint_body(16, roots[LOG_SIZE]) + "\n" + log_signature(body) + cosignature(body, COSIGNED_AT),
     "expect": {"outcome": "reject", "reason": "signature-invalid"}},
    {"id": "checkpoint-reject/other-origin", "rules": ["P-11", "T-4", "T-64"], "origin": "work.example/ledger/other",
     "note": signed_note, "expect": {"outcome": "reject", "reason": "checkpoint-malformed"}},
    {"id": "checkpoint-reject/witness-only", "rules": ["P-20", "T-4", "T-64"], "origin": ORIGIN,
     "note": body + "\n" + cosignature(body, COSIGNED_AT), "expect": {"outcome": "reject", "reason": "note-unverified"}},
    {"id": "checkpoint-reject/cosignature-time-changed", "rules": ["P-20", "T-4", "T-64", "OP-33"], "origin": ORIGIN,
     "note": body + "\n" + log_signature(body) + cosignature(body, COSIGNED_AT + 1, signed_at=COSIGNED_AT),
     "expect": {"outcome": "reject", "reason": "signature-invalid"}},
]
for case in checkpoint_cases:
    if case["expect"]["outcome"] == "accept":
        case["expect"]["profile"] = PROFILE


def profile_case(case_id, profile, expect):
    profiled = checkpoint_body(LOG_SIZE, roots[LOG_SIZE], profile)
    return {"id": case_id, "rules": ["OP-46", "T-88"], "origin": ORIGIN,
            "note": profiled + "\n" + log_signature(profiled), "expect": expect}


def profile_accept(case_id, profile):
    return profile_case(case_id, profile, {"outcome": "accept", "size": LOG_SIZE, "root_hex": roots[LOG_SIZE].hex(),
                                           "cosignatures": [], "profile": profile})


def profile_reject(case_id, profile):
    return profile_case(case_id, profile, {"outcome": "reject", "reason": "checkpoint-malformed"})


checkpoint_cases += [
    profile_accept("checkpoint/profile-single-node-local-dependent",
                   ["durability single-node", "time_sources dependent", "witness local-dependent"]),
    profile_accept("checkpoint/profile-witness-none", ["durability single-node", "time_sources independent", "witness none"]),
    profile_accept("checkpoint/profile-independent-255", ["durability quorum", "time_sources dependent", "witness independent 255"]),
    profile_reject("checkpoint-reject/profile-missing", []),
    profile_reject("checkpoint-reject/profile-witness-missing", PROFILE[:2]),
    profile_reject("checkpoint-reject/profile-extra", PROFILE + ["extra line"]),
    profile_reject("checkpoint-reject/profile-repeated", PROFILE + PROFILE[2:]),
    profile_reject("checkpoint-reject/profile-out-of-order", [PROFILE[1], PROFILE[0], PROFILE[2]]),
    profile_reject("checkpoint-reject/profile-unknown-durability", ["durability eventual"] + PROFILE[1:]),
    profile_reject("checkpoint-reject/profile-unknown-time-sources", [PROFILE[0], "time_sources none", PROFILE[2]]),
    profile_reject("checkpoint-reject/profile-witness-zero", PROFILE[:2] + ["witness independent 0"]),
    profile_reject("checkpoint-reject/profile-witness-leading-zero", PROFILE[:2] + ["witness independent 02"]),
    profile_reject("checkpoint-reject/profile-witness-above-255", PROFILE[:2] + ["witness independent 256"]),
]
write_json("merkle.json", {
    "file": "merkle.json",
    "notes": ["the leaves are the envelope bytes in ledger order: genesis.json genesis/accept at index 0, the records.json envelopes at 1 to 11 and the records-quarantine.json envelopes at 12 to 16; a record at pos p is leaf p",
              "leaf hash = SHA-256(0x00 || envelope), node = SHA-256(0x01 || left || right), the empty tree is SHA-256(\"\") (RFC 9162 section 2.1, P-101)",
              "inclusion and consistency proofs are RFC 9162 section 2.1.3 and 2.1.4 audit paths; reject codes are the suiss-crypto ProofError and NoteError codes",
              "checkpoints are C2SP tlog-checkpoint bodies in C2SP signed notes, signed by the log key and cosigned with tlog-cosignature/v1; the log key is the RFC 8032 section 7.1 test 3 Ed25519 key, the witness key a work-vector seed",
              "the origin is the installation prefix work.example/ledger/ followed by the LedgerID in 64 lowercase hex (OP-46 item 1)",
              "a Work checkpoint body carries exactly three extension lines after the root, in this order: durability (quorum, single-node), time_sources (independent, dependent) and witness (independent k with k 1 to 255 and no leading zero, local-dependent, none); a missing, extra, repeated, reordered or unknown line is checkpoint-malformed under a valid log signature (OP-46 item 3)",
              "keys give the Ed25519 public key and the C2SP verifier key string; the log key's string carries '+' in its base64, which the verifier key parser keeps inside the key"],
    "nodes": [{"id": "node/genesis-and-first", "rules": ["P-101"], "left_hex": leaf_hashes[0].hex(),
               "right_hex": leaf_hashes[1].hex(), "prefix_hex": "01",
               "digest_hex": sha(b"\x01" + leaf_hashes[0] + leaf_hashes[1]).hex()}],
    "roots": [{"size": n, "root_hex": roots[n].hex()} for n in range(LOG_SIZE + 1)],
    "inclusion": inclusion_cases,
    "consistency": consistency_cases,
    "keys": {"log": {"name": ORIGIN, "public_key_hex": log_public.hex(), "vkey": vkey(ORIGIN, 0x01, log_public)},
             "witnesses": [{"name": WITNESS, "public_key_hex": witness_public.hex(),
                            "vkey": vkey(WITNESS, 0x04, witness_public)}]},
    "checkpoints": checkpoint_cases})


# EV-3 EV-4 EV-8 P-6 P-102
statement = variant(rec_act["evidence"][0], signature=None)
statement_bytes = enc(statement)
presenter = SIGNERS[SUPPLIER]
ev_protected, ev_signature = sign1(presenter, statement_bytes)
ev_cose = cose_bytes(ev_protected, statement_bytes, ev_signature)
check(ev_cose, allowed_tags=(18,))
foreign_ev_protected, foreign_ev_signature = sign1(SIGNERS[AGENT], statement_bytes)
foreign_ev_cose = cose_bytes(foreign_ev_protected, statement_bytes, foreign_ev_signature)


def with_evidence(**changes):
    return variant(rec_act, evidence=[variant(rec_act["evidence"][0], **changes)])


EV_RULES = ["EV-3", "EV-8", "P-6", "P-102"]
evidence_signed = [
    ("presenter-signed", with_evidence(signature=[-16, sha(ev_cose)]), SUPPLIER, ev_cose,
     {"outcome": "accept"}, "The records.json Act with its evidence reference signed by the presenting supplier over the statement."),
    ("statement-changed", with_evidence(claimed_at=1792108700001, signature=[-16, sha(ev_cose)]), SUPPLIER, ev_cose,
     {"outcome": "reject", "reason": "signature:invalid"}, "The record's statement has another claimed_at than the statement the presenter signed."),
    ("signature-digest-mismatch", with_evidence(), SUPPLIER, ev_cose,
     {"outcome": "reject", "reason": "signature:invalid"}, "The reference names another COSE_Sign1 than the one presented."),
    ("presenter-not-key-owner", with_evidence(signature=[-16, sha(foreign_ev_cose)]), AGENT, foreign_ev_cose,
     {"outcome": "reject", "reason": "signature:kid_unknown"}, "The agent signs a statement whose presenter is the supplier."),
]
evidence_cases = []
for name, rec, party, cose, expect, purpose in evidence_signed:
    b = enc(rec)
    assert semantic(rec, ctx(rec)) == ("accept", None), name
    write_cbor("SignedRecord", "evidence-" + name, b, "pass")
    evidence_cases.append({"id": "evidence/" + name, "rules": EV_RULES, "purpose": purpose, "hex": b.hex(),
                           "decoded": decoded(b), "record_digest": enc([-16, sha(b)]).hex(), "evidence_index": 0,
                           "statement_hex": statement_bytes.hex(), "presenter": party, "cose_hex": cose.hex(),
                           "cddl": "pass", "expect": expect})
evidence_missing = [
    ("subject-missing", with_evidence(subject=None)),
    ("type-missing", with_evidence(type=None)),
    ("presenter-missing", with_evidence(presenter=None)),
    ("signature-missing", with_evidence(signature=None)),
    ("subject-not-digest-or-id", with_evidence(subject=7)),
]
for name, rec in evidence_missing:
    b = enc(rec)
    check(b)
    write_cbor("SignedRecord", "evidence-reject-" + name, b, "fail")
    evidence_cases.append({"id": "evidence-reject/" + name, "rules": ["EV-3", "P-10", "P-11"], "hex": b.hex(),
                           "decoded": decoded(b, rec), "cddl": "fail",
                           "expect": {"outcome": "reject", "reason": "schema:required_field"}})
write_json("evidence.json", {
    "file": "evidence.json",
    "notes": ["the presenter signs the EvidenceStatement: the det-CBOR of the evidence reference without its signature field, statement_hex; signature in the reference is SHA-256 of the presenter's full tagged COSE_Sign1 bytes, cose_hex",
              "the presenter's COSE_Sign1 uses the Work record profile of P-102, protected header {1: alg, 3: \"application/work-record+cbor\", 4: kid}; the keys are those of cose-sign1.json",
              "a signed case is checked against the keys of its presenter party with Ed25519, ESP256 and ES256 allowed; evidence-reject cases are records the decoder rejects"],
    "cases": evidence_cases})

# T-10 P-31 P-108
def written(name):
    with open(os.path.join(OUT, name)) as f:
        return json.load(f)


derive_records_file = written("records.json")
derive_cose = written("cose-sign1.json")
derive_genesis = written("genesis.json")["cases"][0]
derive_signed = {c["envelope"]: c["cose_hex"] for c in derive_cose["cases"] if c.get("envelope")}
derive_keys = {}
for k in derive_cose["keys"]:
    derive_keys.setdefault(k["party"], []).append(
        {"kid": k["kid_hex"], "alg": k["alg"], "public_key": k["public_key_hex"]})
derive_entries = []
for r, e in zip(derive_records_file["records"], derive_records_file["envelopes"]):
    author = r["decoded"]["author"]
    entry = {"envelope": e["hex"], "record": r["hex"]}
    cose_hex = derive_signed.get("records.json " + e["id"])
    if cose_hex is not None:
        entry["cose_sign1"] = cose_hex
    entry["author_keys"] = {"party": author, "allowed": [-19, -9, -7], "keys": derive_keys.get(author, [])}
    entry["restriction"] = "no_objection"
    entry["issuer"] = "local"
    derive_entries.append(entry)
write_json("derive-entries.json", {
    "at": {"ledger": [-16, derive_genesis["ledger_id"]["digest_hex"]], "prev": [-16, derive_genesis["leaf_hash"]]},
    "entries": derive_entries})

if CBOR_OUT is not None:
    with open(os.path.join(CBOR_OUT, "manifest"), "w") as f:
        f.write("\n".join(manifest) + "\n")
