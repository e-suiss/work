#![allow(clippy::arithmetic_side_effects, reason = "test code")]

use serde_json::{Map, Value, json};
use suiss_crypto::cose::KeySet;
use suiss_crypto::pkcs11::{HsmSigner, KeyStore};
use suiss_crypto::signer::Signer as _;

use super::*;
use crate::domain::b64url;
use crate::domain::keys::tests::token;
use crate::domain::metadata::thumbprint;

pub(crate) const ISSUER: &str = "https://access-server:8443/realms/platform";
pub(crate) const CLIENT: &str = "cli_work";
pub(crate) const NOW: u64 = 1_793_793_600_000;
pub(crate) const TENANT: &str = "tnt_0123456789abcdefghjkmnpqrs";
pub(crate) const DOMAIN: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";
const KID: &str = "-Y4E9TMm6RHXdEMV2FRRKJiFNF_gobJnrL4wNhDQHX8";

/// The platform realm's two signing keys, born in a token of the test's own, the key set its
/// JWKS reads as, and the token, for further keys of the same test.
pub(crate) struct RealmKeys {
    pub(crate) es256: HsmSigner,
    pub(crate) ed25519: HsmSigner,
    pub(crate) set: KeySet,
    pub(crate) store: KeyStore,
}

pub(crate) fn realm_keys(test: &str) -> RealmKeys {
    let (_, store) = token(test);
    let (es256, ed25519, set) = keys_in(&store, "realm");
    RealmKeys {
        es256,
        ed25519,
        set,
        store,
    }
}

/// Another pair of signing keys in `store` under `prefix`, with the key set of that pair alone.
pub(crate) fn keys_in(store: &KeyStore, prefix: &str) -> (HsmSigner, HsmSigner, KeySet) {
    let es256 = store.generate_p256(&format!("{prefix}-es256")).unwrap();
    let ed25519 = store
        .generate_ed25519(&format!("{prefix}-ed25519"))
        .unwrap();
    let mut set = KeySet::default();
    for key in [es256.public_key(), ed25519.public_key()] {
        set.insert(thumbprint(&key), key).unwrap();
    }
    (es256, ed25519, set)
}

/// The claims of one event as Access writes them for the platform stream.
pub(crate) fn claims_of(name: &str, payload: &Value, tenant: Option<&str>, jti: u8) -> Value {
    let mut events = Map::new();
    events.insert(format!("{EVENT_PREFIX}{name}"), payload.clone());
    let mut c = json!({
        "iss": ISSUER,
        "aud": CLIENT,
        "iat": NOW / 1000,
        "jti": b64url(&[jti; 32]),
        "sub_id": {"format": "opaque", "id": TENANT},
        "events": events,
    });
    if let Some(t) = tenant {
        c["access_tenant"] = json!(t);
    }
    c
}

/// A compact SET of `claims` under `header`, signed by `key`.
pub(crate) fn signed_with(key: &HsmSigner, header: &Value, claims: &Value) -> Vec<u8> {
    let input = format!(
        "{}.{}",
        b64url(header.to_string().as_bytes()),
        b64url(claims.to_string().as_bytes())
    );
    let signature = key.sign(input.as_bytes()).unwrap();
    format!("{input}.{}", b64url(&signature)).into_bytes()
}

/// A compact SET signed as Access signs it.
pub(crate) fn signed(key: &HsmSigner, alg: &str, claims: &Value) -> Vec<u8> {
    let header =
        json!({"alg": alg, "kid": b64url(&thumbprint(&key.public_key())), "typ": SET_TYPE});
    signed_with(key, &header, claims)
}

pub(crate) fn revoked() -> Value {
    json!({
        "domain": DOMAIN,
        "source": {"exercise": "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk"},
        "subject": {"kind": "grant", "id": "BQUFBQUFBQUFBQUFBQUFBQ"},
        "at": NOW,
    })
}

pub(crate) fn compromised(window_from: Option<u64>) -> Value {
    let mut p = json!({
        "domain": DOMAIN,
        "source": {"claim": "CAgICAgICAgICAgICAgICA"},
        "party": "AgICAgICAgICAgICAgICAg",
        "instances": ["BAQEBAQEBAQEBAQEBAQEBA"],
        "kids": [KID],
        "declared_at": NOW,
        "evidence_digest": "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk",
    });
    if let Some(from) = window_from {
        p["window_from"] = json!(from);
    }
    p
}

const fn expected(now_ms: u64) -> Expected<'static> {
    Expected {
        issuer: ISSUER,
        audience: CLIENT,
        now_ms,
    }
}

fn read(bytes: &[u8], keys: &KeySet) -> Result<Set, Refusal> {
    let set = parse(bytes)?;
    claims(set.verify(keys)?, &expected(NOW))
}

// T-102
#[test]
fn t_102_a_set_signed_by_the_realm_key_is_accepted() {
    let keys = realm_keys("t102-accept");
    let c = claims_of("authority-revoked", &revoked(), Some(TENANT), 1);
    for (key, alg) in [(&keys.es256, "ES256"), (&keys.ed25519, "Ed25519")] {
        let set = read(&signed(key, alg, &c), &keys.set).unwrap();
        assert_eq!(set.iss, ISSUER);
        assert_eq!(set.jti, b64url(&[1; 32]));
        assert_eq!(set.tenant.as_str(), TENANT);
        assert_eq!(
            set.event,
            Event::Revocation {
                name: "authority-revoked".to_owned(),
                domain: DomainId(fixed_b64url(DOMAIN).unwrap()),
            }
        );
    }
    let mut tampered = signed(&keys.es256, "ES256", &c);
    let last = tampered.len() - 2;
    tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
    assert_eq!(
        read(&tampered, &keys.set),
        Err(Refusal::AuthenticationFailed)
    );
    let (stranger, _, _) = keys_in(&keys.store, "stranger");
    assert_eq!(
        read(&signed(&stranger, "ES256", &c), &keys.set),
        Err(Refusal::InvalidKey("unknown kid"))
    );
    let wrong_alg = json!({"alg": "ES256", "kid": b64url(&thumbprint(&keys.ed25519.public_key())), "typ": SET_TYPE});
    assert_eq!(
        read(&signed_with(&keys.ed25519, &wrong_alg, &c), &keys.set),
        Err(Refusal::InvalidKey("alg does not fit the key"))
    );
}

// T-102
#[test]
fn t_102_an_eddsa_header_is_refused() {
    let keys = realm_keys("t102-eddsa");
    let c = claims_of("authority-revoked", &revoked(), Some(TENANT), 2);
    let refused = read(&signed(&keys.ed25519, "EdDSA", &c), &keys.set);
    assert_eq!(refused, Err(Refusal::InvalidRequest("alg")));
    assert_eq!(refused.unwrap_err().code(), "invalid_request");
}

// T-102
#[test]
fn t_102_no_hmac_signed_event_is_accepted() {
    let keys = realm_keys("t102-hmac");
    let c = claims_of("authority-revoked", &revoked(), Some(TENANT), 3);
    for alg in ["HS256", "HS512", "none", "ES384"] {
        assert_eq!(
            read(&signed(&keys.es256, alg, &c), &keys.set),
            Err(Refusal::InvalidRequest("alg")),
            "{alg}"
        );
    }
    let jwt =
        json!({"alg": "ES256", "kid": b64url(&thumbprint(&keys.es256.public_key())), "typ": "JWT"});
    assert_eq!(
        read(&signed_with(&keys.es256, &jwt, &c), &keys.set),
        Err(Refusal::InvalidRequest("typ"))
    );
    let webhook =
        br#"{"specversion":"1.0","type":"urn:suiss:access:event:authority-revoked","data":{}}"#;
    assert_eq!(
        verifier(Some("application/json")),
        Verifier::Unsupported,
        "the Suiss webhook profile is never read"
    );
    assert!(parse(webhook).is_err());
}

// T-102
#[test]
fn t_102_the_content_type_alone_selects_the_verifier() {
    assert_eq!(verifier(Some(SET_CONTENT_TYPE)), Verifier::Access);
    assert_eq!(verifier(Some("Application/SecEvent+JWT")), Verifier::Access);
    assert_eq!(verifier(Some(CLOUDEVENTS_CONTENT_TYPE)), Verifier::Relay);
    for other in [
        None,
        Some(""),
        Some("application/jwt"),
        Some("application/json"),
        Some("application/secevent+jwt; charset=utf-8"),
        Some("text/plain"),
    ] {
        assert_eq!(verifier(other), Verifier::Unsupported, "{other:?}");
    }
}

// T-102
#[test]
fn t_102_a_platform_set_takes_its_tenant_from_access_tenant() {
    let keys = realm_keys("t102-tenant");
    let other = "tnt_zzzzzzzzzzzzzzzzzzzzzzzzzz";
    let created = json!({"tenant": other, "placement": "pool-default", "at": NOW});
    let set = read(
        &signed(
            &keys.es256,
            "ES256",
            &claims_of("tenant.created", &created, Some(TENANT), 4),
        ),
        &keys.set,
    )
    .unwrap();
    assert_eq!(set.tenant.as_str(), TENANT);
    assert_eq!(set.event, Event::TenantCreated);
    let client = json!({"tenant": other, "realm": "019a0000-0000-7000-8000-0000000000a1", "client_id": CLIENT, "exercise": DOMAIN, "at": NOW});
    let platform = read(
        &signed(
            &keys.es256,
            "ES256",
            &claims_of("api_client.disabled", &client, None, 5),
        ),
        &keys.set,
    )
    .unwrap();
    assert_eq!(platform.tenant.as_str(), other);
    assert_eq!(
        platform.event,
        Event::ApiClient {
            change: ClientChange::Disabled,
            client_id: CLIENT.to_owned(),
        }
    );
}

// T-102
#[test]
fn t_102_a_set_without_access_tenant_is_invalid_request() {
    let keys = realm_keys("t102-no-tenant");
    for (name, payload) in [
        ("authority-revoked", revoked()),
        ("party.compromised", compromised(Some(NOW - 1))),
        (
            "tenant.created",
            json!({"tenant": TENANT, "placement": "pool-default", "at": NOW}),
        ),
    ] {
        let refused = read(
            &signed(&keys.es256, "ES256", &claims_of(name, &payload, None, 6)),
            &keys.set,
        );
        assert_eq!(
            refused,
            Err(Refusal::InvalidRequest("access_tenant")),
            "{name}"
        );
        let body: Value = serde_json::from_slice(&refused.unwrap_err().body()).unwrap();
        assert_eq!(body["err"], "invalid_request");
    }
    let uuid = claims_of(
        "authority-revoked",
        &revoked(),
        Some("019a0000-0000-7000-8000-0000000000a1"),
        7,
    );
    assert_eq!(
        read(&signed(&keys.es256, "ES256", &uuid), &keys.set),
        Err(Refusal::InvalidRequest("access_tenant"))
    );
}

// T-102
#[test]
fn t_102_issuer_audience_age_and_jti_are_checked() {
    let keys = realm_keys("t102-claims");
    let base = claims_of("authority-revoked", &revoked(), Some(TENANT), 8);
    let with = |key: &str, value: Value| {
        let mut c = base.clone();
        c[key] = value;
        read(&signed(&keys.es256, "ES256", &c), &keys.set)
    };
    assert_eq!(
        with("iss", json!("https://access-server:8443/realms/acme")),
        Err(Refusal::InvalidIssuer)
    );
    assert_eq!(
        with("aud", json!("cli_other")),
        Err(Refusal::InvalidAudience)
    );
    assert!(with("aud", json!(["cli_other", CLIENT])).is_ok());
    let stale = (NOW - IAT_MAX_AGE_MS - 1000) / 1000;
    assert_eq!(
        with("iat", json!(stale)),
        Err(Refusal::InvalidRequest("iat"))
    );
    let ahead = (NOW + IAT_SKEW_MS + 1000) / 1000;
    assert_eq!(
        with("iat", json!(ahead)),
        Err(Refusal::InvalidRequest("iat"))
    );
    assert_eq!(
        with("jti", json!("short")),
        Err(Refusal::InvalidRequest("jti"))
    );
    let mut two = Map::new();
    two.insert(format!("{EVENT_PREFIX}authority-revoked"), revoked());
    two.insert(format!("{EVENT_PREFIX}mandate-ended"), revoked());
    assert_eq!(
        with("events", Value::Object(two)),
        Err(Refusal::InvalidRequest("events"))
    );
    assert_eq!(
        with("events", json!({"urn:other:event": revoked()})),
        Err(Refusal::InvalidRequest("events"))
    );
    assert_eq!(
        parse(b"a.b"),
        Err(Refusal::InvalidRequest("compact serialization"))
    );
    assert_eq!(
        parse(&vec![b'a'; MAX_SET_BYTES + 1]),
        Err(Refusal::InvalidRequest("size"))
    );
}

// T-102
#[test]
fn t_102_a_compromise_carries_its_window_from_window_from() {
    let keys = realm_keys("t102-window");
    let windowed = read(
        &signed(
            &keys.ed25519,
            "Ed25519",
            &claims_of(
                "party.compromised",
                &compromised(Some(NOW - 60_000)),
                Some(TENANT),
                9,
            ),
        ),
        &keys.set,
    )
    .unwrap();
    let Event::Compromised { window, kids, .. } = windowed.event else {
        panic!("{windowed:?}");
    };
    assert_eq!(window, Some((NOW - 60_000, NOW)));
    assert_eq!(kids, vec![Kid::parse(KID).unwrap()]);
    let bare = read(
        &signed(
            &keys.ed25519,
            "Ed25519",
            &claims_of("party.compromised", &compromised(None), Some(TENANT), 10),
        ),
        &keys.set,
    )
    .unwrap();
    assert!(matches!(
        bare.event,
        Event::Compromised { window: None, .. }
    ));
    let backwards = read(
        &signed(
            &keys.ed25519,
            "Ed25519",
            &claims_of(
                "party.compromised",
                &compromised(Some(NOW + 1)),
                Some(TENANT),
                11,
            ),
        ),
        &keys.set,
    );
    assert_eq!(backwards, Err(Refusal::InvalidRequest("window_from")));
}

// T-102
#[test]
fn t_102_every_type_of_the_access_catalog_is_read() {
    let keys = realm_keys("t102-catalog");
    let instance = json!({"domain": DOMAIN, "source": {"exercise": DOMAIN}, "subject": {"kind": "instance", "id": "BAQEBAQEBAQEBAQEBAQEBA"}, "at": NOW, "party": "AgICAgICAgICAgICAgICAg"});
    let disabled = json!({"domain": DOMAIN, "source": {"exercise": DOMAIN}, "party": "AgICAgICAgICAgICAgICAg", "at": NOW, "reason_class": "departed"});
    let org = json!({"tenant": TENANT, "organization": "org_1", "at": NOW});
    let cases = [
        ("instance-terminated", instance),
        ("party.disabled", disabled),
        ("organization.created", org.clone()),
        ("verification", org),
    ];
    let names: Vec<String> = cases
        .iter()
        .enumerate()
        .map(|(n, (name, payload))| {
            let jti = u8::try_from(n).unwrap() + 20;
            read(
                &signed(
                    &keys.es256,
                    "ES256",
                    &claims_of(name, payload, Some(TENANT), jti),
                ),
                &keys.set,
            )
            .unwrap()
            .event
            .name()
            .to_owned()
        })
        .collect();
    assert_eq!(
        names,
        [
            "instance-terminated",
            "party.disabled",
            "organization.created",
            "verification"
        ]
    );
    for name in [
        "authority-narrowed",
        "authority-expired",
        "mandate-ended",
        "revalidation-required",
        "projection-invalidated",
    ] {
        let set = read(
            &signed(
                &keys.es256,
                "ES256",
                &claims_of(name, &revoked(), Some(TENANT), 30),
            ),
            &keys.set,
        )
        .unwrap();
        assert!(matches!(set.event, Event::Revocation { .. }), "{name}");
    }
}
