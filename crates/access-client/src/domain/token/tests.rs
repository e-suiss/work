#![allow(clippy::arithmetic_side_effects, reason = "test code")]

use std::collections::BTreeSet;

use serde_json::json;
use suiss_crypto::cose::Algorithm;
use suiss_crypto::pkcs11::{HsmSigner, KeyStore};
use suiss_crypto::sig::{P256_HALF_N, P256_N};
use suiss_crypto::signer::Signer as _;

use super::*;
use crate::domain::keys::tests::token as hsm;

const REALM: &str = "https://access.example/realms/acme";
const WORK: &str = "cli_work";
const NOW: u64 = 1_793_793_600_000;
const URL: &str = "https://work.example/v1/ledgers/led_01/works/wrk_02";

/// `sig` with its S in the lower half of the group order, as Access signs (CR-9).
fn low_s(mut sig: Vec<u8>) -> Vec<u8> {
    let s: [u8; 32] = sig[32..].try_into().unwrap();
    if s.as_slice() > P256_HALF_N.as_slice() {
        let mut out = [0_u8; 32];
        let mut borrow = 0_u16;
        for i in (0..32).rev() {
            let d = u16::from(P256_N[i])
                .wrapping_add(256)
                .wrapping_sub(u16::from(s[i]))
                .wrapping_sub(borrow);
            out[i] = d.to_le_bytes()[0];
            borrow = u16::from(d < 256);
        }
        sig[32..].copy_from_slice(&out);
    }
    sig
}

fn jws(signer: &HsmSigner, header: &Value, claims: &Value) -> String {
    let h = b64url(&serde_json::to_vec(header).unwrap());
    let p = b64url(&serde_json::to_vec(claims).unwrap());
    let input = format!("{h}.{p}");
    let mut sig = signer.sign(input.as_bytes()).unwrap();
    if matches!(signer.public_key(), PublicKey::P256(_)) {
        sig = low_s(sig);
    }
    format!("{input}.{}", b64url(&sig))
}

fn jwk(key: &PublicKey) -> Value {
    match key {
        PublicKey::Ed25519(x) => json!({"kty": "OKP", "crv": "Ed25519", "x": b64url(x)}),
        PublicKey::P256(sec1) => json!({
            "kty": "EC",
            "crv": "P-256",
            "x": b64url(&sec1[1..33]),
            "y": b64url(&sec1[33..65]),
        }),
        PublicKey::MlDsa(..) => Value::Null,
    }
}

struct Keys {
    store: KeyStore,
    realm: HsmSigner,
    realm_p256: HsmSigner,
    holder: HsmSigner,
    set: KeySet,
}

fn keys(test: &str) -> Keys {
    let (_, store) = hsm(test);
    let realm = store.generate_ed25519("realm-ed").unwrap();
    let realm_p256 = store.generate_p256("realm-ec").unwrap();
    let holder = store.generate_p256("holder").unwrap();
    let mut set = KeySet {
        allowed: BTreeSet::from([Algorithm::Ed25519, Algorithm::Esp256]),
        ..KeySet::default()
    };
    for signer in [&realm, &realm_p256] {
        let key = signer.public_key();
        set.insert(thumbprint(&key), key).unwrap();
    }
    Keys {
        store,
        realm,
        realm_p256,
        holder,
        set,
    }
}

fn header(signer: &HsmSigner) -> Value {
    let alg = match signer.public_key() {
        PublicKey::Ed25519(_) => "Ed25519",
        _ => "ES256",
    };
    json!({"alg": alg, "kid": b64url(&thumbprint(&signer.public_key())), "typ": "at+jwt"})
}

fn claims(holder: &HsmSigner) -> Value {
    json!({
        "iss": REALM,
        "sub": "5h0Jq3Ylq4dpXGqGw4Vwq3a3n9GQ3Z8vPm1hS7fXk2Q",
        "aud": [WORK, REALM],
        "client_id": "cli_web",
        "iat": NOW / 1000 - 30,
        "exp": NOW / 1000 + 570,
        "jti": "at-1",
        "scope": "openid work",
        "sid": "c2lk",
        "cnf": {"jkt": b64url(&thumbprint(&holder.public_key()))},
    })
}

fn rules() -> TokenRules<'static> {
    TokenRules {
        issuer: REALM,
        audience: WORK,
        now_ms: NOW,
    }
}

fn proof_claims(token: &str) -> Value {
    json!({
        "jti": "p-1",
        "htm": "GET",
        "htu": URL,
        "iat": NOW / 1000,
        "ath": token_hash(token),
    })
}

fn proof(holder: &HsmSigner, claims: &Value) -> String {
    let header = json!({"alg": "ES256", "typ": "dpop+jwt", "jwk": jwk(&holder.public_key())});
    jws(holder, &header, claims)
}

fn proof_rules<'a>(token: &'a str, jkt: &'a [u8; 32]) -> ProofRules<'a> {
    ProofRules {
        method: "GET",
        url: URL,
        token,
        jkt,
        now_ms: NOW,
    }
}

// E-7 C-9 T-28
#[test]
fn e_7_a_token_signed_by_the_realm_key_names_the_pairwise_subject_of_its_client() {
    let k = keys("token-ok");
    for signer in [&k.realm, &k.realm_p256] {
        let token = jws(signer, &header(signer), &claims(&k.holder));
        assert_eq!(
            unverified(&token).unwrap(),
            (REALM.to_owned(), thumbprint(&signer.public_key()))
        );
        let verified = verify_access_token(&token, &k.set, &rules()).unwrap();
        assert_eq!(verified.issuer, REALM);
        assert_eq!(verified.sub, "5h0Jq3Ylq4dpXGqGw4Vwq3a3n9GQ3Z8vPm1hS7fXk2Q");
        assert_eq!(verified.client_id, "cli_web");
        assert_eq!(verified.scope, "openid work");
        assert_eq!(verified.jkt, thumbprint(&k.holder.public_key()));
        assert_eq!(verified.exp_ms, NOW + 570_000);
    }
    let mut single = claims(&k.holder);
    single["aud"] = json!(WORK);
    let token = jws(&k.realm, &header(&k.realm), &single);
    assert!(verify_access_token(&token, &k.set, &rules()).is_ok());
}

// E-7 C-9
#[test]
fn e_7_a_token_of_another_key_issuer_audience_or_time_is_refused() {
    let k = keys("token-refused");
    let token = |claims: &Value| jws(&k.realm, &header(&k.realm), claims);
    let refused = |claims: &Value| verify_access_token(&token(claims), &k.set, &rules());
    let base = claims(&k.holder);
    let mut other = base.clone();
    other["iss"] = json!("https://access.example/realms/globex");
    assert_eq!(refused(&other), Err(TokenRefusal::Issuer));
    let mut realm_only = base.clone();
    realm_only["aud"] = json!(REALM);
    assert_eq!(refused(&realm_only), Err(TokenRefusal::Audience));
    let mut expired = base.clone();
    expired["exp"] = json!(NOW / 1000 - 61);
    assert_eq!(refused(&expired), Err(TokenRefusal::Expired));
    let mut grace = base.clone();
    grace["exp"] = json!(NOW / 1000 - 59);
    assert!(refused(&grace).is_ok());
    let mut early = base.clone();
    early["nbf"] = json!(NOW / 1000 + 61);
    assert_eq!(refused(&early), Err(TokenRefusal::NotYetValid));
    let mut unbound = base.clone();
    unbound.as_object_mut().unwrap().remove("cnf");
    assert_eq!(refused(&unbound), Err(TokenRefusal::Claims));
    let mut anonymous = base.clone();
    anonymous.as_object_mut().unwrap().remove("sub");
    assert_eq!(refused(&anonymous), Err(TokenRefusal::Claims));

    let stranger = k.store.generate_ed25519("stranger").unwrap();
    let forged = jws(&stranger, &header(&stranger), &base);
    assert_eq!(
        verify_access_token(&forged, &k.set, &rules()),
        Err(TokenRefusal::UnknownKid)
    );
    let mut kid_swap = header(&stranger);
    kid_swap["kid"] = header(&k.realm)["kid"].clone();
    let swapped = jws(&stranger, &kid_swap, &base);
    assert_eq!(
        verify_access_token(&swapped, &k.set, &rules()),
        Err(TokenRefusal::Signature)
    );
    let good = token(&base);
    let (head, rest) = good.split_once('.').unwrap();
    let (_, sig) = rest.split_once('.').unwrap();
    let tampered = format!(
        "{head}.{}.{sig}",
        b64url(&serde_json::to_vec(&other).unwrap())
    );
    assert_eq!(
        verify_access_token(&tampered, &k.set, &rules()),
        Err(TokenRefusal::Signature)
    );
}

// E-7 C-9 SEC-18
#[test]
fn e_7_a_token_outside_the_profile_is_refused_before_its_claims() {
    let k = keys("token-profile");
    let base = claims(&k.holder);
    let with = |patch: &dyn Fn(&mut Value)| {
        let mut h = header(&k.realm);
        patch(&mut h);
        verify_access_token(&jws(&k.realm, &h, &base), &k.set, &rules())
    };
    assert_eq!(
        with(&|h| h["typ"] = json!("JWT")),
        Err(TokenRefusal::Header)
    );
    assert_eq!(
        with(&|h| h["jku"] = json!("https://evil.example/jwks")),
        Err(TokenRefusal::Header)
    );
    assert_eq!(
        with(&|h| h["alg"] = json!("EdDSA")),
        Err(TokenRefusal::Algorithm)
    );
    assert_eq!(
        with(&|h| h["alg"] = json!("none")),
        Err(TokenRefusal::Algorithm)
    );
    assert_eq!(
        with(&|h| h["alg"] = json!("ES256")),
        Err(TokenRefusal::Algorithm)
    );
    let long = "a".repeat(MAX_JWT + 1);
    for bad in ["", "a.b", "a.b.c.d", "eyJ.e30.AA==", long.as_str()] {
        assert_eq!(
            verify_access_token(bad, &k.set, &rules()),
            Err(TokenRefusal::Format),
            "{bad}"
        );
    }
    assert_eq!(TokenRefusal::Replayed.code(), "dpop_proof_replayed");
}

// E-7 SEC-18
#[test]
fn e_7_a_dpop_proof_binds_the_token_to_its_key_and_this_request() {
    let k = keys("proof");
    let token = jws(&k.realm, &header(&k.realm), &claims(&k.holder));
    let jkt = thumbprint(&k.holder.public_key());
    let ok = proof(&k.holder, &proof_claims(&token));
    assert_eq!(
        verify_proof(&ok, &proof_rules(&token, &jkt)).unwrap(),
        ProofClaims {
            jti: "p-1".to_owned(),
            iat_ms: NOW,
        }
    );
    let mut with_query = proof_rules(&token, &jkt);
    with_query.url = "https://work.example/v1/ledgers/led_01/works/wrk_02?x=1";
    assert!(verify_proof(&ok, &with_query).is_ok());

    let refused =
        |claims: &Value| verify_proof(&proof(&k.holder, claims), &proof_rules(&token, &jkt));
    let base = proof_claims(&token);
    for (name, value, part) in [
        ("htm", json!("POST"), "htm"),
        (
            "htu",
            json!("https://work.example/v1/ledgers/led_01"),
            "htu",
        ),
        ("ath", json!(token_hash("another token")), "ath"),
        ("iat", json!(NOW / 1000 - 61), "iat"),
        ("iat", json!(NOW / 1000 + 61), "iat"),
        ("jti", json!(""), "jti"),
    ] {
        let mut c = base.clone();
        c[name] = value;
        assert_eq!(refused(&c), Err(TokenRefusal::Proof(part)), "{name}");
    }
    let other = k.store.generate_p256("other").unwrap();
    let foreign = proof(&other, &base);
    assert_eq!(
        verify_proof(&foreign, &proof_rules(&token, &jkt)),
        Err(TokenRefusal::Proof("jkt"))
    );
    let mut lying = json!({"alg": "ES256", "typ": "dpop+jwt", "jwk": jwk(&k.holder.public_key())});
    let signed_by_other = jws(&other, &lying, &base);
    assert_eq!(
        verify_proof(&signed_by_other, &proof_rules(&token, &jkt)),
        Err(TokenRefusal::Proof("signature"))
    );
    lying["jwk"]["d"] = json!(b64url(&[1; 32]));
    assert_eq!(
        verify_proof(&jws(&k.holder, &lying, &base), &proof_rules(&token, &jkt)),
        Err(TokenRefusal::Proof("jwk"))
    );
    let mut kid =
        json!({"alg": "ES256", "typ": "dpop+jwt", "jwk": jwk(&k.holder.public_key()), "kid": "x"});
    assert_eq!(
        verify_proof(&jws(&k.holder, &kid, &base), &proof_rules(&token, &jkt)),
        Err(TokenRefusal::Proof("header"))
    );
    kid.as_object_mut().unwrap().remove("kid");
    kid["typ"] = json!("JWT");
    assert_eq!(
        verify_proof(&jws(&k.holder, &kid, &base), &proof_rules(&token, &jkt)),
        Err(TokenRefusal::Proof("typ"))
    );
    assert_eq!(target_uri("https://w.example/a?b#c"), "https://w.example/a");
}

// E-7 T-99
#[test]
fn e_7_a_service_token_names_its_caller_and_tenant_and_carries_no_authority() {
    let k = keys("token-service");
    let token = |claims: &Value| jws(&k.realm, &header(&k.realm), claims);
    let verify = |claims: &Value| verify_access_token(&token(claims), &k.set, &rules());
    let mut user = claims(&k.holder);
    user["access_tenant"] = json!("tnt_acme");
    let named = verify(&user).unwrap();
    assert_eq!(named.kind, TokenKind::User);
    assert_eq!(named.tenant.as_deref(), Some("tnt_acme"));
    let service = json!({
        "iss": REALM,
        "sub": "9h0Jq3Ylq4dpXGqGw4Vwq3a3n9GQ3Z8vPm1hS7fXk2Q",
        "aud": WORK,
        "client_id": "cli_relay",
        "access_tenant": "tnt_platform",
        "iat": NOW / 1000 - 30,
        "exp": NOW / 1000 + 270,
        "jti": "st-1",
        "cnf": {"jkt": b64url(&thumbprint(&k.holder.public_key()))},
    });
    let caller = verify(&service).unwrap();
    assert_eq!(caller.kind, TokenKind::Service);
    assert_eq!(caller.client_id, "cli_relay");
    assert_eq!(caller.tenant.as_deref(), Some("tnt_platform"));
    assert_eq!(caller.scope, "");
    assert_eq!(caller.jkt, thumbprint(&k.holder.public_key()));
    let mut untenanted = service.clone();
    untenanted.as_object_mut().unwrap().remove("access_tenant");
    assert_eq!(verify(&untenanted).unwrap().tenant, None);
    for (name, value) in [
        ("scope", json!("work")),
        ("authorization_details", json!([{"type": "x"}])),
        ("access_tenant", json!("")),
        ("access_tenant", json!(7)),
    ] {
        let mut more = service.clone();
        more[name] = value;
        assert_eq!(verify(&more), Err(TokenRefusal::Claims), "{name}");
    }
    let mut elsewhere = service;
    elsewhere["aud"] = json!("cli_other");
    assert_eq!(verify(&elsewhere), Err(TokenRefusal::Audience));
}
