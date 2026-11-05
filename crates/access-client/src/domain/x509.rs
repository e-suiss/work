//! The PEP certificate facts Work reads itself (T-101 item 2): the end of its validity and its subject public key, from the DER of an X.509 certificate, so the certificate in the token is known to belong to the token's key and its expiry refuses consequential actions; and the DER form of an ECDSA signature TLS needs.

use suiss_crypto::cose::PublicKey;

use crate::domain::AccessError;

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const VERSION: u8 = 0xa0;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;

const ED25519_SPKI: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const P256_SPKI: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];

/// What the client reads from its certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateFacts {
    /// `notAfter`, Unix milliseconds.
    pub not_after_ms: u64,
    /// The DER `SubjectPublicKeyInfo`.
    pub spki: Vec<u8>,
}

fn bad(what: &'static str) -> AccessError {
    AccessError::Certificate(what)
}

/// A DER element: tag, content, what follows it, and the element's own bytes.
type Element<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

/// One DER element; definite lengths of at most three bytes.
fn element(input: &[u8]) -> Option<Element<'_>> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 3 {
            return None;
        }
        let (bytes, rest) = rest.split_at_checked(n)?;
        if bytes.first() == Some(&0) {
            return None;
        }
        let len = bytes.iter().try_fold(0_usize, |acc, b| {
            acc.checked_mul(256)?.checked_add(usize::from(*b))
        })?;
        if len < 0x80 {
            return None;
        }
        (len, rest)
    };
    let (content, after) = rest.split_at_checked(len)?;
    let whole_len = input.len().checked_sub(after.len())?;
    let whole = input.get(..whole_len)?;
    Some((tag, content, after, whole))
}

/// Reads `notAfter` and the subject public key of a DER certificate.
///
/// # Errors
/// [`AccessError::Certificate`].
pub fn read(der: &[u8]) -> Result<CertificateFacts, AccessError> {
    let (tag, cert, rest, _) = element(der).ok_or_else(|| bad("der"))?;
    if tag != SEQUENCE || !rest.is_empty() {
        return Err(bad("der"));
    }
    let (tag, tbs, _, _) = element(cert).ok_or_else(|| bad("der"))?;
    if tag != SEQUENCE {
        return Err(bad("der"));
    }
    let mut at = tbs;
    let (tag, _, after, _) = element(at).ok_or_else(|| bad("der"))?;
    if tag == VERSION {
        at = after;
    }
    let (tag, _, after, _) = element(at).ok_or_else(|| bad("serial"))?;
    if tag != INTEGER {
        return Err(bad("serial"));
    }
    let (_, _, after, _) = element(after).ok_or_else(|| bad("signature"))?;
    let (_, _, after, _) = element(after).ok_or_else(|| bad("issuer"))?;
    let (tag, validity, after, _) = element(after).ok_or_else(|| bad("validity"))?;
    if tag != SEQUENCE {
        return Err(bad("validity"));
    }
    let (_, _, rest, _) = element(validity).ok_or_else(|| bad("validity"))?;
    let (tag, not_after, _, _) = element(rest).ok_or_else(|| bad("validity"))?;
    let not_after_ms = time_ms(tag, not_after).ok_or_else(|| bad("validity"))?;
    let (_, _, after, _) = element(after).ok_or_else(|| bad("subject"))?;
    let (tag, _, _, spki) = element(after).ok_or_else(|| bad("spki"))?;
    if tag != SEQUENCE {
        return Err(bad("spki"));
    }
    Ok(CertificateFacts {
        not_after_ms,
        spki: spki.to_vec(),
    })
}

pub(crate) fn digits(text: &[u8]) -> Option<u64> {
    text.iter().try_fold(0_u64, |acc, b| {
        b.is_ascii_digit()
            .then(|| {
                acc.checked_mul(10)?
                    .checked_add(u64::from(b.checked_sub(b'0')?))
            })
            .flatten()
    })
}

/// `UTCTime` `YYMMDDHHMMSSZ` or `GeneralizedTime` `YYYYMMDDHHMMSSZ` in Unix milliseconds.
fn time_ms(tag: u8, text: &[u8]) -> Option<u64> {
    let (year, rest) = match tag {
        UTC_TIME if text.len() == 13 => {
            let (yy, rest) = text.split_at_checked(2)?;
            let yy = digits(yy)?;
            (
                if yy >= 50 {
                    yy.checked_add(1900)?
                } else {
                    yy.checked_add(2000)?
                },
                rest,
            )
        }
        GENERALIZED_TIME if text.len() == 15 => {
            let (yyyy, rest) = text.split_at_checked(4)?;
            (digits(yyyy)?, rest)
        }
        _ => return None,
    };
    let (body, z) = rest.split_at_checked(10)?;
    if z != b"Z" {
        return None;
    }
    let field = |i: usize| digits(body.get(i..i.checked_add(2)?)?);
    let (month, day, hour, minute, second) =
        (field(0)?, field(2)?, field(4)?, field(6)?, field(8)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    days.checked_mul(86_400)?
        .checked_add(hour.checked_mul(3600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)?
        .checked_mul(1000)
}

/// Days since 1970-01-01 of a proleptic Gregorian date from 1970 on.
pub(crate) fn days_from_civil(year: u64, month: u64, day: u64) -> Option<u64> {
    if year < 1970 {
        return None;
    }
    let y = if month <= 2 {
        year.checked_sub(1)?
    } else {
        year
    };
    let era = y.checked_div(400)?;
    let yoe = y.checked_sub(era.checked_mul(400)?)?;
    let m = if month > 2 {
        month.checked_sub(3)?
    } else {
        month.checked_add(9)?
    };
    let doy = m
        .checked_mul(153)?
        .checked_add(2)?
        .checked_div(5)?
        .checked_add(day)?
        .checked_sub(1)?;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe.checked_div(4)?)?
        .checked_sub(yoe.checked_div(100)?)?
        .checked_add(doy)?;
    era.checked_mul(146_097)?
        .checked_add(doe)?
        .checked_sub(719_468)
}

/// The DER `SubjectPublicKeyInfo` of a token key.
#[must_use]
pub fn spki_of(key: &PublicKey) -> Option<Vec<u8>> {
    match key {
        PublicKey::Ed25519(k) => Some([ED25519_SPKI.as_slice(), k.as_slice()].concat()),
        PublicKey::P256(sec1) => {
            let point = sec1.strip_prefix(&[0x04])?;
            (point.len() == 64).then(|| [P256_SPKI.as_slice(), point].concat())
        }
        PublicKey::MlDsa(..) => None,
    }
}

fn der_integer(raw: &[u8]) -> Option<Vec<u8>> {
    let start = raw
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(raw.len().checked_sub(1)?);
    let digits = raw.get(start..)?;
    let pad = digits.first().is_some_and(|b| *b >= 0x80);
    let len = u8::try_from(digits.len().checked_add(usize::from(pad))?).ok()?;
    let mut out = vec![INTEGER, len];
    if pad {
        out.push(0);
    }
    out.extend_from_slice(digits);
    Some(out)
}

/// The DER `ECDSA-Sig-Value` of an `r ‖ s` P-256 signature, as TLS carries it.
#[must_use]
pub fn ecdsa_der(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() != 64 {
        return None;
    }
    let (r, s) = raw.split_at_checked(32)?;
    let body = [der_integer(r)?, der_integer(s)?].concat();
    let mut out = vec![SEQUENCE, u8::try_from(body.len()).ok()?];
    out.extend(body);
    Some(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(u8::try_from(len).unwrap());
        } else if len < 0x100 {
            out.extend([0x81, u8::try_from(len).unwrap()]);
        } else {
            out.push(0x82);
            out.extend(u16::try_from(len).unwrap().to_be_bytes());
        }
        out.extend_from_slice(content);
        out
    }

    pub(crate) fn name(cn: &str) -> Vec<u8> {
        let atv = tlv(
            SEQUENCE,
            &[tlv(0x06, &[0x55, 0x04, 0x03]), tlv(0x0c, cn.as_bytes())].concat(),
        );
        tlv(SEQUENCE, &tlv(0x31, &atv))
    }

    /// A self-signed Ed25519 certificate's `TBSCertificate` and its `Certificate` once `sign`
    /// signed it.
    pub(crate) fn certificate(
        spki: &[u8],
        not_after: &str,
        sign: impl Fn(&[u8]) -> Vec<u8>,
    ) -> Vec<u8> {
        let alg = tlv(SEQUENCE, &tlv(0x06, &[0x2b, 0x65, 0x70]));
        let validity = tlv(
            SEQUENCE,
            &[
                tlv(UTC_TIME, b"250101000000Z"),
                tlv(UTC_TIME, not_after.as_bytes()),
            ]
            .concat(),
        );
        let tbs = tlv(
            SEQUENCE,
            &[
                tlv(VERSION, &tlv(INTEGER, &[2])),
                tlv(INTEGER, &[1]),
                alg.clone(),
                name("work-access-pep"),
                validity,
                name("work-access-pep"),
                spki.to_vec(),
            ]
            .concat(),
        );
        let signature = [vec![0], sign(&tbs)].concat();
        tlv(SEQUENCE, &[tbs, alg, tlv(0x03, &signature)].concat())
    }

    // T-101
    #[test]
    fn t_101_the_certificate_expiry_and_key_are_read_from_its_der() {
        let key = PublicKey::Ed25519([9; 32]);
        let spki = spki_of(&key).unwrap();
        let der = certificate(&spki, "261104120000Z", |_| vec![0; 64]);
        let facts = read(&der).unwrap();
        assert_eq!(facts.spki, spki);
        assert_eq!(facts.not_after_ms, 1_793_793_600_000);
        assert_eq!(
            time_ms(GENERALIZED_TIME, b"20261104120000Z"),
            Some(1_793_793_600_000)
        );
        assert_eq!(time_ms(UTC_TIME, b"700101000000Z"), Some(0));
        assert_eq!(time_ms(UTC_TIME, b"261304120000Z"), None);
        assert!(read(der.split_last().unwrap().1).is_err());
        assert!(read(&[der.clone(), vec![0]].concat()).is_err());
    }

    // T-101
    #[test]
    fn t_101_an_ecdsa_signature_is_sent_to_tls_in_der() {
        let mut raw = [0_u8; 64];
        raw[31] = 1;
        raw[32] = 0x80;
        let der = ecdsa_der(&raw).unwrap();
        let mut want = vec![0x30, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21, 0x00, 0x80];
        want.extend([0_u8; 31]);
        assert_eq!(der, want);
        assert!(ecdsa_der(&raw[..63]).is_none());
        let p256 = PublicKey::P256([vec![4], vec![1; 64]].concat());
        assert_eq!(spki_of(&p256).unwrap().len(), 91);
    }
}
