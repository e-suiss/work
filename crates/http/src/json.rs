//! The JSON spelling every API family shares (P-54 item 8): field names are `snake_case`, and an integer that can pass 2^53, a count, a position or an amount, travels as a decimal string read back only in its canonical form; the `OpenAPI` gate refuses a 64-bit integer schema and a property name outside `snake_case`.

/// `#[serde(with = "work_http::json::decimal")]` for a `u64` written as a decimal string.
pub mod decimal {
    use serde::{Deserialize as _, Deserializer, Serializer, de::Error as _};

    /// Writes `value` as a decimal string.
    ///
    /// # Errors
    /// The serializer's error.
    #[allow(
        clippy::trivially_copy_pass_by_ref,
        reason = "the signature serde `with` asks for"
    )]
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }

    /// Reads a decimal string without sign or leading zero.
    ///
    /// # Errors
    /// A value that is not such a string or does not fit a `u64`.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let text = String::deserialize(deserializer)?;
        let canonical = !text.is_empty()
            && text.bytes().all(|b| b.is_ascii_digit())
            && (text == "0" || !text.starts_with('0'));
        if !canonical {
            return Err(D::Error::custom("expected a decimal string"));
        }
        text.parse()
            .map_err(|_| D::Error::custom("the decimal does not fit 64 bits"))
    }
}

/// RFC 3339 UTC time with milliseconds (`YYYY-MM-DDTHH:MM:SS.mmmZ`) of Unix milliseconds
/// (P-54 item 8); `None` outside years 0000 to 9999.
#[must_use]
pub fn rfc3339_millis(ms: i64) -> Option<String> {
    const DAY_MS: i64 = 86_400_000;
    let days = ms.checked_div_euclid(DAY_MS)?;
    let of_day = ms.checked_rem_euclid(DAY_MS)?;
    let (y, m, d) = crate::deprecation::civil_from_days(days)?;
    if !(0..=9999).contains(&y) {
        return None;
    }
    let hh = of_day / 3_600_000;
    let mm = of_day % 3_600_000 / 60_000;
    let ss = of_day % 60_000 / 1000;
    let mmm = of_day % 1000;
    Some(format!(
        "{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{mmm:03}Z"
    ))
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Counted {
        #[serde(with = "super::decimal")]
        seq: u64,
    }

    // P-54
    #[test]
    fn p_54_large_integers_travel_as_canonical_decimal_strings() {
        let max = serde_json::to_string(&Counted { seq: u64::MAX }).unwrap();
        assert_eq!(max, r#"{"seq":"18446744073709551615"}"#);
        let read: Counted = serde_json::from_str(r#"{"seq":"42"}"#).unwrap();
        assert_eq!(read, Counted { seq: 42 });
        let zero: Counted = serde_json::from_str(r#"{"seq":"0"}"#).unwrap();
        assert_eq!(zero.seq, 0);
        assert_eq!(
            super::rfc3339_millis(1_792_749_600_123).as_deref(),
            Some("2026-10-23T10:00:00.123Z")
        );
        assert_eq!(
            super::rfc3339_millis(0).as_deref(),
            Some("1970-01-01T00:00:00.000Z")
        );
        assert_eq!(super::rfc3339_millis(i64::MAX), None);
        for bad in [
            r#"{"seq":42}"#,
            r#"{"seq":"042"}"#,
            r#"{"seq":"-1"}"#,
            r#"{"seq":""}"#,
            r#"{"seq":"1e3"}"#,
            r#"{"seq":"18446744073709551616"}"#,
        ] {
            assert!(serde_json::from_str::<Counted>(bad).is_err(), "{bad}");
        }
    }
}
