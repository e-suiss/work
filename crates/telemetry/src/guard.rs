//! The content guard (P-43, OP-19, OP-18 rule 1, T-39 rule 3, SEC-24): telemetry links to records
//! only by identifier, so a span or event that declares a body, payload, content, secret,
//! credential or payment field, or an unstable OpenTelemetry `GenAI` attribute, is never enabled.

use tracing::Metadata;
use tracing_subscriber::layer::{Context, Layer};

/// Field-name words that name record content, secrets, credentials or payment data.
pub const CONTENT_WORDS: &[&str] = &[
    "body",
    "bodies",
    "payload",
    "payloads",
    "content",
    "contents",
    "plaintext",
    "ciphertext",
    "secret",
    "secrets",
    "password",
    "passwords",
    "passwd",
    "passphrase",
    "token",
    "tokens",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "apikey",
    "privatekey",
    "otp",
    "card",
    "pan",
    "cvv",
    "cvc",
    "iban",
];

/// Adjacent field-name words that together name a secret.
pub const CONTENT_PAIRS: &[(&str, &str)] =
    &[("api", "key"), ("private", "key"), ("signing", "key")];

/// The OpenTelemetry `GenAI` semantic-convention namespace, unstable upstream (P-43 rule 3).
pub const GENAI_PREFIX: &str = "gen_ai";

/// Why a field name may not be recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldBan {
    /// The name spells record content, a secret, a credential or payment data (P-43, SEC-24).
    Content,
    /// The name is an unstable OpenTelemetry `GenAI` attribute (P-43 rule 3).
    GenAi,
}

/// Why `name` may not be a telemetry field, or `None` when it may.
///
/// Names are split into words at `.`, `_` and `-` and compared case-insensitively.
#[must_use]
pub fn forbidden_field(name: &str) -> Option<FieldBan> {
    let lower = name.to_ascii_lowercase();
    if lower == GENAI_PREFIX
        || lower
            .strip_prefix(GENAI_PREFIX)
            .is_some_and(|rest| rest.starts_with(['.', '_', '-']))
    {
        return Some(FieldBan::GenAi);
    }
    let words: Vec<&str> = lower
        .split(['.', '_', '-'])
        .filter(|w| !w.is_empty())
        .collect();
    let single = words.iter().any(|w| CONTENT_WORDS.contains(w));
    let pair = words
        .windows(2)
        .any(|p| matches!(p, [a, b] if CONTENT_PAIRS.contains(&(*a, *b))));
    (single || pair).then_some(FieldBan::Content)
}

/// True if a callsite declares a field that [`forbidden_field`] rejects.
#[must_use]
pub fn declares_forbidden_field(metadata: &Metadata<'_>) -> bool {
    metadata
        .fields()
        .iter()
        .any(|f| forbidden_field(f.name()).is_some())
}

/// A global layer that disables every span and event declaring a forbidden field, so no
/// exporter behind it ever sees the value.
#[derive(Clone, Copy, Debug, Default)]
pub struct ContentGuard;

impl<S: tracing::Subscriber> Layer<S> for ContentGuard {
    fn enabled(&self, metadata: &Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        !declares_forbidden_field(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // P-43 SEC-24 T-39
    #[test]
    fn p_43_content_secret_and_genai_names_are_forbidden() {
        for name in [
            "body",
            "record_body",
            "request.body",
            "payload",
            "content",
            "secret",
            "client_secret",
            "password",
            "refresh_token",
            "session_cookie",
            "api_key",
            "apiKey",
            "private_key",
            "signing_key",
            "otp",
            "card_number",
            "pan",
        ] {
            assert_eq!(forbidden_field(name), Some(FieldBan::Content), "{name}");
        }
        for name in ["gen_ai.request.model", "gen_ai", "GEN_AI.system"] {
            assert_eq!(forbidden_field(name), Some(FieldBan::GenAi), "{name}");
        }
    }

    // P-43 T-39
    #[test]
    fn p_43_identifier_fields_are_allowed() {
        for name in [
            "record",
            "record_id",
            "work",
            "commitment",
            "condition",
            "correlation",
            "trace_id",
            "span_id",
            "event",
            "outcome",
            "idempotency_key",
            "ledger",
            "pos",
            "tokenizer_width",
            "panel",
            "general",
            "message",
        ] {
            assert_eq!(forbidden_field(name), None, "{name}");
        }
    }
}
