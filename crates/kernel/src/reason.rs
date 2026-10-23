//! Reason codes for rejection and quarantine (P-11, P-19, SEC-18); a rejection is a typed decision, not an error, and its code is the `snake_case` wire string of the vectors.

use core::fmt;

use crate::uri::TypeUri;

macro_rules! wire_enum {
    ($(#[$meta:meta])* $name:ident { $($(#[$vmeta:meta])* $variant:ident => $wire:literal,)+ }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $($(#[$vmeta])* $variant,)+
        }

        impl $name {
            /// Every value, in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            /// The `snake_case` wire name.
            #[must_use]
            pub const fn wire_name(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire,)+
                }
            }

            /// The value with this wire name.
            #[must_use]
            pub fn from_wire_name(name: &str) -> Option<Self> {
                match name {
                    $($wire => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

pub(crate) use wire_enum;

wire_enum! {
    /// Detail of input that is not well-formed CBOR (P-5).
    MalformedCbor {
        /// Input ends inside an item.
        Truncated => "truncated",
        /// Bytes follow the top-level item.
        TrailingBytes => "trailing_bytes",
        /// A text string is not valid UTF-8.
        InvalidUtf8 => "invalid_utf8",
    }
}

wire_enum! {
    /// Detail of well-formed but non-deterministic CBOR (P-5, P-72).
    NonCanonicalCbor {
        /// An integer or length is not in its shortest form.
        NonPreferredArgument => "non_preferred_argument",
        /// Map keys are not in bytewise order of their encodings.
        UnsortedMapKeys => "unsorted_map_keys",
        /// A map key repeats.
        DuplicateMapKey => "duplicate_map_key",
        /// An indefinite-length item.
        IndefiniteLength => "indefinite_length",
        /// A tag outside the allowlist.
        TagNotAllowed => "tag_not_allowed",
        /// A floating-point value.
        FloatNotInProfile => "float_not_in_profile",
        /// A simple value other than false, true or null.
        SimpleNotInProfile => "simple_not_in_profile",
    }
}

wire_enum! {
    /// A structural or semantic resource limit (P-7, P-33, SEC-18).
    Limit {
        /// Nesting depth.
        Depth => "depth",
        /// Items in one array or map.
        Items => "items",
        /// Bytes in one string.
        String => "string",
        /// Entries in `basis`.
        Basis => "basis",
        /// Rings in `on_behalf_of`.
        OnBehalfOf => "on_behalf_of",
        /// Entries in `relations`.
        Relations => "relations",
        /// Entries in `concerns`.
        Concerns => "concerns",
        /// Bytes in one request.
        Request => "request",
    }
}

wire_enum! {
    /// Detail of a mismatch with the normative CDDL (P-11, P-72).
    Schema {
        /// `kind` is not `act`, `declaration` or `claim`.
        Kind => "kind",
        /// A relation outside the eight, or with a source, target or qualifier it does not allow.
        Relation => "relation",
        /// A required field or element is missing.
        RequiredField => "required_field",
        /// A top-level key that is neither a core field nor inside `ext`.
        UnknownCoreField => "unknown_core_field",
        /// An optional list written as `[]`.
        EmptyOptionalList => "empty_optional_list",
        /// An optional map written as `{}`.
        EmptyOptionalMap => "empty_optional_map",
        /// A subtype or qualifier that is not an absolute HTTPS URI.
        TypeUri => "type_uri",
        /// An extension key that is not an absolute HTTPS URI.
        ExtKey => "ext_key",
        /// A digest algorithm label other than SHA-256.
        DigestAlg => "digest_alg",
        /// A digest value that is not 32 bytes.
        DigestLength => "digest_length",
        /// An envelope `ingest` value outside the three.
        Ingest => "ingest",
        /// A COSE container that is not tagged `COSE_Sign1`.
        Container => "container",
        /// A `params` key outside the subtype schema, or a value of the wrong type (P-80).
        Params => "params",
    }
}

wire_enum! {
    /// A set-valued list that must be sorted by encoded bytes and duplicate-free (P-72).
    SetField {
        /// `basis`.
        Basis => "basis",
        /// `concerns`.
        Concerns => "concerns",
        /// `critical`.
        Critical => "critical",
        /// The `parties` audience in `visibility` (P-77).
        Visibility => "visibility",
    }
}

wire_enum! {
    /// An author-ordered list in which an entry repeats (P-72).
    ListField {
        /// `relations`.
        Relations => "relations",
        /// `evidence`.
        Evidence => "evidence",
        /// `correlation`.
        Correlation => "correlation",
        /// Part names in `body`.
        Body => "body",
        /// Parties in the `on_behalf_of` chain (P-78).
        OnBehalfOf => "on_behalf_of",
        /// The author or a principal written into the `parties` audience (P-77).
        Visibility => "visibility",
    }
}

wire_enum! {
    /// Detail of a rejected author signature (P-6, P-7).
    Signature {
        /// Algorithm outside the Access COSE table.
        AlgNotAllowed => "alg_not_allowed",
        /// The signature does not verify.
        Invalid => "invalid",
        /// ECDSA signature with a high S value.
        HighS => "high_s",
        /// Non-canonical Ed25519 encoding.
        NonCanonicalEd25519 => "non_canonical_ed25519",
        /// Ed25519 key of small order.
        SmallOrderKey => "small_order_key",
        /// The key identifier is not bound to the author in Access.
        KidUnknown => "kid_unknown",
        /// Unprotected or protected header outside the profile.
        HeaderProfile => "header_profile",
    }
}

wire_enum! {
    /// The envelope field that disagrees with the record or the previous envelope (P-11, P-75).
    EnvelopeField {
        /// `ledger`.
        Ledger => "ledger",
        /// `record`.
        Record => "record",
        /// `prev`.
        Prev => "prev",
        /// `recorded_at`.
        RecordedAt => "recorded_at",
        /// `proof_commit`.
        ProofCommit => "proof_commit",
        /// `actor_type`.
        ActorType => "actor_type",
    }
}

macro_rules! reason_enum {
    (@one $variant:ident) => {
        1
    };
    (
        detailed { $($(#[$dmeta:meta])* $dvariant:ident($dtype:ident) => $dwire:literal,)+ }
        bare { $($(#[$bmeta:meta])* $bvariant:ident => $bwire:literal,)+ }
    ) => {
        /// Why a record is rejected or quarantined (P-11, P-19); the code is `<family>` or `<family>:<detail>`, and a namespaced sub-code may follow (P-71).
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum Reason {
            $($(#[$dmeta])* $dvariant($dtype),)+
            $($(#[$bmeta])* $bvariant,)+
        }

        impl Reason {
            const COUNT: usize = 0 $(+ $dtype::ALL.len())+ $(+ reason_enum!(@one $bvariant))+;

            /// Every reason, detailed families first, each in declaration order.
            pub const ALL: &'static [Self] = &Self::all();

            #[expect(
                clippy::indexing_slicing,
                clippy::arithmetic_side_effects,
                reason = "evaluated only at compile time for `ALL`"
            )]
            const fn all() -> [Self; Self::COUNT] {
                let mut out = [Self::AuthorityMissing; Self::COUNT];
                let mut n = 0;
                $(
                    let mut i = 0;
                    while i < $dtype::ALL.len() {
                        out[n] = Self::$dvariant($dtype::ALL[i]);
                        n += 1;
                        i += 1;
                    }
                )+
                $(
                    out[n] = Self::$bvariant;
                    n += 1;
                )+
                let _ = n;
                out
            }

            /// The code before the optional `:`.
            #[must_use]
            pub const fn family(self) -> &'static str {
                match self {
                    $(Self::$dvariant(_) => $dwire,)+
                    $(Self::$bvariant => $bwire,)+
                }
            }

            /// The code after the `:`, when the family has one.
            #[must_use]
            pub const fn detail(self) -> Option<&'static str> {
                match self {
                    $(Self::$dvariant(d) => Some(d.wire_name()),)+
                    $(Self::$bvariant => None,)+
                }
            }

            fn bare(family: &str) -> Option<Self> {
                match family {
                    $($bwire => Some(Self::$bvariant),)+
                    _ => None,
                }
            }

            fn detailed(family: &str, detail: &str) -> Option<Self> {
                match family {
                    $($dwire => $dtype::from_wire_name(detail).map(Self::$dvariant),)+
                    _ => None,
                }
            }
        }
    };
}

reason_enum! {
    detailed {
        /// `malformed_cbor:<detail>`.
        MalformedCbor(MalformedCbor) => "malformed_cbor",
        /// `non_canonical_cbor:<detail>`.
        NonCanonicalCbor(NonCanonicalCbor) => "non_canonical_cbor",
        /// `limit_exceeded:<limit>`.
        LimitExceeded(Limit) => "limit_exceeded",
        /// `schema:<detail>`.
        Schema(Schema) => "schema",
        /// `non_canonical_set_order:<field>`.
        NonCanonicalSetOrder(SetField) => "non_canonical_set_order",
        /// `duplicate_entry:<field>`.
        DuplicateEntry(ListField) => "duplicate_entry",
        /// `signature:<detail>`.
        Signature(Signature) => "signature",
        /// `envelope_mismatch:<field>`.
        EnvelopeMismatch(EnvelopeField) => "envelope_mismatch",
    }
    bare {
        /// A consequential record without `authority` (P-13, C-32).
        AuthorityMissing => "authority_missing",
        /// `capacity` and `on_behalf_of` disagree (P-13, E-13).
        CapacityMismatch => "capacity_mismatch",
        /// A Declaration without `capacity` (P-13, P-83).
        CapacityMissing => "capacity_missing",
        /// Automation origin without a bound system author or without basis (INV-20, T-66).
        UnattributedAutomation => "unattributed_automation",
        /// An agent-authored record without `producer` (P-15).
        ProducerMissing => "producer_missing",
        /// A signature is required but absent (P-21).
        AuthorSignatureMissing => "author_signature_missing",
        /// An unsigned human record without `auth_context` (P-21).
        AuthContextMissing => "auth_context_missing",
        /// An extensible value with no core category mapping (C-5, P-71).
        UnmappedExtensionValue => "unmapped_extension_value",
        /// `critical` names a key that is not in `ext` (P-69).
        ExtensionCriticalDangling => "extension_critical_dangling",
        /// The audience is `work` but the record concerns no Work (P-77).
        VisibilityNoWork => "visibility_no_work",
        /// `critical` names a key the verifier does not understand (P-19); a quarantine, never a rejection.
        ExtensionCriticalUnknown => "extension_critical_unknown",
        /// The record's protocol version has no rule set in this kernel (P-87); a quarantine, never a rejection.
        ProtocolVersionUnknown => "protocol_version_unknown",
        /// The same author wrote the same version twice in one supersede chain (P-24, P-74).
        DuplicateVersion => "duplicate_version",
        /// A Declaration whose effect would start before its `recorded_at` (INV-4, P-24).
        RetroactiveDeclaration => "retroactive_declaration",
        /// A `supersedes` target of another kind than the record (P-24, P-86); only derivation knows the target, so only derivation rejects with it.
        SupersedesKindMismatch => "supersedes_kind_mismatch",
    }
}

impl Reason {
    /// Parses a full reason code such as `schema:relation`; a namespaced sub-code (an absolute HTTPS URI after a further `:`) this kernel does not know reads as its parent code (P-71).
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        let Some((family, rest)) = code.split_once(':') else {
            return Self::bare(code);
        };
        if is_sub_code(rest) {
            return Self::bare(family);
        }
        match rest.split_once(':') {
            None => Self::detailed(family, rest),
            Some((detail, sub)) if is_sub_code(sub) => Self::detailed(family, detail),
            Some(_) => None,
        }
    }
}

fn is_sub_code(value: &str) -> bool {
    TypeUri::parse(value).is_some()
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.family())?;
        if let Some(detail) = self.detail() {
            f.write_str(":")?;
            f.write_str(detail)?;
        }
        Ok(())
    }
}

wire_enum! {
    /// A reason that quarantines a record and never rejects it (P-19, P-87).
    QuarantineReason {
        /// `critical` names a key the verifier does not understand (P-19).
        ExtensionCriticalUnknown => "extension_critical_unknown",
        /// The record's protocol version has no rule set in this kernel (P-87).
        ProtocolVersionUnknown => "protocol_version_unknown",
    }
}

impl QuarantineReason {
    /// Parses a full reason code that names a quarantine reason, with the sub-code rule of [`Reason::from_code`].
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        Reason::from_code(code).and_then(|r| Self::try_from(r).ok())
    }
}

impl From<QuarantineReason> for Reason {
    fn from(reason: QuarantineReason) -> Self {
        match reason {
            QuarantineReason::ExtensionCriticalUnknown => Self::ExtensionCriticalUnknown,
            QuarantineReason::ProtocolVersionUnknown => Self::ProtocolVersionUnknown,
        }
    }
}

impl TryFrom<Reason> for QuarantineReason {
    type Error = Reason;

    fn try_from(reason: Reason) -> Result<Self, Reason> {
        match reason {
            Reason::ExtensionCriticalUnknown => Ok(Self::ExtensionCriticalUnknown),
            Reason::ProtocolVersionUnknown => Ok(Self::ProtocolVersionUnknown),
            other => Err(other),
        }
    }
}

impl fmt::Display for QuarantineReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Reason::from(*self), f)
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::ToString;

    use super::*;

    // P-11 SEC-18
    #[test]
    fn p_11_every_reason_round_trips_through_its_wire_string() {
        assert!(Reason::ALL.len() > 60);
        for (i, reason) in Reason::ALL.iter().enumerate() {
            let code = reason.to_string();
            assert_eq!(Reason::from_code(&code), Some(*reason), "{code}");
            assert!(!Reason::ALL.iter().take(i).any(|r| r == reason), "{code}");
        }
        assert_eq!(
            Reason::Schema(Schema::EmptyOptionalList).to_string(),
            "schema:empty_optional_list"
        );
        assert_eq!(Reason::AuthorityMissing.to_string(), "authority_missing");
        assert_eq!(Reason::CapacityMissing.to_string(), "capacity_missing");
        assert_eq!(
            Reason::SupersedesKindMismatch.to_string(),
            "supersedes_kind_mismatch"
        );
        assert_eq!(Reason::from_code("authority_missing:x"), None);
        assert_eq!(Reason::from_code("schema"), None);
        assert_eq!(Reason::from_code("schema:nope"), None);
        assert_eq!(Reason::from_code(""), None);
    }

    // P-71
    #[test]
    fn p_71_unknown_namespaced_sub_code_reads_as_its_parent() {
        let sub = "https://procurement.example/ns/reason/budget_frozen";
        assert_eq!(
            Reason::from_code(&format!("authority_missing:{sub}")),
            Some(Reason::AuthorityMissing)
        );
        assert_eq!(
            Reason::from_code(&format!("schema:relation:{sub}")),
            Some(Reason::Schema(Schema::Relation))
        );
        assert_eq!(Reason::from_code(&format!("schema:{sub}")), None);
        assert_eq!(Reason::from_code("schema:relation:extra"), None);
        assert_eq!(
            Reason::from_code("authority_missing:http://p.example/x"),
            None
        );
        assert_eq!(
            QuarantineReason::from_code(&format!("protocol_version_unknown:{sub}")),
            Some(QuarantineReason::ProtocolVersionUnknown)
        );
    }

    // P-19 P-87
    #[test]
    fn p_19_quarantine_reasons_are_exactly_the_two_that_never_reject() {
        for q in QuarantineReason::ALL {
            let reason = Reason::from(*q);
            assert_eq!(QuarantineReason::try_from(reason), Ok(*q));
            assert_eq!(q.to_string(), reason.to_string());
            assert_eq!(q.wire_name(), reason.family());
        }
        let quarantines = Reason::ALL
            .iter()
            .filter(|r| QuarantineReason::try_from(**r).is_ok())
            .count();
        assert_eq!(quarantines, QuarantineReason::ALL.len());
        assert_eq!(QuarantineReason::from_code("authority_missing"), None);
    }
}
