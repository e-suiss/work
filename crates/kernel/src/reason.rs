//! Reason codes for rejection and quarantine (P-11, P-19, SEC-18); a rejection is a typed decision, not an error, and its code is the `snake_case` wire string of the vectors.

use core::fmt;

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

/// Why a record is rejected or quarantined (P-11, P-19).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reason {
    /// `malformed_cbor:<detail>`.
    MalformedCbor(MalformedCbor),
    /// `non_canonical_cbor:<detail>`.
    NonCanonicalCbor(NonCanonicalCbor),
    /// `limit_exceeded:<limit>`.
    LimitExceeded(Limit),
    /// `schema:<detail>`.
    Schema(Schema),
    /// `non_canonical_set_order:<field>`.
    NonCanonicalSetOrder(SetField),
    /// `duplicate_entry:<field>`.
    DuplicateEntry(ListField),
    /// `signature:<detail>`.
    Signature(Signature),
    /// A consequential record without `authority` (P-13, C-32).
    AuthorityMissing,
    /// `capacity` and `on_behalf_of` disagree (P-13, E-13).
    CapacityMismatch,
    /// Automation origin without a bound system author or without basis (INV-20, T-66).
    UnattributedAutomation,
    /// An agent-authored record without `producer` (P-15).
    ProducerMissing,
    /// A signature is required but absent (P-21).
    AuthorSignatureMissing,
    /// An unsigned human record without `auth_context` (P-21).
    AuthContextMissing,
    /// An extensible value with no core category mapping (C-5, P-71).
    UnmappedExtensionValue,
    /// `critical` names a key that is not in `ext` (P-69).
    ExtensionCriticalDangling,
    /// The audience is `work` but the record concerns no Work (P-77).
    VisibilityNoWork,
    /// `critical` names a key the verifier does not understand (P-19); a quarantine, never a rejection.
    ExtensionCriticalUnknown,
    /// The same author wrote the same version twice in one supersede chain (P-24, P-74).
    DuplicateVersion,
    /// A Declaration whose effect would start before its `recorded_at` (INV-4, P-24).
    RetroactiveDeclaration,
    /// `envelope_mismatch:<field>`.
    EnvelopeMismatch(EnvelopeField),
}

impl Reason {
    /// The code before the optional `:`.
    #[must_use]
    pub const fn family(self) -> &'static str {
        match self {
            Self::MalformedCbor(_) => "malformed_cbor",
            Self::NonCanonicalCbor(_) => "non_canonical_cbor",
            Self::LimitExceeded(_) => "limit_exceeded",
            Self::Schema(_) => "schema",
            Self::NonCanonicalSetOrder(_) => "non_canonical_set_order",
            Self::DuplicateEntry(_) => "duplicate_entry",
            Self::Signature(_) => "signature",
            Self::AuthorityMissing => "authority_missing",
            Self::CapacityMismatch => "capacity_mismatch",
            Self::UnattributedAutomation => "unattributed_automation",
            Self::ProducerMissing => "producer_missing",
            Self::AuthorSignatureMissing => "author_signature_missing",
            Self::AuthContextMissing => "auth_context_missing",
            Self::UnmappedExtensionValue => "unmapped_extension_value",
            Self::ExtensionCriticalDangling => "extension_critical_dangling",
            Self::VisibilityNoWork => "visibility_no_work",
            Self::ExtensionCriticalUnknown => "extension_critical_unknown",
            Self::DuplicateVersion => "duplicate_version",
            Self::RetroactiveDeclaration => "retroactive_declaration",
            Self::EnvelopeMismatch(_) => "envelope_mismatch",
        }
    }

    /// The code after the `:`, when the family has one.
    #[must_use]
    pub const fn detail(self) -> Option<&'static str> {
        match self {
            Self::MalformedCbor(d) => Some(d.wire_name()),
            Self::NonCanonicalCbor(d) => Some(d.wire_name()),
            Self::LimitExceeded(d) => Some(d.wire_name()),
            Self::Schema(d) => Some(d.wire_name()),
            Self::NonCanonicalSetOrder(d) => Some(d.wire_name()),
            Self::DuplicateEntry(d) => Some(d.wire_name()),
            Self::Signature(d) => Some(d.wire_name()),
            Self::EnvelopeMismatch(d) => Some(d.wire_name()),
            _ => None,
        }
    }

    /// Parses a full reason code such as `schema:relation`.
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        let (family, detail) = match code.split_once(':') {
            Some((f, d)) => (f, Some(d)),
            None => (code, None),
        };
        let bare = match family {
            "authority_missing" => Some(Self::AuthorityMissing),
            "capacity_mismatch" => Some(Self::CapacityMismatch),
            "unattributed_automation" => Some(Self::UnattributedAutomation),
            "producer_missing" => Some(Self::ProducerMissing),
            "author_signature_missing" => Some(Self::AuthorSignatureMissing),
            "auth_context_missing" => Some(Self::AuthContextMissing),
            "unmapped_extension_value" => Some(Self::UnmappedExtensionValue),
            "extension_critical_dangling" => Some(Self::ExtensionCriticalDangling),
            "visibility_no_work" => Some(Self::VisibilityNoWork),
            "extension_critical_unknown" => Some(Self::ExtensionCriticalUnknown),
            "duplicate_version" => Some(Self::DuplicateVersion),
            "retroactive_declaration" => Some(Self::RetroactiveDeclaration),
            _ => None,
        };
        match (bare, detail) {
            (Some(reason), None) => Some(reason),
            (Some(_), Some(_)) | (None, None) => None,
            (None, Some(d)) => match family {
                "malformed_cbor" => MalformedCbor::from_wire_name(d).map(Self::MalformedCbor),
                "non_canonical_cbor" => {
                    NonCanonicalCbor::from_wire_name(d).map(Self::NonCanonicalCbor)
                }
                "limit_exceeded" => Limit::from_wire_name(d).map(Self::LimitExceeded),
                "schema" => Schema::from_wire_name(d).map(Self::Schema),
                "non_canonical_set_order" => {
                    SetField::from_wire_name(d).map(Self::NonCanonicalSetOrder)
                }
                "duplicate_entry" => ListField::from_wire_name(d).map(Self::DuplicateEntry),
                "signature" => Signature::from_wire_name(d).map(Self::Signature),
                "envelope_mismatch" => EnvelopeField::from_wire_name(d).map(Self::EnvelopeMismatch),
                _ => None,
            },
        }
    }
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

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    // P-11 SEC-18
    #[test]
    fn p_11_reason_codes_round_trip_through_their_wire_strings() {
        let samples = [
            Reason::Schema(Schema::EmptyOptionalList),
            Reason::LimitExceeded(Limit::OnBehalfOf),
            Reason::NonCanonicalSetOrder(SetField::Critical),
            Reason::DuplicateEntry(ListField::Body),
            Reason::EnvelopeMismatch(EnvelopeField::ActorType),
            Reason::ExtensionCriticalUnknown,
            Reason::DuplicateVersion,
            Reason::VisibilityNoWork,
            Reason::Schema(Schema::Params),
            Reason::DuplicateEntry(ListField::OnBehalfOf),
            Reason::NonCanonicalSetOrder(SetField::Visibility),
        ];
        for reason in samples {
            let code = reason.to_string();
            assert_eq!(Reason::from_code(&code), Some(reason), "{code}");
        }
        assert_eq!(
            Reason::Schema(Schema::EmptyOptionalList).to_string(),
            "schema:empty_optional_list"
        );
        assert_eq!(Reason::AuthorityMissing.to_string(), "authority_missing");
        assert_eq!(Reason::from_code("authority_missing:x"), None);
        assert_eq!(Reason::from_code("schema"), None);
        assert_eq!(Reason::from_code("schema:nope"), None);
    }
}
