/// A ledger identifier: the 32-byte genesis digest (P-67), the leading key column of every
/// table and the row-level security scope (T-13, T-36).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LedgerId([u8; 32]);

impl LedgerId {
    /// From the raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lower-case hex, the form `app.ledger_id` carries.
    #[must_use]
    pub fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(64);
        for b in self.0 {
            for nibble in [b >> 4, b & 0x0f] {
                s.extend(HEX.get(usize::from(nibble)).map(|&c| char::from(c)));
            }
        }
        s
    }
}

impl std::fmt::Debug for LedgerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LedgerId({})", self.to_hex())
    }
}

/// A work item (§15 P-29): the item an outbox pointer names and whose version its event carries
/// as `seq` (T-81).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ItemRef {
    /// A Work, by its 16-byte UUID.
    Work([u8; 16]),
    /// A Commitment, by its 32-byte digest.
    Commitment([u8; 32]),
    /// A Condition, by its 32-byte digest.
    Condition([u8; 32]),
}

impl ItemRef {
    /// The stored `item_kind`.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Work(_) => "work",
            Self::Commitment(_) => "commitment",
            Self::Condition(_) => "condition",
        }
    }

    /// The stored `item_id` bytes.
    #[must_use]
    pub const fn id(&self) -> &[u8] {
        match self {
            Self::Work(id) => id,
            Self::Commitment(id) | Self::Condition(id) => id,
        }
    }

    /// From a stored `(item_kind, item_id)` pair; `None` for an unknown kind or a wrong length.
    #[must_use]
    pub fn from_parts(kind: &str, id: &[u8]) -> Option<Self> {
        match kind {
            "work" => <[u8; 16]>::try_from(id).ok().map(Self::Work),
            "commitment" => <[u8; 32]>::try_from(id).ok().map(Self::Commitment),
            "condition" => <[u8; 32]>::try_from(id).ok().map(Self::Condition),
            _ => None,
        }
    }
}

impl std::fmt::Debug for ItemRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ItemRef({}:", self.kind())?;
        for b in self.id() {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // P-67
    #[test]
    fn t_13_ledger_scope_is_the_lower_case_hex_of_the_digest() {
        let mut bytes = [0xab_u8; 32];
        bytes[0] = 0x0f;
        bytes[31] = 0xa0;
        let id = LedgerId::from_bytes(bytes);
        let hex = id.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.starts_with("0fab"));
        assert!(hex.ends_with("aba0"));
        assert_eq!(id.as_bytes(), &bytes);
    }

    // T-81 P-29
    #[test]
    fn t_81_item_kind_and_id_round_trip_with_the_stored_lengths() {
        let items = [
            ItemRef::Work([0x01; 16]),
            ItemRef::Commitment([0x02; 32]),
            ItemRef::Condition([0x03; 32]),
        ];
        for item in items {
            assert_eq!(ItemRef::from_parts(item.kind(), item.id()), Some(item));
        }
        assert_eq!(ItemRef::from_parts("work", &[0x01; 32]), None);
        assert_eq!(ItemRef::from_parts("commitment", &[0x02; 16]), None);
        assert_eq!(ItemRef::from_parts("gate", &[0x02; 32]), None);
        assert_eq!(
            format!("{:?}", ItemRef::Work([0xab; 16])),
            format!("ItemRef(work:{})", "ab".repeat(16))
        );
    }
}
