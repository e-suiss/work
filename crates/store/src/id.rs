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
}
