//! The node a process leads ledgers as (§17.12, T-85 item 4, OP-9 item 4, OP-28 item 3): the
//! cell it runs in, a lease holder drawn once from the `Rng` port, the lease length and the
//! protocol versions its kernel carries rule sets for. It takes a ledger only in the ledger's own
//! cell, only while no other node holds a live sequencer lease on it, and only when it supports
//! every version the ledger's log has activated, the genesis being the first activation.

use std::time::Duration;

use work_kernel::activation::{Activation, check_activations};
use work_kernel::record::ProtocolVersion;
use work_kernel::rules::RuleSet;
use work_store::{CellId, Seat};

use crate::ports::{Rng, RngError};

/// How long a sequencer lease lasts unless it is renewed; the leader renews it every third of
/// that (§17.12; POLICY DEFAULT, as Access `LEASE_TTL`).
pub const DEFAULT_LEASE: Duration = Duration::from_secs(10);

/// The longest lease a node takes.
pub const MAX_LEASE: Duration = Duration::from_hours(1);

/// One process as a sequencer node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    seat: Seat,
    protocols: Vec<ProtocolVersion>,
}

fn millis(lease: Duration) -> u64 {
    let capped = lease.clamp(Duration::from_millis(1), MAX_LEASE);
    u64::try_from(capped.as_millis()).unwrap_or(1)
}

impl Node {
    /// A node in `cell` with a fresh lease holder from `rng`, the default lease and every
    /// protocol version this kernel carries a rule set for (T-4 rule 4, P-87).
    ///
    /// # Errors
    /// [`RngError`]; no node leads without a holder.
    pub fn new(cell: CellId, rng: &(impl Rng + ?Sized)) -> Result<Self, RngError> {
        let mut holder = [0_u8; 16];
        rng.fill(&mut holder)?;
        Ok(Self {
            seat: Seat {
                cell,
                holder,
                lease_ms: millis(DEFAULT_LEASE),
            },
            protocols: RuleSet::ALL.iter().map(|r| r.protocol()).collect(),
        })
    }

    /// The same node with leases of `lease`, kept between 1 ms and [`MAX_LEASE`].
    #[must_use]
    pub fn with_lease(mut self, lease: Duration) -> Self {
        self.seat.lease_ms = millis(lease);
        self
    }

    /// The same node supporting exactly `protocols`, as a node of another build would.
    #[must_use]
    pub fn with_protocols(mut self, protocols: &[ProtocolVersion]) -> Self {
        self.protocols = protocols.to_vec();
        self
    }

    /// The cell the node runs in.
    #[must_use]
    pub const fn cell(&self) -> &CellId {
        &self.seat.cell
    }

    /// The lease length.
    #[must_use]
    pub const fn lease(&self) -> Duration {
        Duration::from_millis(self.seat.lease_ms)
    }

    /// The protocol versions the node supports.
    #[must_use]
    pub fn protocols(&self) -> &[ProtocolVersion] {
        &self.protocols
    }

    pub(crate) const fn seat(&self) -> &Seat {
        &self.seat
    }

    /// The activations of a ledger, given as their envelope bytes in log order with the genesis
    /// first, when the node supports every one: they pass the kernel's sequence rule and each
    /// activates a protocol version the node carries a rule set for; `None` otherwise, and for
    /// an entry it cannot read (OP-28 item 3, P-110 items 7, 8).
    #[must_use]
    pub fn activations(&self, entries: &[Vec<u8>]) -> Option<Vec<Activation>> {
        let slices: Vec<&[u8]> = entries.iter().map(Vec::as_slice).collect();
        check_activations(&slices)
            .ok()
            .filter(|list| list.iter().all(|a| self.protocols.contains(&a.protocol)))
    }

    /// Whether the node supports every activation entry of a ledger, given in log order
    /// (OP-28 item 3, P-110 item 7).
    #[must_use]
    pub fn supports(&self, entries: &[Vec<u8>]) -> bool {
        self.activations(entries).is_some()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use work_store::Durability;

    use super::*;
    use crate::adapters::SeededRng;
    use crate::{GenesisInput, genesis};

    fn node() -> Node {
        Node::new(CellId::new("cell-a").unwrap(), &SeededRng::new([5; 32])).unwrap()
    }

    const ACTIVATION: &str = include_str!("../../../conformance/vectors/records/activation.json");

    fn opened(protocol: (u64, u64), schema: [u8; 32]) -> Vec<u8> {
        let input = GenesisInput {
            recorded_at_ms: 1_792_749_600_000,
            protocol,
            schema,
            nonce: [9; 32],
        };
        genesis(&input, Durability::SingleNode).unwrap().bytes
    }

    fn v1_0() -> Vec<u8> {
        opened((1, 0), *RuleSet::V1_0.schema().as_bytes())
    }

    /// The golden genesis and the protocol 1.1 activation after it (P-110).
    fn activated() -> Vec<Vec<u8>> {
        let file: serde_json::Value = serde_json::from_str(ACTIVATION).unwrap();
        let sequence = file["sequences"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"] == "sequence/genesis-then-activation")
            .unwrap();
        sequence["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| {
                h.as_str()
                    .unwrap()
                    .as_bytes()
                    .chunks(2)
                    .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
                    .collect()
            })
            .collect()
    }

    // OP-28 P-87 P-110 T-4
    #[test]
    fn op_28_a_node_leads_only_a_ledger_whose_activated_versions_it_supports() {
        let current = node();
        assert!(current.supports(&[v1_0()]));
        assert!(!current.supports(&[opened((1, 0), [7; 32])]));
        assert!(!current.supports(&[opened((1, 1), [7; 32])]));
        assert!(!current.supports(&[v1_0(), opened((2, 0), [7; 32])]));
        let older = node().with_protocols(&[]);
        assert!(!older.supports(&[v1_0()]));
        let newer = node().with_protocols(&[
            ProtocolVersion { major: 1, minor: 0 },
            ProtocolVersion { major: 1, minor: 1 },
        ]);
        assert!(newer.supports(&[opened((1, 1), [7; 32])]));
        assert!(!current.supports(&[]));
        assert!(!current.supports(&[vec![0xa0]]));
        assert!(!current.supports(&[b"not cbor".to_vec()]));
        let ledger = activated();
        assert!(!current.supports(&ledger));
        assert_eq!(newer.activations(&ledger).unwrap().len(), 2);
    }

    // T-85 OP-9 OP-10
    #[test]
    fn t_85_a_node_draws_its_holder_once_and_keeps_its_lease_in_range() {
        let a = node();
        let b = Node::new(CellId::new("cell-a").unwrap(), &SeededRng::new([6; 32])).unwrap();
        assert_ne!(a.seat().holder, b.seat().holder);
        assert_eq!(a.seat().holder, node().seat().holder);
        assert_eq!(a.cell().as_str(), "cell-a");
        assert_eq!(a.lease(), DEFAULT_LEASE);
        assert_eq!(
            a.clone().with_lease(Duration::ZERO).lease(),
            Duration::from_millis(1)
        );
        assert_eq!(a.with_lease(Duration::from_hours(24)).lease(), MAX_LEASE);
    }
}
