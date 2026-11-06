//! Which ledgers get a SEC-36 compromise window notice and what each says (WD-123): every ledger of the tenant that holds a record of the window, once per Access event; the notice names the first of the event's Instances whose key signed a record in that ledger, else the first of them that wrote an unsigned record there under an `auth_context` naming it, else the first Instance when only unsigned records of the Party naming no Instance fall in the window, with every compromised kid.

use std::collections::BTreeMap;

use work_access_client::domain::events::Compromise;
use work_kernel::compromise::{NoticeInput, Window};
use work_kernel::id::{Digest, LedgerId, PartyRef};
use work_store::WindowHit;

/// Why no notice can be written for an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Unplannable {
    /// The event names no Instance or kid, so the body has none to carry.
    #[error("the event names no Instance")]
    Instances,
    /// The event's source is not a `party_compromise` Claim.
    #[error("the event names no Claim")]
    Source,
    /// The compromised Party is not a Party reference.
    #[error("the Party is not a Party reference")]
    Party,
}

/// The kids that signed and the Instances that wrote unsigned records of a window in a ledger.
type Writers = (Vec<[u8; 32]>, Vec<[u8; 16]>);

/// The notices of `compromise` that `author` writes, one per ledger of `hits` in ledger order.
///
/// # Errors
/// [`Unplannable`].
pub fn plan(
    compromise: &Compromise,
    author: &PartyRef,
    hits: &[WindowHit],
) -> Result<Vec<NoticeInput>, Unplannable> {
    let first = compromise
        .instances
        .first()
        .filter(|_| !compromise.kids.is_empty())
        .ok_or(Unplannable::Instances)?;
    let source = compromise.source.clone().ok_or(Unplannable::Source)?;
    let party = PartyRef::new(&compromise.party).ok_or(Unplannable::Party)?;
    let mut ledgers: BTreeMap<[u8; 32], Writers> = BTreeMap::new();
    for hit in hits {
        let (kids, instances) = ledgers.entry(hit.ledger).or_default();
        kids.extend(hit.kid);
        instances.extend(hit.instance);
    }
    let kids: Vec<[u8; 32]> = compromise.kids.iter().map(|k| k.0).collect();
    Ok(ledgers
        .into_iter()
        .map(|(ledger, (signed, wrote))| {
            let instance = compromise
                .instances
                .iter()
                .zip(&kids)
                .find(|(_, k)| signed.contains(k))
                .map(|(i, _)| i)
                .or_else(|| compromise.instances.iter().find(|i| wrote.contains(&i.0)))
                .unwrap_or(first);
            NoticeInput {
                author: author.clone(),
                ledger: LedgerId(Digest::sha256(ledger)),
                party: party.clone(),
                jti: compromise.jti.clone(),
                window: Window {
                    instance: instance.0,
                    kids: kids.clone(),
                    window_from: compromise.window.0,
                    window_to: compromise.window.1,
                    event_digest: compromise.event_digest,
                    domain: compromise.domain.0,
                    source: source.clone(),
                },
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use work_access_client::domain::keys::{DomainId, KernelId, Kid};
    use work_proto::id::TenantId;

    use super::*;

    fn compromise() -> Compromise {
        Compromise {
            tenant: TenantId::new("tnt_acme").unwrap(),
            domain: DomainId([1; 32]),
            party: "AgICAgICAgICAgICAgICAg".to_owned(),
            instances: vec![KernelId([4; 16]), KernelId([5; 16])],
            kids: vec![Kid([7; 32]), Kid([8; 32])],
            window: (1_000, 5_000),
            source: Some("CAgICAgICAgICAgICAgICA".to_owned()),
            jti: "jti-1".to_owned(),
            event_digest: [9; 32],
        }
    }

    fn author() -> PartyRef {
        PartyRef::new("AwMDAwMDAwMDAwMDAwMDAw").unwrap()
    }

    // SEC-36
    #[test]
    fn sec_36_one_notice_per_ledger_holding_a_record_of_the_window() {
        let hits = [
            WindowHit {
                ledger: [0xb0; 32],
                kid: Some([8; 32]),
                instance: None,
            },
            WindowHit {
                ledger: [0xa0; 32],
                kid: None,
                instance: None,
            },
            WindowHit {
                ledger: [0xb0; 32],
                kid: Some([7; 32]),
                instance: None,
            },
        ];
        let notices = plan(&compromise(), &author(), &hits).unwrap();
        assert_eq!(notices.len(), 2);
        assert_eq!(notices[0].ledger, LedgerId(Digest::sha256([0xa0; 32])));
        assert_eq!(notices[0].window.instance, [4; 16]);
        assert_eq!(notices[1].ledger, LedgerId(Digest::sha256([0xb0; 32])));
        assert_eq!(notices[1].window.instance, [4; 16]);
        assert_eq!(notices[1].window.kids, vec![[7; 32], [8; 32]]);
        assert_eq!(notices[1].window.event_digest, [9; 32]);
        assert_eq!(notices[1].window.source, "CAgICAgICAgICAgICAgICA");
        assert_eq!(notices[1].author, author());
        let only_second = [WindowHit {
            ledger: [0xc0; 32],
            kid: Some([8; 32]),
            instance: None,
        }];
        assert_eq!(
            plan(&compromise(), &author(), &only_second).unwrap()[0]
                .window
                .instance,
            [5; 16]
        );
        assert_eq!(
            plan(&compromise(), &author(), &[]).unwrap(),
            Vec::<NoticeInput>::new()
        );
    }

    // SEC-36 P-116
    #[test]
    fn sec_36_an_unsigned_record_names_the_instance_of_its_auth_context() {
        let hits = [
            WindowHit {
                ledger: [0xd0; 32],
                kid: None,
                instance: Some([5; 16]),
            },
            WindowHit {
                ledger: [0xd0; 32],
                kid: None,
                instance: None,
            },
        ];
        let notices = plan(&compromise(), &author(), &hits).unwrap();
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].window.instance, [5; 16]);
        let signed_too = [
            WindowHit {
                ledger: [0xd0; 32],
                kid: Some([7; 32]),
                instance: None,
            },
            hits[0].clone(),
        ];
        assert_eq!(
            plan(&compromise(), &author(), &signed_too).unwrap()[0]
                .window
                .instance,
            [4; 16]
        );
    }

    // SEC-36
    #[test]
    fn sec_36_an_event_without_instance_or_claim_writes_no_notice() {
        let mut bare = compromise();
        bare.instances.clear();
        bare.kids.clear();
        assert_eq!(plan(&bare, &author(), &[]), Err(Unplannable::Instances));
        let mut exercised = compromise();
        exercised.source = None;
        assert_eq!(plan(&exercised, &author(), &[]), Err(Unplannable::Source));
    }
}
