//! Access's actor kinds and Work's actor types (P-12, C-17; Access OP-149 m.8): every `actor_kind` a signed key lookup names is the Work actor type of the same wire name, so the server binds a Party to the type Access recorded for it without a table of its own.

#![allow(clippy::unwrap_used, reason = "test code")]

use work_access_client::domain::keys::ActorKind;
use work_kernel::id::PartyRef;
use work_kernel::validate::{ActorType, ActorTypeSource};
use work_ledger::{ActorBindings, Declared, DeclaredActors};

// P-12 C-17 MD-7
#[test]
fn p_12_every_access_actor_kind_is_the_work_actor_type_of_its_name() {
    let party = PartyRef::new("AwMDAwMDAwMDAwMDAwMDAw").unwrap();
    for kind in ActorKind::ALL {
        let actor_type = ActorType::from_wire_name(kind.wire_name()).unwrap();
        assert_eq!(actor_type.wire_name(), kind.wire_name());
        let mut bindings = ActorBindings::new();
        bindings.bind(party.clone(), actor_type).unwrap();
        let derived = DeclaredActors {
            author: Declared {
                party: party.clone(),
                actor_type: ActorType::Human,
            },
            on_behalf_of: vec![],
            evidence: vec![],
        }
        .derive(&bindings);
        assert_eq!(derived.author.actor_type, actor_type);
        assert_eq!(derived.author.source, ActorTypeSource::AccessBinding);
    }
}
