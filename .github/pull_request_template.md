## What and why

<!-- What does this change do, and why is it needed? -->

## Specification rules affected

<!-- Spec IDs this change implements or touches (e.g. CM-25, ST-7, INV-14), or "none". -->

## How it was tested

<!-- Tests added or run. Tests carry the rule ID in their name or on a bare ID line above them. -->

## Breaking change

- [ ] No
- [ ] Yes — impact and migration:

## Security-sensitive paths

<!-- Required if this touches the kernel, store and migrations, ledger, federation, the signer, bindings or shared-crate versions. -->
- What could this change break?
- Does it open a new attack surface?

## Design review

Model test — answer for every new concept, field or operation:
- [ ] It is more than a card, a column or an "assignee" field.
- [ ] If it is canonical, it has its own identity and other things refer to it; otherwise it is a typed statement, a condition type or a derived view.
- [ ] It is not derivable from records (derived things are projections, never stored as canonical).
- [ ] A profession- or industry-specific term is a Practice label or subtype, mapped onto a core category.
- [ ] No field is mandatory unless it helps the person who enters it.

The change does **not**:
- [ ] put mutable or claimed data into a Work's root identity;
- [ ] make Work the owner of external truth, or give claims, observations, predictions or content normative effect;
- [ ] create, widen or bypass authority, or work around an Access denial;
- [ ] store something derivable from records as canonical;
- [ ] make a channel, session or surface a source of truth;
- [ ] widen visibility or internal structure across a trust boundary implicitly, or move private context into shared work without explicit, minimal disclosure;
- [ ] create automation that cannot be attributed, or weaken evidence, provenance or accountability;
- [ ] rewrite history or delete physically;
- [ ] add a new primitive where a Practice, a statement type or a projection is enough;
- [ ] promise an intervention the executor cannot provide;
- [ ] give a first-party Suiss component a semantic privilege a conforming third party cannot use, or change architectural ownership because of commercial packaging;
- [ ] add a protocol feature without an end-to-end user flow;
- [ ] invent a new transport, webhook signature, event envelope or agent protocol;
- [ ] grow the small fixed core without need.

## Checklist

- [ ] Title follows Conventional Commits (`type(scope): summary`)
- [ ] Under ~400 changed lines, or split into smaller pull requests
- [ ] Wording in docs, UI text, API field names and messages follows the claim vocabulary (`cargo xtask check forbidden-claims`)
- [ ] No explanatory comments; spec IDs appear as bare ID lines
- [ ] `decision` label added if this adds or changes a specification decision (register and ranges updated)
