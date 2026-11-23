//! Responsibility (§10.1…§10.4, §10.9, §10.10): the single accountable Party and its chain under a regime, the organisation rule, queue definitions with their versioned distribution policy, the assignment axis and the closed responsibility operation set with its commitment-axis mapping, the ownership lease, distribution decisions and open workload, principal guarantees and their scoped waivers, the participation policy of `engaged_in` and the responsibility of an intervening Party; every value is derived from records and Access inputs, nothing is stored (RC-1…RC-25, RC-44, RC-45, RC-48).

mod accountability;
mod assignment;
mod chains;
mod distribution;
mod guarantee;
mod intervention;
mod org_rule;
mod participation;
mod queue;

pub use accountability::{
    Accountability, AccountabilitySource, Accountable, Directory, Explicit, accountability,
    queue_accountability,
};
pub use assignment::{
    AccessWait, Assignment, AssignmentAct, AssignmentEvent, AssignmentSignal, AssignmentSignalKind,
    AssignmentState, CommitmentEffect, ForwardTarget, Forwarding, Hold, HoldVia, LeaseStatus,
    Nomination, Offer, PingPong, ResponsibilityOperation, access_wait, assignment_signals,
    assignment_state, lease_status, ping_pong,
};
pub use distribution::{DistributionDecision, Workload, decisions, workload};
pub use guarantee::{PrincipalGuarantee, Waiver, WaiverScope, guarantees, waivers};
pub use intervention::{ActBy, ControlSpan, InterventionMark, interventions};
pub use org_rule::{
    GroupResolution, OrgRule, OrgRuleVersion, Regime, Resolution, org_rules, resolve_group,
    rule_for,
};
pub use participation::{
    PARTICIPATION_KEY, Participation, ParticipationPolicy, SUGGESTED_PARTICIPATION, participation,
};
pub use queue::{
    Candidates, DistributionMethod, Lease, LeaseExpiry, QueueDefinition, QueueVersion, in_force,
    queue_versions,
};
