//! Pure rules of the Relay client: what an intent is and the key it is sent with, the event request it becomes, what Relay's answer means for it, the waitpoints, escalation policies and ceiling decisions Relay takes, and what an event Relay delivers to Work may become.

pub mod answer;
pub mod inbound;
pub mod intent;
pub mod request;
pub mod waitpoint;
