//! Responsibility control (RC-26 … RC-43, RC-49): the normative basis of agent actions and their autonomy, the control axis with its single driver and control lease, stop requests and their answers, and the executor coordination contract; Work records and coordinates requests while authority stays in Access and actual execution and stopping stay with the executor (RC-2).

pub mod autonomy;
pub mod axis;
pub mod body;
pub mod executor;
pub mod stop;
