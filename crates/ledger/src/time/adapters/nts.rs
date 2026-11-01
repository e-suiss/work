//! The NTS client (OP-32 item 1, OP-42 item 4) on `ntp-proto`'s `NtpSource` state machine: per
//! server an NTS-KE session over TLS, then authenticated `NTPv4` polls every 64 s; each measurement
//! becomes a sample of the server's time against the process monotonic clock. The system clock
//! is neither read nor set: the local NTP timescale is a fixed anchor plus monotonic time.

use std::io::BufRead;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ntp_proto::tls_utils::Certificate;
use ntp_proto::{
    KeyExchangeClient, Measurement, NtpClock, NtpDuration, NtpInstant, NtpLeapIndicator,
    NtpSourceAction, NtsClientConfig, ObservableSourceTimedata, PollInterval, PollIntervalLimits,
    ProtocolVersion, SourceConfig, SourceController, StateUpdate, SynchronizationConfig, System,
    TimeSyncController,
};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::time::adapters::ProcessMonotonic;
use crate::time::domain::{NTS_INTERVAL_MS, NtsSample};
use crate::time::ports::NtsEvent;

/// Upper bound on each NTS-KE step and each NTP send (T-32 rule 7).
pub const NTS_TIMEOUT: Duration = Duration::from_secs(5);

/// The default NTS-KE port (RFC 8915).
pub const NTS_KE_PORT: u16 = 4460;

const RETRY: Duration = Duration::from_millis(NTS_INTERVAL_MS);
const POLL_LOG2: u8 = 6;
const ANCHOR_NTP_SECONDS: u32 = 3_976_214_400;
const ANCHOR_UNIX_MS: i64 = 1_767_225_600_000;

/// A configured NTS server: its NTS-KE host and port (OP-32 item 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtsServer {
    /// Host name or address; also the TLS server name.
    pub host: String,
    /// NTS-KE port.
    pub port: u16,
}

/// Why an NTS session ended.
#[derive(Debug, thiserror::Error)]
enum SessionError {
    #[error("{0}: {1}")]
    Io(&'static str, std::io::Error),
    #[error("NTS-KE: {0}")]
    KeyExchange(ntp_proto::NtsError),
    #[error("{0}: no answer within {NTS_TIMEOUT:?}")]
    Timeout(&'static str),
    #[error("NTP: no address for {0}")]
    NoAddress(String),
    #[error("the server asked for a new key exchange")]
    Reset,
    #[error("the server refused service")]
    Demobilized,
    #[error("NTP source: {0}")]
    Source(NoClockControl),
}

/// Reads PEM certificates that NTS-KE accepts as roots besides the platform's, such as the
/// test-only root of the local environment.
///
/// # Errors
/// The read error.
pub fn read_roots(pem: &mut dyn BufRead) -> std::io::Result<Vec<Certificate>> {
    ntp_proto::tls_utils::pemfile::certs(pem).collect()
}

/// Starts one task per server; each sends its samples and losses on `events` (OP-32 item 2).
///
/// # Errors
/// [`ntp_proto::NtsError`] when the TLS client cannot be built.
pub fn spawn_nts(
    servers: Vec<NtsServer>,
    roots: Vec<Certificate>,
    mono: &Arc<ProcessMonotonic>,
    events: &mpsc::Sender<NtsEvent>,
) -> Result<Vec<tokio::task::JoinHandle<()>>, ntp_proto::NtsError> {
    let _installed = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let client = Arc::new(KeyExchangeClient::new(&NtsClientConfig {
        certificates: roots.into(),
        protocol_version: ProtocolVersion::V4,
    })?);
    Ok(servers
        .into_iter()
        .enumerate()
        .map(|(source, server)| {
            tokio::spawn(follow(
                source,
                server,
                Arc::clone(&client),
                Arc::clone(mono),
                events.clone(),
            ))
        })
        .collect())
}

async fn follow(
    source: usize,
    server: NtsServer,
    client: Arc<KeyExchangeClient>,
    mono: Arc<ProcessMonotonic>,
    events: mpsc::Sender<NtsEvent>,
) {
    loop {
        let ended = session(source, &server, &client, &mono, &events).await;
        if let Err(error) = ended {
            tracing::warn!(
                event = "ledger_time.nts_session_ended",
                source,
                host = %server.host,
                %error,
                "NTS session ended; retrying"
            );
        }
        if events.send(NtsEvent::Lost { source }).await.is_err() {
            return;
        }
        tokio::time::sleep(RETRY).await;
    }
}

type Slot = Arc<Mutex<Option<Measurement<NtpDuration>>>>;

async fn bounded<T, E>(
    what: &'static str,
    call: impl Future<Output = Result<T, E>>,
    wrap: impl FnOnce(E) -> SessionError,
) -> Result<T, SessionError> {
    timeout(NTS_TIMEOUT, call)
        .await
        .map_err(|_| SessionError::Timeout(what))?
        .map_err(wrap)
}

async fn session(
    source: usize,
    server: &NtsServer,
    client: &KeyExchangeClient,
    mono: &ProcessMonotonic,
    events: &mpsc::Sender<NtsEvent>,
) -> Result<(), SessionError> {
    let tcp = bounded(
        "NTS-KE connect",
        TcpStream::connect((server.host.as_str(), server.port)),
        |e| SessionError::Io("NTS-KE connect", e),
    )
    .await?;
    let keys = bounded(
        "NTS-KE",
        client.exchange_keys(tcp, server.host.clone(), []),
        SessionError::KeyExchange,
    )
    .await?;
    let peer = bounded(
        "NTP resolve",
        tokio::net::lookup_host((keys.remote.as_str(), keys.port)),
        |e| SessionError::Io("NTP resolve", e),
    )
    .await?
    .next()
    .ok_or_else(|| SessionError::NoAddress(keys.remote.clone()))?;
    let local: SocketAddr = if peer.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(local)
        .await
        .map_err(|e| SessionError::Io("NTP bind", e))?;
    socket
        .connect(peer)
        .await
        .map_err(|e| SessionError::Io("NTP connect", e))?;

    let slot: Slot = Arc::new(Mutex::new(None));
    let no_peers: Arc<[IpAddr]> = Arc::from(Vec::new());
    let mut system: System<usize, Collector> = System::new(
        SlotClock(Arc::clone(&slot)),
        SynchronizationConfig::default(),
        (),
        no_peers,
    )
    .map_err(SessionError::Source)?;
    let (mut ntp, first) = system
        .create_ntp_source(
            source,
            poll_config(),
            peer,
            keys.protocol_version,
            Some(keys.nts),
        )
        .map_err(SessionError::Source)?;

    let mut pending: Vec<NtpSourceAction<()>> = first.collect();
    let mut sent = None;
    let mut wake = tokio::time::Instant::now();
    let mut buf = [0_u8; 1024];
    loop {
        for action in pending.drain(..) {
            match action {
                NtpSourceAction::Send(packet) => {
                    sent = Some(local_time(mono));
                    bounded("NTP send", socket.send(&packet), |e| {
                        SessionError::Io("NTP send", e)
                    })
                    .await?;
                }
                NtpSourceAction::SetTimer(after) => {
                    wake = tokio::time::Instant::now()
                        .checked_add(after)
                        .unwrap_or(wake);
                }
                NtpSourceAction::UpdateSystem(_) => {}
                NtpSourceAction::Reset => return Err(SessionError::Reset),
                NtpSourceAction::Demobilize => return Err(SessionError::Demobilized),
            }
        }
        tokio::select! {
            received = socket.recv(&mut buf) => {
                let n = received.map_err(|e| SessionError::Io("NTP receive", e))?;
                let at = local_time(mono);
                let Some(send_time) = sent else { continue };
                let packet = buf.get(..n).unwrap_or_default();
                pending.extend(ntp.handle_incoming(packet, NtpInstant::now(), send_time, at));
                let measured = slot.lock().unwrap_or_else(PoisonError::into_inner).take();
                if let Some(sample) = measured.and_then(sample_of)
                    && events.send(NtsEvent::Sample { source, sample }).await.is_err()
                {
                    return Ok(());
                }
            }
            () = tokio::time::sleep_until(wake) => pending.extend(ntp.handle_timer()),
        }
    }
}

fn poll_config() -> SourceConfig {
    let poll = PollInterval::from_byte(POLL_LOG2);
    SourceConfig {
        poll_interval_limits: PollIntervalLimits {
            min: poll,
            max: poll,
        },
        initial_poll_interval: poll,
    }
}

fn anchor() -> ntp_proto::NtpTimestamp {
    ntp_proto::NtpTimestamp::from_seconds_nanos_since_ntp_era(ANCHOR_NTP_SECONDS, 0)
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "NTP timestamps add modulo the NTP era by design"
)]
fn local_time(mono: &ProcessMonotonic) -> ntp_proto::NtpTimestamp {
    anchor() + NtpDuration::from_system_duration(mono.elapsed())
}

fn millis(d: NtpDuration) -> Option<i64> {
    let (seconds, nanos) = d.as_seconds_nanos();
    i64::from(seconds)
        .checked_mul(1_000)?
        .checked_add(i64::from(
            nanos.checked_add(500_000)?.checked_div(1_000_000)?,
        ))
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "NTP timestamps subtract modulo the NTP era by design"
)]
fn since_anchor(t: ntp_proto::NtpTimestamp) -> NtpDuration {
    t - anchor()
}

fn sample_of(m: Measurement<NtpDuration>) -> Option<NtsSample> {
    if m.leap == NtpLeapIndicator::Unknown {
        return None;
    }
    let mono_ms = millis(since_anchor(m.localtime))?;
    let unix_ms = ANCHOR_UNIX_MS
        .checked_add(mono_ms)?
        .checked_add(millis(m.offset)?)?;
    Some(NtsSample {
        unix_ms: u64::try_from(unix_ms).ok()?,
        mono_ms: u64::try_from(mono_ms).ok()?,
    })
}

/// The system clock is never controlled from here.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("the ledger time driver does not control the system clock")]
struct NoClockControl;

#[derive(Debug, Clone)]
struct SlotClock(Slot);

impl NtpClock for SlotClock {
    type Error = NoClockControl;

    fn now(&self) -> Result<ntp_proto::NtpTimestamp, Self::Error> {
        Err(NoClockControl)
    }

    fn set_frequency(&self, _freq: f64) -> Result<ntp_proto::NtpTimestamp, Self::Error> {
        Err(NoClockControl)
    }

    fn get_frequency(&self) -> Result<f64, Self::Error> {
        Err(NoClockControl)
    }

    fn step_clock(&self, _offset: NtpDuration) -> Result<ntp_proto::NtpTimestamp, Self::Error> {
        Err(NoClockControl)
    }

    fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
        Err(NoClockControl)
    }

    fn error_estimate_update(
        &self,
        _est_error: NtpDuration,
        _max_error: NtpDuration,
    ) -> Result<(), Self::Error> {
        Err(NoClockControl)
    }

    fn status_update(&self, _leap_status: NtpLeapIndicator) -> Result<(), Self::Error> {
        Err(NoClockControl)
    }
}

/// Hands each measurement to the session through the shared slot instead of steering a clock.
struct Collector {
    slot: Slot,
}

impl TimeSyncController for Collector {
    type Clock = SlotClock;
    type SourceId = usize;
    type AlgorithmConfig = ();
    type ControllerMessage = ();
    type SourceMessage = ();
    type NtpSourceController = Capture;
    type OneWaySourceController = Unused;

    fn new(
        clock: SlotClock,
        _synchronization_config: SynchronizationConfig,
        _algorithm_config: (),
    ) -> Result<Self, NoClockControl> {
        Ok(Self { slot: clock.0 })
    }

    fn take_control(&mut self) -> Result<(), NoClockControl> {
        Ok(())
    }

    fn add_source(&mut self, _id: usize, _source_config: SourceConfig) -> Capture {
        Capture {
            slot: Arc::clone(&self.slot),
        }
    }

    fn add_one_way_source(
        &mut self,
        _id: usize,
        _source_config: SourceConfig,
        _measurement_noise_estimate: f64,
        _measurement_accuracy_estimate: f64,
        _period: Option<f64>,
    ) -> Unused {
        Unused
    }

    fn remove_source(&mut self, _id: usize) {}

    fn source_update(&mut self, _id: usize, _usable: bool) {}

    fn source_message(&mut self, _id: usize, _message: ()) -> StateUpdate<usize, ()> {
        StateUpdate::default()
    }

    fn time_update(&mut self) -> StateUpdate<usize, ()> {
        StateUpdate::default()
    }
}

struct Capture {
    slot: Slot,
}

impl SourceController for Capture {
    type ControllerMessage = ();
    type SourceMessage = ();
    type MeasurementDelay = NtpDuration;

    fn handle_message(&mut self, _message: ()) {}

    fn handle_measurement(&mut self, measurement: Measurement<NtpDuration>) -> Option<()> {
        *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(measurement);
        None
    }

    fn desired_poll_interval(&self) -> PollInterval {
        PollInterval::from_byte(POLL_LOG2)
    }

    fn observe(&self) -> ObservableSourceTimedata {
        ObservableSourceTimedata::default()
    }
}

struct Unused;

impl SourceController for Unused {
    type ControllerMessage = ();
    type SourceMessage = ();
    type MeasurementDelay = ();

    fn handle_message(&mut self, _message: ()) {}

    fn handle_measurement(&mut self, _measurement: Measurement<()>) -> Option<()> {
        None
    }

    fn desired_poll_interval(&self) -> PollInterval {
        PollInterval::from_byte(POLL_LOG2)
    }

    fn observe(&self) -> ObservableSourceTimedata {
        ObservableSourceTimedata::default()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects, reason = "test code")]

    use super::*;

    // OP-32
    #[test]
    fn op_32_the_local_timescale_is_the_anchor_plus_monotonic_time() {
        assert_eq!(millis(since_anchor(anchor())), Some(0));
        let later = anchor() + NtpDuration::from_seconds(1.5);
        assert_eq!(millis(since_anchor(later)), Some(1_500));
        assert_eq!(millis(NtpDuration::from_seconds(-0.25)), Some(-250));
        assert_eq!(
            i64::from(ANCHOR_NTP_SECONDS) - 2_208_988_800,
            ANCHOR_UNIX_MS / 1_000
        );
    }

    // OP-32 OP-42
    #[test]
    fn op_42_polls_every_64_s_through_the_ntp_source_state_machine() {
        let c = poll_config();
        assert_eq!(c.initial_poll_interval.as_log(), 6);
        assert_eq!(c.poll_interval_limits.min, c.poll_interval_limits.max);
        assert_eq!(
            1_u64 << c.initial_poll_interval.as_log(),
            NTS_INTERVAL_MS / 1_000
        );
        assert_eq!(
            Capture {
                slot: Slot::default()
            }
            .desired_poll_interval(),
            c.initial_poll_interval
        );
    }
}
