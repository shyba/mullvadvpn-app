use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crossbeam_channel as channel;
use error_chain::ChainedError;

use talpid_core::tunnel::{self, TunnelEvent, TunnelMonitor};
use talpid_types::net::{TunnelEndpoint, TunnelEndpointData, TunnelOptions};

use super::{OPENVPN_LOG_FILENAME, WIREGUARD_LOG_FILENAME};
use logging;

error_chain!{}

const MIN_TUNNEL_ALIVE_TIME_MS: Duration = Duration::from_millis(1000);

/// Spawn the tunnel state machine thread, returning a channel for sending tunnel requests.
pub fn spawn() -> channel::Sender<TunnelRequest> {
    let (request_tx, request_rx) = channel::unbounded();

    thread::spawn(move || event_loop(request_rx));

    request_tx
}

fn event_loop(requests: channel::Receiver<TunnelRequest>) {
    let mut state = TunnelState::from(NotConnectedState);

    while let Some(new_state) = state.handle_events(&requests) {
        state = new_state;
    }
}

/// Representation of external requests for the tunnel state machine.
pub enum TunnelRequest {
    /// Request a tunnel to be opened.
    StartTunnel(TunnelParameters),
    /// Request a tunnel to be closed.
    CloseTunnel,
}

/// Information necessary to open a tunnel.
pub struct TunnelParameters {
    pub endpoint: TunnelEndpoint,
    pub options: TunnelOptions,
    pub log_dir: Option<PathBuf>,
    pub resource_dir: PathBuf,
    pub account_token: String,
}

/// Valid states of the tunnel.
///
/// All implementations must be able to handle external requests of the type `TunnelRequest`. It is
/// recommended to handle the requests together with any other event sources for the state, using
/// `select!`.
enum TunnelState {
    NotConnected(NotConnectedState),
    Connecting(ConnectingState),
    Connected(ConnectedState),
    Exiting(ExitingState),
    Restarting(RestartingState),
}

impl TunnelState {
    /// Main state function.
    ///
    /// This is the state entry point. It consumes itself and returns the next state to advance to
    /// when it has completed, or `None` if the requests channel has closed. The requests channel
    /// contains `TunnelRequest` events that are handled by the state to advance the state machine.
    fn handle_events(self, requests: &channel::Receiver<TunnelRequest>) -> Option<TunnelState> {
        match self {
            TunnelState::NotConnected(state) => state.handle_events(requests),
            TunnelState::Connecting(state) => state.handle_events(requests),
            TunnelState::Connected(state) => state.handle_events(requests),
            TunnelState::Exiting(state) => state.handle_events(requests),
            TunnelState::Restarting(state) => state.handle_events(requests),
        }
    }
}

macro_rules! impl_from_for_tunnel_state {
    ($($state_type:ident -> $state_variant:ident),* $(,)*) => {
        $(
            impl From<$state_type> for TunnelState {
                fn from(state: $state_type) -> Self {
                    TunnelState::$state_variant(state)
                }
            }
        )*
    };
}

impl_from_for_tunnel_state! {
    NotConnectedState -> NotConnected,
    ConnectingState -> Connecting,
    ConnectedState -> Connected,
    ExitingState -> Exiting,
    RestartingState -> Restarting,
}

/// Internal handle to request tunnel to be closed.
struct CloseHandle {
    listening_for_tunnel_events: Arc<AtomicBool>,
    tunnel_close_handle: tunnel::CloseHandle,
}

impl CloseHandle {
    fn new(tunnel_monitor: &TunnelMonitor, listening_for_tunnel_events: Arc<AtomicBool>) -> Self {
        CloseHandle {
            listening_for_tunnel_events,
            tunnel_close_handle: tunnel_monitor.close_handle(),
        }
    }

    fn close(self) -> channel::Receiver<io::Result<()>> {
        let (close_tx, close_rx) = channel::unbounded();

        // Prevent event dispatcher thread from locking by telling it to not send events to the
        // closed channel.
        self.listening_for_tunnel_events
            .store(false, Ordering::Release);

        thread::spawn(move || {
            close_tx.send(self.tunnel_close_handle.close());
            trace!("Tunnel kill thread exit");
        });

        close_rx
    }
}

/// No tunnel is running.
struct NotConnectedState;

impl NotConnectedState {
    fn handle_events(self, requests: &channel::Receiver<TunnelRequest>) -> Option<TunnelState> {
        for request in requests {
            if let TunnelRequest::StartTunnel(parameters) = request {
                return Some(ConnectingState::start(parameters));
            }
        }

        None
    }
}

/// The tunnel has been started, but it is not established/functional.
struct ConnectingState {
    close_handle: CloseHandle,
    tunnel_events: channel::Receiver<TunnelEvent>,
}

impl ConnectingState {
    fn start(parameters: TunnelParameters) -> TunnelState {
        match Self::new(parameters) {
            Ok(connecting) => TunnelState::from(connecting),
            Err(error) => {
                let chained_error = error.chain_err(|| "Failed to start a new tunnel");
                error!("{}", chained_error);
                NotConnectedState.into()
            }
        }
    }

    fn new(parameters: TunnelParameters) -> Result<Self> {
        let (event_tx, event_rx) = channel::unbounded();
        let listening_for_events = Arc::new(AtomicBool::new(true));
        let monitor =
            Self::spawn_tunnel_monitor(parameters, event_tx, listening_for_events.clone())?;
        let close_handle = CloseHandle::new(&monitor, listening_for_events);

        Self::spawn_tunnel_monitor_wait_thread(monitor);

        Ok(ConnectingState {
            close_handle,
            tunnel_events: event_rx,
        })
    }

    fn spawn_tunnel_monitor(
        parameters: TunnelParameters,
        events: channel::Sender<TunnelEvent>,
        enable_events: Arc<AtomicBool>,
    ) -> Result<TunnelMonitor> {
        // Must wrap the channel in a Mutex because TunnelMonitor forces the closure to be Sync
        let event_tx = Mutex::new(events);
        let on_tunnel_event = move |event| {
            if enable_events.load(Ordering::Acquire) {
                event_tx
                    .lock()
                    .expect("no other thread should use the tunnel event channel")
                    .send(event);
            }
        };
        let log_file = Self::prepare_tunnel_log_file(&parameters)?;

        TunnelMonitor::new(
            parameters.endpoint,
            &parameters.options,
            &parameters.account_token,
            log_file.as_ref().map(PathBuf::as_path),
            &parameters.resource_dir,
            on_tunnel_event,
        ).chain_err(|| "Unable to start tunnel monitor")
    }

    fn prepare_tunnel_log_file(parameters: &TunnelParameters) -> Result<Option<PathBuf>> {
        if let Some(ref log_dir) = parameters.log_dir {
            let filename = match parameters.endpoint.tunnel {
                TunnelEndpointData::OpenVpn(_) => OPENVPN_LOG_FILENAME,
                TunnelEndpointData::Wireguard(_) => WIREGUARD_LOG_FILENAME,
            };
            let tunnel_log = log_dir.join(filename);
            logging::rotate_log(&tunnel_log).chain_err(|| "Unable to rotate tunnel log")?;
            Ok(Some(tunnel_log))
        } else {
            Ok(None)
        }
    }

    fn spawn_tunnel_monitor_wait_thread(tunnel_monitor: TunnelMonitor) {
        thread::spawn(move || {
            let result = tunnel_monitor.wait_at_least(MIN_TUNNEL_ALIVE_TIME_MS);
            if let Err(error) = result.chain_err(|| "Tunnel exited in an unexpected way") {
                error!("{}", error.display_chain());
            }
            trace!("Tunnel monitor thread exit");
        });
    }

    fn handle_events(self, requests: &channel::Receiver<TunnelRequest>) -> Option<TunnelState> {
        let tunnel_events = self.tunnel_events.clone();
        let close_handle = self.close_handle;

        loop {
            select! {
                recv(requests, request) => {
                    if let TunnelRequest::CloseTunnel = request? {
                        return Some(ExitingState::wait_for(close_handle));
                    }
                },
                recv(tunnel_events, event) => {
                    if let TunnelEvent::Up(_) = event? {
                        return Some(ConnectedState::new(
                            self.tunnel_events,
                            close_handle,
                        ));
                    }
                },
            }
        }
    }
}

/// The tunnel is up and working.
struct ConnectedState {
    close_handle: CloseHandle,
    tunnel_events: channel::Receiver<TunnelEvent>,
}

impl ConnectedState {
    fn new(
        tunnel_events: channel::Receiver<TunnelEvent>,
        close_handle: CloseHandle,
    ) -> TunnelState {
        ConnectedState {
            close_handle,
            tunnel_events,
        }.into()
    }

    fn handle_events(self, requests: &channel::Receiver<TunnelRequest>) -> Option<TunnelState> {
        let tunnel_events = self.tunnel_events;
        let close_handle = self.close_handle;

        loop {
            select! {
                recv(requests, request) => {
                    if let TunnelRequest::CloseTunnel = request? {
                        break;
                    }
                },
                recv(tunnel_events, event) => {
                    if let TunnelEvent::Down = event? {
                        break;
                    }
                },
            }
        }

        Some(ExitingState::wait_for(close_handle))
    }
}

/// This state is active from when we manually trigger a tunnel kill until the tunnel wait
/// operation (TunnelExit) returned.
struct ExitingState {
    exited: channel::Receiver<io::Result<()>>,
}

impl ExitingState {
    fn new(exited: channel::Receiver<io::Result<()>>) -> TunnelState {
        ExitingState { exited }.into()
    }

    fn wait_for(close_handle: CloseHandle) -> TunnelState {
        Self::new(close_handle.close())
    }

    fn handle_events(self, requests: &channel::Receiver<TunnelRequest>) -> Option<TunnelState> {
        let exited = self.exited.clone();

        loop {
            select! {
                recv(requests, request) => {
                    if let TunnelRequest::StartTunnel(parameters) = request? {
                        return Some(RestartingState::new(self.exited, parameters));
                    }
                },
                recv(exited, _) => {
                    return Some(NotConnectedState.into());
                },
            }
        }
    }
}

/// This state is active when the tunnel is being closed but will be reopened shortly afterwards.
struct RestartingState {
    exited: channel::Receiver<io::Result<()>>,
    parameters: TunnelParameters,
}

impl RestartingState {
    fn new(exited: channel::Receiver<io::Result<()>>, parameters: TunnelParameters) -> TunnelState {
        RestartingState { exited, parameters }.into()
    }

    fn wait_for(close_handle: CloseHandle, parameters: TunnelParameters) -> TunnelState {
        Self::new(close_handle.close(), parameters)
    }

    fn handle_events(self, requests: &channel::Receiver<TunnelRequest>) -> Option<TunnelState> {
        let exited = self.exited.clone();

        loop {
            select! {
                recv(requests, request) => {
                    if let TunnelRequest::CloseTunnel = request? {
                        return Some(ExitingState::new(self.exited));
                    }
                },
                recv(exited, _) => {
                    return Some(ConnectingState::start(self.parameters));
                },
            }
        }
    }
}
