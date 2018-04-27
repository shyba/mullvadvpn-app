use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crossbeam_channel as channel;
use error_chain::ChainedError;

use talpid_core::tunnel::{self, TunnelEvent, TunnelMetadata, TunnelMonitor};
use talpid_types::net::{TunnelEndpoint, TunnelEndpointData, TunnelOptions};

use super::{OPENVPN_LOG_FILENAME, WIREGUARD_LOG_FILENAME};
use logging;

error_chain!{}

const MIN_TUNNEL_ALIVE_TIME_MS: Duration = Duration::from_millis(1000);

/// Spawn the tunnel state machine thread, returning a channel for sending tunnel requests.
pub fn spawn() -> (
    channel::Sender<TunnelRequest>,
    channel::Receiver<TunnelStateInfo>,
) {
    let (request_tx, request_rx) = channel::unbounded();
    let (info_tx, info_rx) = channel::unbounded();

    thread::spawn(move || event_loop(request_rx, info_tx));

    (request_tx, info_rx)
}

fn event_loop(
    requests: channel::Receiver<TunnelRequest>,
    info_listener: channel::Sender<TunnelStateInfo>,
) {
    let mut state = TunnelState::from(NotConnectedState);

    while let Some(new_state) = state.handle_events(&requests) {
        info_listener.send(new_state.info());
        state = new_state;
    }
}

/// Representation of external requests for the tunnel state machine.
pub enum TunnelRequest {
    /// Request a state information event to be sent.
    PollStateInfo,
    /// Request a tunnel to be opened.
    Start(TunnelParameters),
    /// Requst the tunnel to restart if it has been previously requested to be opened.
    Restart(TunnelParameters),
    /// Request a tunnel to be closed.
    Close,
}

/// Information necessary to open a tunnel.
#[derive(Debug, PartialEq)]
pub struct TunnelParameters {
    pub endpoint: TunnelEndpoint,
    pub options: TunnelOptions,
    pub log_dir: Option<PathBuf>,
    pub resource_dir: PathBuf,
    pub account_token: String,
}

/// Description of the tunnel states.
#[derive(Clone, Debug, PartialEq)]
pub enum TunnelStateInfo {
    NotConnected,
    Connecting(TunnelEndpoint),
    Connected(TunnelEndpoint, TunnelMetadata),
    Exiting,
    Restarting,
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

    /// Returns information describing the state.
    fn info(&self) -> TunnelStateInfo {
        match *self {
            TunnelState::NotConnected(_) => TunnelStateInfo::NotConnected,
            TunnelState::Connecting(ref state) => state.info(),
            TunnelState::Connected(ref state) => state.info(),
            TunnelState::Exiting(_) => TunnelStateInfo::Exiting,
            TunnelState::Restarting(_) => TunnelStateInfo::Restarting,
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
    tunnel_close_event: channel::Receiver<Result<()>>,
}

impl CloseHandle {
    fn new(
        tunnel_close_handle: tunnel::CloseHandle,
        tunnel_close_event: channel::Receiver<Result<()>>,
        listening_for_tunnel_events: Arc<AtomicBool>,
    ) -> Self {
        CloseHandle {
            listening_for_tunnel_events,
            tunnel_close_handle,
            tunnel_close_event,
        }
    }

    fn close(self) -> channel::Receiver<Result<()>> {
        // Prevent event dispatcher thread from locking by telling it to not send events to the
        // closed channel.
        self.listening_for_tunnel_events
            .store(false, Ordering::Release);

        let close_result = self
            .tunnel_close_handle
            .close()
            .chain_err(|| "Failed to request tunnel monitor to close the tunnel");

        if let Err(error) = close_result {
            error!("{}", error.display_chain());
        }

        self.tunnel_close_event
    }
}

/// No tunnel is running.
struct NotConnectedState;

impl NotConnectedState {
    fn tunnel_closing(tunnel_close_event: channel::Receiver<Result<()>>) -> TunnelState {
        Self::tunnel_closed(tunnel_close_event.recv())
    }

    fn tunnel_closed(tunnel_close_result: Option<Result<()>>) -> TunnelState {
        match tunnel_close_result {
            Some(Err(error)) => {
                let chained_error = error.chain_err(|| "Tunnel closed with an error");
                warn!("{}", chained_error);
            }
            None => warn!("Tunnel monitor thread has died"),
            _ => debug!("Tunnel has closed"),
        }

        NotConnectedState.into()
    }

    fn handle_events(self, requests: &channel::Receiver<TunnelRequest>) -> Option<TunnelState> {
        for request in requests {
            return Some(match request {
                TunnelRequest::Start(parameters) => ConnectingState::start(parameters),
                TunnelRequest::Restart(_) => continue,
                TunnelRequest::Close => continue,
                TunnelRequest::PollStateInfo => TunnelState::from(self),
            });
        }

        None
    }
}

/// The tunnel has been started, but it is not established/functional.
struct ConnectingState {
    tunnel_events: channel::Receiver<TunnelEvent>,
    tunnel_endpoint: TunnelEndpoint,
    tunnel_parameters: TunnelParameters,
    tunnel_close_event: channel::Receiver<Result<()>>,
    close_handle: CloseHandle,
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

    fn restart(exit_result: Option<Result<()>>, parameters: TunnelParameters) -> TunnelState {
        match exit_result {
            Some(Err(error)) => {
                let chained_error = error.chain_err(|| "Tunnel closed unexpectedly, restarting.");
                info!("{}", chained_error.display_chain());
            }
            _ => info!("Tunnel closed. Restarting."),
        }

        Self::start(parameters)
    }

    fn new(parameters: TunnelParameters) -> Result<Self> {
        let (event_tx, event_rx) = channel::unbounded();
        let listening_for_events = Arc::new(AtomicBool::new(true));
        let tunnel_endpoint = parameters.endpoint;
        let monitor =
            Self::spawn_tunnel_monitor(&parameters, event_tx, listening_for_events.clone())?;
        let tunnel_close_handle = monitor.close_handle();
        let tunnel_close_event = Self::spawn_tunnel_monitor_wait_thread(monitor);
        let close_handle = CloseHandle::new(
            tunnel_close_handle,
            tunnel_close_event.clone(),
            listening_for_events,
        );

        Ok(ConnectingState {
            tunnel_events: event_rx,
            tunnel_endpoint,
            tunnel_parameters: parameters,
            tunnel_close_event,
            close_handle,
        })
    }

    fn spawn_tunnel_monitor(
        parameters: &TunnelParameters,
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

    fn spawn_tunnel_monitor_wait_thread(
        tunnel_monitor: TunnelMonitor,
    ) -> channel::Receiver<Result<()>> {
        let (tunnel_close_event_tx, tunnel_close_event_rx) = channel::unbounded();

        thread::spawn(move || {
            let result = tunnel_monitor
                .wait_at_least(MIN_TUNNEL_ALIVE_TIME_MS)
                .chain_err(|| "Tunnel has stopped unexpectedly");

            tunnel_close_event_tx.send(result);
            trace!("Tunnel monitor thread exit");
        });

        tunnel_close_event_rx
    }

    fn handle_events(self, requests: &channel::Receiver<TunnelRequest>) -> Option<TunnelState> {
        let tunnel_events = self.tunnel_events.clone();
        let tunnel_close_event = self.tunnel_close_event.clone();

        loop {
            select! {
                recv(requests, request) => {
                    let request = request.unwrap_or(TunnelRequest::Close);

                    return Some(match request {
                        TunnelRequest::Start(parameters) => {
                            if parameters != self.tunnel_parameters {
                                RestartingState::wait_for(self.close_handle, parameters)
                            } else {
                                continue;
                            }
                        }
                        TunnelRequest::Restart(parameters) => {
                            RestartingState::wait_for(self.close_handle, parameters)
                        }
                        TunnelRequest::Close => ExitingState::wait_for(self.close_handle),
                        TunnelRequest::PollStateInfo => TunnelState::from(self),
                    });
                },
                recv(tunnel_events, event) => {
                    return Some(match event {
                        Some(TunnelEvent::Up(metadata)) => {
                            ConnectedState::new(
                                metadata,
                                self.tunnel_events,
                                self.tunnel_endpoint,
                                self.tunnel_parameters,
                                self.tunnel_close_event,
                                self.close_handle,
                            )
                        }
                        None => {
                            RestartingState::wait_for(self.close_handle, self.tunnel_parameters)
                        }
                        _ => continue,
                    });
                },
                recv(tunnel_close_event, result) => {
                    return Some(ConnectingState::restart(result, self.tunnel_parameters));
                },
            }
        }
    }

    fn info(&self) -> TunnelStateInfo {
        TunnelStateInfo::Connecting(self.tunnel_endpoint)
    }
}

/// The tunnel is up and working.
struct ConnectedState {
    tunnel_events: channel::Receiver<TunnelEvent>,
    tunnel_endpoint: TunnelEndpoint,
    metadata: TunnelMetadata,
    tunnel_parameters: TunnelParameters,
    tunnel_close_event: channel::Receiver<Result<()>>,
    close_handle: CloseHandle,
}

impl ConnectedState {
    fn new(
        metadata: TunnelMetadata,
        tunnel_events: channel::Receiver<TunnelEvent>,
        tunnel_endpoint: TunnelEndpoint,
        tunnel_parameters: TunnelParameters,
        tunnel_close_event: channel::Receiver<Result<()>>,
        close_handle: CloseHandle,
    ) -> TunnelState {
        ConnectedState {
            tunnel_events,
            tunnel_endpoint,
            metadata,
            tunnel_parameters,
            tunnel_close_event,
            close_handle,
        }.into()
    }

    fn handle_events(self, requests: &channel::Receiver<TunnelRequest>) -> Option<TunnelState> {
        let tunnel_events = self.tunnel_events.clone();
        let tunnel_close_event = self.tunnel_close_event.clone();

        loop {
            select! {
                recv(requests, request) => {
                    let request = request.unwrap_or(TunnelRequest::Close);

                    return Some(match request {
                        TunnelRequest::Start(parameters) => {
                            if parameters != self.tunnel_parameters {
                                RestartingState::wait_for(self.close_handle, parameters)
                            } else {
                                continue;
                            }
                        }
                        TunnelRequest::Restart(parameters) => {
                            RestartingState::wait_for(self.close_handle, parameters)
                        }
                        TunnelRequest::Close => ExitingState::wait_for(self.close_handle),
                        TunnelRequest::PollStateInfo => TunnelState::from(self),
                    });
                },
                recv(tunnel_events, event) => {
                    return Some(match event {
                        Some(TunnelEvent::Down) | None => {
                            RestartingState::wait_for(self.close_handle, self.tunnel_parameters)
                        }
                        _ => continue,
                    });
                },
                recv(tunnel_close_event, result) => {
                    return Some(ConnectingState::restart(result, self.tunnel_parameters));
                },
            }
        }
    }

    fn info(&self) -> TunnelStateInfo {
        TunnelStateInfo::Connected(self.tunnel_endpoint, self.metadata.clone())
    }
}

/// This state is active from when we manually trigger a tunnel kill until the tunnel wait
/// operation (TunnelExit) returned.
struct ExitingState {
    exited: channel::Receiver<Result<()>>,
}

impl ExitingState {
    fn new(exited: channel::Receiver<Result<()>>) -> TunnelState {
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
                    return Some(match request {
                        Some(TunnelRequest::Start(parameters)) => {
                            RestartingState::new(self.exited, parameters)
                        }
                        Some(TunnelRequest::Restart(_)) => continue,
                        Some(TunnelRequest::Close) => continue,
                        Some(TunnelRequest::PollStateInfo) => TunnelState::from(self),
                        None => NotConnectedState::tunnel_closing(self.exited),
                    });
                },
                recv(exited, result) => {
                    return Some(NotConnectedState::tunnel_closed(result))
                },
            }
        }
    }
}

/// This state is active when the tunnel is being closed but will be reopened shortly afterwards.
struct RestartingState {
    exited: channel::Receiver<Result<()>>,
    parameters: TunnelParameters,
}

impl RestartingState {
    fn new(exited: channel::Receiver<Result<()>>, parameters: TunnelParameters) -> TunnelState {
        RestartingState { exited, parameters }.into()
    }

    fn wait_for(close_handle: CloseHandle, parameters: TunnelParameters) -> TunnelState {
        Self::new(close_handle.close(), parameters)
    }

    fn handle_events(mut self, requests: &channel::Receiver<TunnelRequest>) -> Option<TunnelState> {
        let exited = self.exited.clone();

        loop {
            select! {
                recv(requests, request) => {
                    let request = request.unwrap_or(TunnelRequest::Close);

                    return Some(match request {
                        TunnelRequest::Start(parameters) => {
                            self.parameters = parameters;
                            continue;
                        }
                        TunnelRequest::Restart(parameters) => {
                            self.parameters = parameters;
                            continue;
                        }
                        TunnelRequest::Close => ExitingState::new(self.exited),
                        TunnelRequest::PollStateInfo => TunnelState::from(self),
                    });
                },
                recv(exited, result) => {
                    return Some(ConnectingState::restart(result, self.parameters));
                },
            }
        }
    }
}
