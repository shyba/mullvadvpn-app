use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use error_chain::ChainedError;
use futures::sync::{mpsc, oneshot};
use futures::{Async, Future, Poll, Sink, Stream};
use tokio_core::reactor::Core;

use talpid_core::tunnel::{self, TunnelEvent, TunnelMetadata, TunnelMonitor};
use talpid_types::net::{TunnelEndpoint, TunnelEndpointData, TunnelOptions};

use logging;

error_chain!{}

const MIN_TUNNEL_ALIVE_TIME_MS: Duration = Duration::from_millis(1000);

const OPENVPN_LOG_FILENAME: &str = "openvpn.log";
const WIREGUARD_LOG_FILENAME: &str = "wireguard.log";

/// Spawn the tunnel state machine thread, returning a channel for sending tunnel requests.
pub fn spawn() -> (
    mpsc::UnboundedSender<TunnelRequest>,
    mpsc::UnboundedReceiver<TunnelStateInfo>,
) {
    let (request_tx, request_rx) = mpsc::unbounded();
    let (info_tx, info_rx) = mpsc::unbounded();

    thread::spawn(move || {
        if let Err(error) = event_loop(request_rx, info_tx) {
            error!("{}", error.display_chain());
        }
    });

    (request_tx, info_rx)
}

fn event_loop(
    requests: mpsc::UnboundedReceiver<TunnelRequest>,
    info_listener: mpsc::UnboundedSender<TunnelStateInfo>,
) -> Result<()> {
    let mut reactor =
        Core::new().chain_err(|| "Failed to initialize tunnel state machine event loop")?;

    let state_machine = TunnelStateMachine::new(requests);
    let listener = info_listener
        .sink_map_err(|_| Error::from("Failed to send state change event to listener"));

    reactor
        .run(state_machine.forward(listener).map(|_| ()))
        .chain_err(|| "Tunnel state machine finished with an error")
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

struct TunnelStateMachine {
    current_state: Option<TunnelState>,
    requests: mpsc::UnboundedReceiver<TunnelRequest>,
}

impl TunnelStateMachine {
    fn new(requests: mpsc::UnboundedReceiver<TunnelRequest>) -> Self {
        TunnelStateMachine {
            current_state: Some(TunnelState::from(NotConnectedState)),
            requests,
        }
    }
}

impl Stream for TunnelStateMachine {
    type Item = TunnelStateInfo;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        use self::TunnelStateTransition::*;

        let transition = self
            .current_state
            .take()
            .expect("Tunnel state machine is missing its state")
            .handle_event(&mut self.requests);

        let result = match transition {
            NewState(ref state) | SameState(ref state) => Ok(Async::Ready(Some(state.info()))),
            NoEvents(_) => Ok(Async::NotReady),
        };

        self.current_state = Some(match transition {
            NewState(new_state) => new_state,
            SameState(same_state) => same_state,
            NoEvents(same_state) => same_state,
        });

        result
    }
}

/// Asynchronous result of an attempt to progress a state.
enum TunnelStateTransition<T: TunnelStateProgress> {
    /// Transition to a new state.
    NewState(TunnelState),
    /// An event was received, but it was ignored by the state so no transition is performed.
    SameState(T),
    /// No events were received, the event loop should block until one becomes available.
    NoEvents(T),
}

impl<T: TunnelStateProgress> TunnelStateTransition<T> {
    /// Helper method to chain handling multiple different event types.
    ///
    /// The `handle_event` is only called if no events were handled so far.
    pub fn or_else<F>(self, handle_event: F) -> Self
    where
        F: FnOnce(T) -> Self,
    {
        use self::TunnelStateTransition::*;

        match self {
            NewState(state) => NewState(state),
            SameState(state) => SameState(state),
            NoEvents(state) => handle_event(state),
        }
    }
}

/// Trait that contains the method all states should implement to handle an event and advance the
/// state machine.
trait TunnelStateProgress: Sized {
    /// Main state function.
    ///
    /// This is the state entry point. It consumes itself and returns the next state to advance to
    /// when it has completed, or itself if it wants to ignore a received event or if no events were
    /// ready to be received. See [`TunnelStateTransition`] for more details.
    ///
    /// An implementation can handle events from many sources, but it should handle request events
    /// received through the provided `requests` stream.
    ///
    /// [`TunnelStateTransition`]: enum.TunnelStateTransition.html
    fn handle_event(
        self,
        requests: &mut mpsc::UnboundedReceiver<TunnelRequest>,
    ) -> TunnelStateTransition<Self>;
}

/// Try to receive an event from the asynchronous poll expression.
///
/// This macro is similar to the `try_ready!` macro provided in `futures`. If there is an event
/// ready, it will be returned wrapped in a `Result`. If there are no events ready to be received,
/// the function will return with a transition that indicates that no events were received, which
/// is analogous to `Async::NotReady`.
///
/// When the asynchronous event indicates that the stream has finished or that it has failed, an
/// error type is returned so that either close scenario can be handled in a similar way.
macro_rules! try_handle_event {
    ($same_state:expr, $event:expr) => {
        match $event {
            Ok(Async::Ready(Some(event))) => Ok(event),
            Ok(Async::Ready(None)) => Err(None),
            Ok(Async::NotReady) => return TunnelStateTransition::NoEvents($same_state),
            Err(error) => Err(Some(error)),
        }
    };
}

/// Valid states of the tunnel.
///
/// All implementations must implement `TunnelStateProgress` so that they can handle events and
/// requests in order to advance the state machine.
enum TunnelState {
    NotConnected(NotConnectedState),
    Connecting(ConnectingState),
    Connected(ConnectedState),
    Exiting(ExitingState),
    Restarting(RestartingState),
}

impl TunnelState {
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

impl TunnelStateProgress for TunnelState {
    fn handle_event(
        self,
        requests: &mut mpsc::UnboundedReceiver<TunnelRequest>,
    ) -> TunnelStateTransition<Self> {
        use self::TunnelStateTransition::*;

        macro_rules! handle_event {
            ( $($state:ident),* $(,)* ) => {
                match self {
                    $(
                        TunnelState::$state(state) => match state.handle_event(requests) {
                            NewState(tunnel_state) => NewState(tunnel_state),
                            SameState(state) => SameState(TunnelState::$state(state)),
                            NoEvents(state) => NoEvents(TunnelState::$state(state)),
                        },
                    )*
                }
            }
        }

        handle_event! {
            NotConnected,
            Connecting,
            Connected,
            Exiting,
            Restarting,
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
    fn new(
        tunnel_close_handle: tunnel::CloseHandle,
        listening_for_tunnel_events: Arc<AtomicBool>,
    ) -> Self {
        CloseHandle {
            listening_for_tunnel_events,
            tunnel_close_handle,
        }
    }

    fn close(self) {
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
    }
}

/// No tunnel is running.
struct NotConnectedState;

impl NotConnectedState {
    fn tunnel_closed(tunnel_close_result: Result<()>) -> TunnelState {
        match tunnel_close_result {
            Err(error) => {
                let chained_error = error.chain_err(|| "Tunnel closed with an error");
                warn!("{}", chained_error);
            }
            _ => debug!("Tunnel has closed"),
        }

        NotConnectedState.into()
    }
}

impl TunnelStateProgress for NotConnectedState {
    fn handle_event(
        self,
        requests: &mut mpsc::UnboundedReceiver<TunnelRequest>,
    ) -> TunnelStateTransition<Self> {
        use self::TunnelStateTransition::*;

        match try_handle_event!(self, requests.poll()) {
            Ok(TunnelRequest::Start(parameters)) => NewState(ConnectingState::start(parameters)),
            Ok(TunnelRequest::Restart(_)) => SameState(self),
            Ok(TunnelRequest::PollStateInfo) => NewState(TunnelState::from(self)),
            Ok(TunnelRequest::Close) | Err(_) => SameState(self),
        }
    }
}

/// The tunnel has been started, but it is not established/functional.
struct ConnectingState {
    tunnel_events: mpsc::UnboundedReceiver<TunnelEvent>,
    tunnel_endpoint: TunnelEndpoint,
    tunnel_parameters: TunnelParameters,
    tunnel_close_event: oneshot::Receiver<Result<()>>,
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

    fn restart(exit_result: Result<()>, parameters: TunnelParameters) -> TunnelState {
        match exit_result {
            Err(error) => {
                let chained_error = error.chain_err(|| "Tunnel closed unexpectedly, restarting.");
                info!("{}", chained_error.display_chain());
            }
            _ => info!("Tunnel closed. Restarting."),
        }

        Self::start(parameters)
    }

    fn new(parameters: TunnelParameters) -> Result<Self> {
        let (event_tx, event_rx) = mpsc::unbounded();
        let listening_for_events = Arc::new(AtomicBool::new(true));
        let tunnel_endpoint = parameters.endpoint;
        let monitor =
            Self::spawn_tunnel_monitor(&parameters, event_tx, listening_for_events.clone())?;
        let tunnel_close_handle = monitor.close_handle();
        let tunnel_close_event = Self::spawn_tunnel_monitor_wait_thread(monitor);
        let close_handle = CloseHandle::new(tunnel_close_handle, listening_for_events);

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
        events: mpsc::UnboundedSender<TunnelEvent>,
        enable_events: Arc<AtomicBool>,
    ) -> Result<TunnelMonitor> {
        // Must wrap the channel in a Mutex because TunnelMonitor forces the closure to be Sync
        let event_tx = Mutex::new(events.wait());
        let on_tunnel_event = move |event| {
            if enable_events.load(Ordering::Acquire) {
                let _ = event_tx
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
    ) -> oneshot::Receiver<Result<()>> {
        let (tunnel_close_event_tx, tunnel_close_event_rx) = oneshot::channel();

        thread::spawn(move || {
            let result = tunnel_monitor
                .wait_at_least(MIN_TUNNEL_ALIVE_TIME_MS)
                .chain_err(|| "Tunnel has stopped unexpectedly");

            let _ = tunnel_close_event_tx.send(result);
            trace!("Tunnel monitor thread exit");
        });

        tunnel_close_event_rx
    }

    fn handle_requests(
        self,
        requests: &mut mpsc::UnboundedReceiver<TunnelRequest>,
    ) -> TunnelStateTransition<Self> {
        use self::TunnelStateTransition::*;

        match try_handle_event!(self, requests.poll()) {
            Ok(TunnelRequest::Start(parameters)) => {
                if parameters != self.tunnel_parameters {
                    self.close_handle.close();
                    NewState(RestartingState::new(self.tunnel_close_event, parameters))
                } else {
                    SameState(self)
                }
            }
            Ok(TunnelRequest::Restart(parameters)) => {
                self.close_handle.close();
                NewState(RestartingState::new(self.tunnel_close_event, parameters))
            }
            Ok(TunnelRequest::PollStateInfo) => NewState(TunnelState::from(self)),
            Ok(TunnelRequest::Close) | Err(_) => {
                self.close_handle.close();
                NewState(ExitingState::new(self.tunnel_close_event))
            }
        }
    }

    fn handle_tunnel_events(mut self) -> TunnelStateTransition<Self> {
        use self::TunnelStateTransition::*;

        match try_handle_event!(self, self.tunnel_events.poll()) {
            Ok(TunnelEvent::Up(metadata)) => NewState(ConnectedState::new(
                metadata,
                self.tunnel_events,
                self.tunnel_endpoint,
                self.tunnel_parameters,
                self.tunnel_close_event,
                self.close_handle,
            )),
            Ok(_) => SameState(self),
            Err(_) => {
                self.close_handle.close();
                NewState(RestartingState::new(
                    self.tunnel_close_event,
                    self.tunnel_parameters,
                ))
            }
        }
    }

    fn handle_tunnel_close_event(mut self) -> TunnelStateTransition<Self> {
        use self::TunnelStateTransition::*;

        let result = match self.tunnel_close_event.poll() {
            Ok(Async::Ready(result)) => result,
            Ok(Async::NotReady) => return NoEvents(self),
            Err(_cancelled) => Err(Error::from("Tunnel monitor thread has stopped")),
        };

        NewState(ConnectingState::restart(result, self.tunnel_parameters))
    }

    fn info(&self) -> TunnelStateInfo {
        TunnelStateInfo::Connecting(self.tunnel_endpoint)
    }
}

impl TunnelStateProgress for ConnectingState {
    fn handle_event(
        self,
        requests: &mut mpsc::UnboundedReceiver<TunnelRequest>,
    ) -> TunnelStateTransition<Self> {
        self.handle_requests(requests)
            .or_else(Self::handle_tunnel_events)
            .or_else(Self::handle_tunnel_close_event)
    }
}

/// The tunnel is up and working.
struct ConnectedState {
    tunnel_events: mpsc::UnboundedReceiver<TunnelEvent>,
    tunnel_endpoint: TunnelEndpoint,
    metadata: TunnelMetadata,
    tunnel_parameters: TunnelParameters,
    tunnel_close_event: oneshot::Receiver<Result<()>>,
    close_handle: CloseHandle,
}

impl ConnectedState {
    fn new(
        metadata: TunnelMetadata,
        tunnel_events: mpsc::UnboundedReceiver<TunnelEvent>,
        tunnel_endpoint: TunnelEndpoint,
        tunnel_parameters: TunnelParameters,
        tunnel_close_event: oneshot::Receiver<Result<()>>,
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

    fn handle_requests(
        self,
        requests: &mut mpsc::UnboundedReceiver<TunnelRequest>,
    ) -> TunnelStateTransition<Self> {
        use self::TunnelStateTransition::*;

        match try_handle_event!(self, requests.poll()) {
            Ok(TunnelRequest::Start(parameters)) => {
                if parameters != self.tunnel_parameters {
                    self.close_handle.close();
                    NewState(RestartingState::new(self.tunnel_close_event, parameters))
                } else {
                    SameState(self)
                }
            }
            Ok(TunnelRequest::Restart(parameters)) => {
                self.close_handle.close();
                NewState(RestartingState::new(self.tunnel_close_event, parameters))
            }
            Ok(TunnelRequest::PollStateInfo) => NewState(TunnelState::from(self)),
            Ok(TunnelRequest::Close) | Err(_) => {
                self.close_handle.close();
                NewState(ExitingState::new(self.tunnel_close_event))
            }
        }
    }

    fn handle_tunnel_events(mut self) -> TunnelStateTransition<Self> {
        use self::TunnelStateTransition::*;

        match try_handle_event!(self, self.tunnel_events.poll()) {
            Ok(TunnelEvent::Down) | Err(_) => {
                self.close_handle.close();
                NewState(RestartingState::new(
                    self.tunnel_close_event,
                    self.tunnel_parameters,
                ))
            }
            Ok(_) => SameState(self),
        }
    }

    fn handle_tunnel_close_event(mut self) -> TunnelStateTransition<Self> {
        use self::TunnelStateTransition::*;

        let result = match self.tunnel_close_event.poll() {
            Ok(Async::Ready(result)) => result,
            Ok(Async::NotReady) => return NoEvents(self),
            Err(_cancelled) => Err(Error::from("Tunnel monitor thread has stopped")),
        };

        NewState(ConnectingState::restart(result, self.tunnel_parameters))
    }

    fn info(&self) -> TunnelStateInfo {
        TunnelStateInfo::Connected(self.tunnel_endpoint, self.metadata.clone())
    }
}

impl TunnelStateProgress for ConnectedState {
    fn handle_event(
        self,
        requests: &mut mpsc::UnboundedReceiver<TunnelRequest>,
    ) -> TunnelStateTransition<Self> {
        self.handle_requests(requests)
            .or_else(Self::handle_tunnel_events)
            .or_else(Self::handle_tunnel_close_event)
    }
}

/// This state is active from when we manually trigger a tunnel kill until the tunnel wait
/// operation (TunnelExit) returned.
struct ExitingState {
    exited: oneshot::Receiver<Result<()>>,
}

impl ExitingState {
    fn new(exited: oneshot::Receiver<Result<()>>) -> TunnelState {
        ExitingState { exited }.into()
    }

    fn handle_requests(
        self,
        requests: &mut mpsc::UnboundedReceiver<TunnelRequest>,
    ) -> TunnelStateTransition<Self> {
        use self::TunnelStateTransition::*;

        match try_handle_event!(self, requests.poll()) {
            Ok(TunnelRequest::Start(parameters)) => {
                NewState(RestartingState::new(self.exited, parameters))
            }
            Ok(TunnelRequest::Restart(_)) => SameState(self),
            Ok(TunnelRequest::PollStateInfo) => NewState(TunnelState::from(self)),
            Ok(TunnelRequest::Close) | Err(_) => SameState(self),
        }
    }

    fn handle_exit_event(mut self) -> TunnelStateTransition<Self> {
        use self::TunnelStateTransition::*;

        let result = match self.exited.poll() {
            Ok(Async::Ready(result)) => result,
            Ok(Async::NotReady) => return NoEvents(self),
            Err(_cancelled) => Err(Error::from("Tunnel monitor thread has stopped")),
        };

        NewState(NotConnectedState::tunnel_closed(result))
    }
}

impl TunnelStateProgress for ExitingState {
    fn handle_event(
        self,
        requests: &mut mpsc::UnboundedReceiver<TunnelRequest>,
    ) -> TunnelStateTransition<Self> {
        self.handle_requests(requests)
            .or_else(Self::handle_exit_event)
    }
}

/// This state is active when the tunnel is being closed but will be reopened shortly afterwards.
struct RestartingState {
    exited: oneshot::Receiver<Result<()>>,
    parameters: TunnelParameters,
}

impl RestartingState {
    fn new(exited: oneshot::Receiver<Result<()>>, parameters: TunnelParameters) -> TunnelState {
        RestartingState { exited, parameters }.into()
    }

    fn handle_requests(
        mut self,
        requests: &mut mpsc::UnboundedReceiver<TunnelRequest>,
    ) -> TunnelStateTransition<Self> {
        use self::TunnelStateTransition::*;

        match try_handle_event!(self, requests.poll()) {
            Ok(TunnelRequest::Start(parameters)) | Ok(TunnelRequest::Restart(parameters)) => {
                self.parameters = parameters;
                SameState(self)
            }
            Ok(TunnelRequest::PollStateInfo) => NewState(TunnelState::from(self)),
            Ok(TunnelRequest::Close) | Err(_) => NewState(ExitingState::new(self.exited)),
        }
    }

    fn handle_exit_event(mut self) -> TunnelStateTransition<Self> {
        use self::TunnelStateTransition::*;

        let result = match self.exited.poll() {
            Ok(Async::Ready(result)) => result,
            Ok(Async::NotReady) => return NoEvents(self),
            Err(_cancelled) => Err(Error::from("Tunnel monitor thread has stopped")),
        };

        NewState(ConnectingState::restart(result, self.parameters))
    }
}

impl TunnelStateProgress for RestartingState {
    fn handle_event(
        self,
        requests: &mut mpsc::UnboundedReceiver<TunnelRequest>,
    ) -> TunnelStateTransition<Self> {
        self.handle_requests(requests)
            .or_else(Self::handle_exit_event)
    }
}
