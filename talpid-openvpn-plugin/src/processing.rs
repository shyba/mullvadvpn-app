use openvpn_plugin;
use std::collections::HashMap;

use jsonrpc_client_core::{Client, Future};
use jsonrpc_client_ipc::IpcTransport;
use std::sync::Mutex;
use tokio_core::reactor::Core;

use super::Arguments;

error_chain! {
    errors {
        IpcSendingError {
            description("Failed while sending an event over the IPC channel")
        }
    }
}


/// Struct processing OpenVPN events and notifies listeners over IPC
pub struct EventProcessor {
    ipc_client: Mutex<EventProxy>,
    client: Option<Client>,
    core: Core,
}

impl EventProcessor {
    pub fn new(arguments: Arguments) -> Result<EventProcessor> {
        trace!("Creating EventProcessor");
        let mut core = Core::new().chain_err(|| "Unable to initialize Tokio Core")?;
        let handle = core.handle();
        let (client, client_handle) = IpcTransport::new(&arguments.ipc_socket_path, &handle).chain_err(|| "Unable to create IPC transport")?.into_client();
        let ipc_client = EventProxy::new(client_handle);

        Ok(EventProcessor {
            ipc_client: Mutex::new(ipc_client),
            client,
            core,
        })
    }

    pub fn process_event(
        &mut self,
        event: openvpn_plugin::types::OpenVpnPluginEvent,
        env: HashMap<String, String>,
    ) -> Result<()> {
        trace!("Processing \"{:?}\" event", event);
        let call_future = self.ipc_client
            .lock()
            .expect("Some thread panicked while locking the ipc_client")
            .openvpn_event(event, env)
            .map_err(|e| Error::with_chain(e, ErrorKind::IpcSendingError));
        // Create combined future of `call_future` and `self.client` and run that on `self.core`
        // until completion...
        self.core.run(self.client...)
    }
}

jsonrpc_client!(pub struct EventProxy {
    pub fn openvpn_event(&mut self, event: openvpn_plugin::types::OpenVpnPluginEvent, env: HashMap<String, String>) -> Future<()>;
});
