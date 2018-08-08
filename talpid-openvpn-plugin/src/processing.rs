use openvpn_plugin;
use std::collections::HashMap;
use talpid_ipc;
use jsonrpc_client_core::Future;
use std::sync::Mutex;

use super::Arguments;

error_chain! {
    errors {
        AuthDenied {
            description("Failed to authenticate with Talpid IPC server")
        }
        IpcSendingError {
            description("Failed while sending an event over the IPC channel")
        }
    }
}


/// Struct processing OpenVPN events and notifies listeners over IPC
pub struct EventProcessor {
    ipc_client: Mutex<EventProxy>,
}

impl EventProcessor {
    pub fn new(arguments: Arguments) -> Result<EventProcessor> {
        trace!("Creating EventProcessor");
        let ipc_client_handle = talpid_ipc::connect(arguments.ipc_socket_path)
            .chain_err(|| "Unable to create IPC client")?;
        let ipc_client = EventProxy::new(ipc_client_handle);

        Ok(EventProcessor {
            ipc_client: Mutex::new(ipc_client),
        })
    }

    pub fn process_event(
        &mut self,
        event: openvpn_plugin::types::OpenVpnPluginEvent,
        env: HashMap<String, String>,
    ) -> Result<()> {
        trace!("Processing \"{:?}\" event", event);
        self.ipc_client
            .lock()
            .expect("Some thread panicked while locking the ipc_client")
            .openvpn_event(event, env)
            .map_err(|e| Error::with_chain(e, ErrorKind::IpcSendingError))
            .wait()
    }
}

jsonrpc_client!(pub struct EventProxy {
    pub fn openvpn_event(&mut self, event: openvpn_plugin::types::OpenVpnPluginEvent, env: HashMap<String, String>) -> Future<()>;
});
