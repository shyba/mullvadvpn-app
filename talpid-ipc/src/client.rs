use std::thread;
use tokio_core::reactor::Core;
use jsonrpc_client_ipc;
use jsonrpc_client_core;
use jsonrpc_client_core::Future;
use error_chain::ChainedError;

error_chain! {
    errors {
        CoreError { description("Error when creating event loop") }
    }
}

pub fn connect(path: String) -> Result<jsonrpc_client_core::ClientHandle> {
        create(move |core| {
            let handle = core.handle();
            let (client, client_handle) = jsonrpc_client_ipc::IpcTransport::new(&path, &handle).unwrap().into_client();
            handle.spawn(client.map_err(|e| {
                error!("{}", e.display_chain());
            }));
            client_handle
        })
}

/// Creates a new tokio event loop on a new thread, runs the provided `init` closure on the thread
/// and sends back the result.
/// Used to spawn futures on the core in the separate thread and be able to return sendable handles.
fn create<F, T>(init: F) -> Result<T>
where
    F: FnOnce(&mut Core) -> T + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = ::std::sync::mpsc::channel();
    thread::spawn(move || match create_core(init) {
        Err(e) => tx.send(Err(e)).unwrap(),
        Ok((mut core, out)) => {
            tx.send(Ok(out)).unwrap();
            loop {
                core.turn(None);
            }
        }
    });
    rx.recv().unwrap()
}

fn create_core<F, T>(init: F) -> Result<(Core, T)>
where
    F: FnOnce(&mut Core) -> T + Send + 'static,
{
    let mut core = Core::new().chain_err(|| ErrorKind::CoreError)?;
    let out = init(&mut core);
    Ok((core, out))
}
