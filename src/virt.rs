/// Wrapper around [`trussed::virt`][] that provides clients with both the core backend and the [`SoftwareRsa`](crate::SoftwareRsa) backend.
use crate::SoftwareRsa;

pub struct Dispatcher;
pub enum BackendIds {
    SoftwareRsa,
}
impl<P: Platform> Dispatch<P> for Dispatcher {
    type BackendId = BackendIds;
    type Context = ();
    fn request(
        &mut self,
        _backend: &Self::BackendId,
        ctx: &mut trussed::types::Context<Self::Context>,
        request: &trussed::api::Request,
        resources: &mut trussed::service::ServiceResources<P>,
    ) -> Result<trussed::Reply, trussed::Error> {
        SoftwareRsa.request(&mut ctx.core, &mut ctx.backends, request, resources)
    }
}

use std::path::PathBuf;
use trussed::{
    backend::{Backend, BackendId, Dispatch},
    virt::{self, Client, Filesystem, Ram, StoreProvider},
    Platform,
};

pub fn with_client<S, R, F>(store: S, client_id: &str, f: F) -> R
where
    F: FnOnce(Client<S, Dispatcher>) -> R,
    S: StoreProvider,
{
    virt::with_platform(store, |platform| {
        platform.run_client_with_backends(
            client_id,
            Dispatcher,
            &[BackendId::Custom(BackendIds::SoftwareRsa), BackendId::Core],
            |client| f(client),
        )
    })
}

pub fn with_fs_client<P, R, F>(internal: P, client_id: &str, f: F) -> R
where
    F: FnOnce(Client<Filesystem, Dispatcher>) -> R,
    P: Into<PathBuf>,
{
    with_client(Filesystem::new(internal), client_id, f)
}

pub fn with_ram_client<R, F>(client_id: &str, f: F) -> R
where
    F: FnOnce(Client<Ram, Dispatcher>) -> R,
{
    with_client(Ram::default(), client_id, f)
}
