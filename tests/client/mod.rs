use trussed_rsa_backend::SoftwareRsa;

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

use trussed::{
    backend::{Backend, BackendId, Dispatch},
    virt::{self, Client, Ram},
    Platform,
};

pub fn get<R, F: FnOnce(&mut Client<Ram, Dispatcher>) -> R>(test: F) -> R {
    virt::with_platform(Ram::default(), |platform| {
        platform.run_client_with_backends(
            "rsa tests",
            Dispatcher,
            &[BackendId::Custom(BackendIds::SoftwareRsa), BackendId::Core],
            |mut client| test(&mut client),
        )
    })
}
