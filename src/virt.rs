// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Wrapper around [`trussed::virt`][] that provides clients with both the core backend and the [`SoftwareRsa`](crate::SoftwareRsa) backend.

use crate::SoftwareRsa;

pub struct Dispatcher;
pub enum BackendIds {
    SoftwareRsa,
}
impl Dispatch for Dispatcher {
    type BackendId = BackendIds;
    type Context = ();
    fn request<P: Platform>(
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
    virt::{self, StoreConfig},
    Platform,
};

pub type Client<'a, D = Dispatcher> = virt::Client<'a, D>;

pub fn with_client<R, F>(store: StoreConfig, client_id: &str, f: F) -> R
where
    F: FnOnce(Client) -> R,
{
    virt::with_platform(store, |platform| {
        platform.run_client_with_backends(
            client_id,
            Dispatcher,
            &[BackendId::Custom(BackendIds::SoftwareRsa), BackendId::Core],
            f,
        )
    })
}

pub fn with_ram_client<R, F>(client_id: &str, f: F) -> R
where
    F: FnOnce(Client) -> R,
{
    with_client(StoreConfig::ram(), client_id, f)
}
