use crate::{config::Config, session::Session};
use byte_strings::c_str;
use indymilter::{
    Actions, Callbacks, Context, EomContext, MacroStage, Macros, NegotiateContext, ProtoOpts,
    SocketInfo, Status,
};
use std::{
    borrow::Cow,
    ffi::{CStr, CString},
    sync::Arc,
};
use tracing::{debug, error};

trait MacrosExt {
    fn get_string(&self, name: &CStr) -> Option<Cow<'_, str>>;
    fn queue_id(&self) -> Cow<'_, str>;
}

impl MacrosExt for Macros {
    fn get_string(&self, name: &CStr) -> Option<Cow<'_, str>> {
        self.get(name).map(|v| v.to_string_lossy())
    }

    fn queue_id(&self) -> Cow<'_, str> {
        self.get_string(c_str!("i"))
            .unwrap_or_else(|| "NONE".into())
    }
}

pub fn make_callbacks(config: Arc<Config>) -> Callbacks<Session> {
    Callbacks::new()
        .on_negotiate(move |cx, _, _| Box::pin(handle_negotiate(config.clone(), cx)))
        .on_connect(|cx, _, socket_info| Box::pin(handle_connect(cx, socket_info)))
        .on_mail(|cx, smtp_args| Box::pin(handle_mail(cx, smtp_args)))
        .on_header(|cx, name, value| Box::pin(handle_header(cx, name, value)))
        .on_eoh(|cx| Box::pin(handle_eoh(cx)))
        .on_body(|cx, chunk| Box::pin(handle_body(cx, chunk)))
        .on_eom(|cx| Box::pin(handle_eom(cx)))
        .on_abort(|cx| Box::pin(handle_abort(cx)))
        .on_close(|cx| Box::pin(handle_close(cx)))
}

async fn handle_negotiate(config: Arc<Config>, context: &mut NegotiateContext<Session>) -> Status {
    context.requested_actions |= Actions::ADD_HEADER;
    context.requested_opts |= ProtoOpts::SKIP | ProtoOpts::LEADING_SPACE;

    let macros = &mut context.requested_macros;
    macros.insert(MacroStage::Connect, c_str!("j").into());
    macros.insert(MacroStage::Mail, c_str!("{auth_type}").into());
    macros.insert(MacroStage::Data, c_str!("i").into());

    context.data = Some(Session::new(config));

    Status::Continue
}

async fn handle_connect(context: &mut Context<Session>, socket_info: SocketInfo) -> Status {
    debug!("connecting from {socket_info:?}");

    let session = context.data.as_mut().unwrap();

    let ip = match socket_info {
        SocketInfo::Inet(addr) => Some(addr.ip()),
        _ => None,
    };

    let hostname = context
        .macros
        .get_string(c_str!("j"))
        .map_or_else(|| "unknown".into(), |h| h.into_owned());

    session.ip = ip;
    session.hostname = Some(hostname);

    Status::Continue
}

async fn handle_mail(context: &mut Context<Session>, smtp_args: Vec<CString>) -> Status {
    let session = context.data.as_mut().unwrap();

    if let Some(_login) = context.macros.get_string(c_str!("{auth_type}")) {
        session.auth = true;
    }

    let _mail_from = smtp_args[0].to_string_lossy();

    Status::Continue
}

async fn handle_header(context: &mut Context<Session>, name: CString, value: CString) -> Status {
    let session = context.data.as_mut().unwrap();
    let id = context.macros.queue_id();

    let name = name.to_string_lossy();
    let value = value.into_bytes();

    match session.handle_header(&id, name, value) {
        Ok(status) => status,
        Err(e) => {
            error!("{id}: failed to handle header callback: {e}");
            Status::Tempfail
        }
    }
}

async fn handle_eoh(context: &mut Context<Session>) -> Status {
    let session = context.data.as_mut().unwrap();
    let id = context.macros.queue_id();

    match session.prepare_processing(&id).await {
        Ok(status) => status,
        Err(e) => {
            error!("{id}: failed to handle eoh callback: {e}");
            Status::Tempfail
        }
    }
}

async fn handle_body(context: &mut Context<Session>, chunk: impl AsRef<[u8]>) -> Status {
    let session = context.data.as_mut().unwrap();
    let id = context.macros.queue_id();

    match session.process_body_chunk(chunk.as_ref()) {
        Ok(status) => status,
        Err(e) => {
            error!("{id}: failed to handle body callback: {e}");
            Status::Tempfail
        }
    }
}

async fn handle_eom(context: &mut EomContext<Session>) -> Status {
    debug!("finishing message");

    let session = context.data.as_mut().unwrap();
    let id = context.macros.queue_id();

    match session.finish_message(&id, &context.actions).await {
        Ok(status) => status,
        Err(e) => {
            error!("{id}: failed to handle eom callback: {e}");
            Status::Tempfail
        }
    }
}

async fn handle_abort(context: &mut Context<Session>) -> Status {
    let session = context.data.as_mut().unwrap();

    session.abort_message();

    Status::Continue
}

async fn handle_close(context: &mut Context<Session>) -> Status {
    context.data = None;

    Status::Continue
}
