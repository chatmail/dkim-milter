// DKIM Milter – milter for DKIM signing and verification
// Copyright © 2022–2023 David Bürgin <dbuergin@gluet.ch>
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.

use crate::{config::SessionConfig, session::Session};
use byte_strings::c_str;
use indymilter::{
    Actions, Callbacks, Context, EomContext, MacroStage, Macros, NegotiateContext, ProtoOpts,
    SocketInfo, Status,
};
use log::{error, warn};
use std::{
    borrow::Cow,
    ffi::{CStr, CString},
    sync::{Arc, RwLock},
};

macro_rules! get_session {
    ($context:expr) => {
        match $context.data.as_mut() {
            ::std::option::Option::Some(session) => session,
            ::std::option::Option::None => return ::indymilter::Status::Tempfail,
        }
    };
}

trait MacrosExt {
    fn get_string(&self, name: &CStr) -> Option<Cow<'_, str>>;

    fn queue_id(&self) -> Cow<'_, str> {
        self.get_string(c_str!("i"))
            .unwrap_or_else(|| "NONE".into())
    }
}

impl MacrosExt for Macros {
    fn get_string(&self, name: &CStr) -> Option<Cow<'_, str>> {
        self.get(name).map(|v| v.to_string_lossy())
    }
}

pub fn make_callbacks(session_config: Arc<RwLock<Arc<SessionConfig>>>) -> Callbacks<Session> {
    Callbacks::new()
        .on_negotiate(move |cx, actions, opts| {
            Box::pin(handle_negotiate(session_config.clone(), cx, actions, opts))
        })
        .on_connect(|cx, _, socket_info| Box::pin(handle_connect(cx, socket_info)))
        .on_mail(|cx, smtp_args| Box::pin(handle_mail(cx, smtp_args)))
        .on_rcpt(|cx, smtp_args| Box::pin(handle_rcpt(cx, smtp_args)))
        .on_header(|cx, name, value| Box::pin(handle_header(cx, name, value)))
        .on_eoh(|cx| Box::pin(handle_eoh(cx)))
        .on_body(|cx, chunk| Box::pin(handle_body(cx, chunk)))
        .on_eom(|cx| Box::pin(handle_eom(cx)))
        .on_abort(|cx| Box::pin(handle_abort(cx)))
        .on_close(|cx| Box::pin(handle_close(cx)))
}

async fn handle_negotiate(
    session_config: Arc<RwLock<Arc<SessionConfig>>>,
    context: &mut NegotiateContext<Session>,
    supported_actions: Actions,
    supported_opts: ProtoOpts,
) -> Status {
    let session_config = session_config.read()
        .expect("could not get configuration read lock")
        .clone();

    let config = &session_config.config;

    if !config.dry_run {
        if !supported_actions.contains(Actions::ADD_HEADER) {
            error!("MTA does not support adding headers, aborting");
            return Status::Reject;
        }
        context.requested_actions |= Actions::ADD_HEADER;

        if config.delete_incoming_authentication_results {
            if !supported_actions.contains(Actions::CHANGE_HEADER) {
                error!("MTA does not support altering headers, aborting");
                return Status::Reject;
            }
            context.requested_actions |= Actions::CHANGE_HEADER;
        }
    }

    if !supported_opts.contains(ProtoOpts::LEADING_SPACE) {
        error!("MTA does not support accurate whitespace handling in headers, aborting");
        return Status::Reject;
    }
    context.requested_opts |= ProtoOpts::LEADING_SPACE;

    let can_skip = supported_opts.contains(ProtoOpts::SKIP);
    if can_skip {
        context.requested_opts |= ProtoOpts::SKIP;
    } else {
        // Only `warn!` here, we can proceed just fine without `Skip`.
        warn!("MTA does not support skipping repeated callback calls");
    }

    let macros = &mut context.requested_macros;
    macros.insert(MacroStage::Connect, c_str!("j").into());
    macros.insert(MacroStage::Mail, c_str!("{auth_type}").into());
    macros.insert(MacroStage::Data, c_str!("i").into());

    context.data = Some(Session::new(session_config, can_skip));

    Status::Continue
}

async fn handle_connect(context: &mut Context<Session>, socket_info: SocketInfo) -> Status {
    let session = get_session!(context);

    let ip = match socket_info {
        SocketInfo::Inet(addr) => Some(addr.ip()),
        _ => None,
    };

    let hostname = context.macros.get_string(c_str!("j"))
        .map_or_else(|| "unknown".into(), |h| h.into_owned());

    session.init_connection(ip, hostname);

    Status::Continue
}

async fn handle_mail(context: &mut Context<Session>, smtp_args: Vec<CString>) -> Status {
    let session = get_session!(context);

    session.init_message();

    let mail_from = smtp_args[0].to_string_lossy();

    session.set_envelope_sender(mail_from.into());

    if context.macros.get_string(c_str!("{auth_type}")).is_some() {
        session.set_authenticated();
    }

    Status::Continue
}

async fn handle_rcpt(context: &mut Context<Session>, smtp_args: Vec<CString>) -> Status {
    let session = get_session!(context);

    let rcpt_to = smtp_args[0].to_string_lossy();

    session.add_envelope_recipient(rcpt_to.into());

    Status::Continue
}

async fn handle_header(context: &mut Context<Session>, name: CString, value: CString) -> Status {
    let session = get_session!(context);
    let id = context.macros.queue_id();

    let name = name.to_string_lossy();
    let value = value.into_bytes();

    match session.process_header(&id, name, value) {
        Ok(status) => status,
        Err(e) => {
            error!("{id}: failed to handle header callback: {e}");
            Status::Tempfail
        }
    }
}

async fn handle_eoh(context: &mut Context<Session>) -> Status {
    let session = get_session!(context);
    let id = context.macros.queue_id();

    match session.init_processing(&id).await {
        Ok(status) => status,
        Err(e) => {
            error!("{id}: failed to handle eoh callback: {e}");
            Status::Tempfail
        }
    }
}

async fn handle_body(context: &mut Context<Session>, chunk: impl AsRef<[u8]>) -> Status {
    let session = get_session!(context);
    let id = context.macros.queue_id();

    match session.process_body_chunk(chunk.as_ref()) {
        Ok(status) => match status {
            Status::Skip if !session.can_skip() => Status::Continue,
            status => status,
        },
        Err(e) => {
            error!("{id}: failed to handle body callback: {e}");
            Status::Tempfail
        }
    }
}

async fn handle_eom(context: &mut EomContext<Session>) -> Status {
    let session = get_session!(context);
    let id = context.macros.queue_id();

    match session.finish_message(&id, &mut context.reply, &context.actions).await {
        Ok(status) => status,
        Err(e) => {
            error!("{id}: failed to handle eom callback: {e}");
            Status::Tempfail
        }
    }
}

async fn handle_abort(context: &mut Context<Session>) -> Status {
    let session = get_session!(context);

    session.abort_message();

    Status::Continue
}

async fn handle_close(context: &mut Context<Session>) -> Status {
    context.data = None;

    Status::Continue
}
