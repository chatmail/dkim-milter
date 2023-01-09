use dkim_milter::{Config, Socket};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};

pub const LOCALHOST: (Ipv4Addr, u16) = (Ipv4Addr::LOCALHOST, 0);

pub struct DkimMilter {
    milter_handle: JoinHandle<io::Result<()>>,
    shutdown: oneshot::Sender<()>,
    addr: SocketAddr,
}

impl DkimMilter {
    pub async fn spawn(config: Config) -> io::Result<Self> {
        let listener = match &config.socket {
            Socket::Inet(addr) => TcpListener::bind(addr).await?,
            Socket::Unix(_) => unimplemented!(),
        };

        let addr = listener.local_addr()?;

        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let milter = tokio::spawn(dkim_milter::run(listener, config, shutdown_rx));

        Ok(Self {
            milter_handle: milter,
            shutdown: shutdown_tx,
            addr,
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub async fn shutdown(self) -> io::Result<()> {
        let _ = self.shutdown.send(());

        self.milter_handle.await?
    }
}
