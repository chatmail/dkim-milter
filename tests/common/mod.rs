use dkim_milter::{CliOptions, Config, LogDestination, LogLevel, LookupFuture, Socket, StubConfig};
use std::{
    env,
    error::Error,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Once,
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time,
};

pub const LOCALHOST: (Ipv4Addr, u16) = (Ipv4Addr::LOCALHOST, 0);

pub fn default_cli_options() -> CliOptions {
    // Set this environment variable to test debug logging to syslog.
    if env::var("DKIM_MILTER_TEST_LOG").is_ok() {
        CliOptions {
            log_destination: Some(LogDestination::Syslog),
            log_level: Some(LogLevel::Debug),
            ..Default::default()
        }
    } else {
        CliOptions {
            log_destination: Some(LogDestination::Stderr),
            log_level: Some(LogLevel::Debug),
            ..Default::default()
        }
    }
}

// Because each file in tests/ is compiled as its own crate, each integration
// test file will have its own `Once` ensuring logging for the tests in that
// file is installed only once.
static INIT_LOG: Once = Once::new();

pub async fn read_config(opts: CliOptions) -> Result<Config, Box<dyn Error>> {
    let config = StubConfig::read(opts).await?;

    INIT_LOG.call_once(|| config.install_static_logger().unwrap());

    let config = config.read_fully().await?;

    Ok(config)
}

pub async fn read_config_with_lookup(
    opts: CliOptions,
    lookup: impl Fn(&str) -> LookupFuture + Send + Sync + 'static,
) -> Result<Config, Box<dyn Error>> {
    let config = StubConfig::read(opts).await?;

    INIT_LOG.call_once(|| config.install_static_logger().unwrap());

    let config = config.read_fully_with_lookup(lookup).await?;

    Ok(config)
}

pub struct DkimMilter {
    milter_handle: JoinHandle<io::Result<()>>,
    reload: mpsc::Sender<()>,
    shutdown: oneshot::Sender<()>,
    addr: SocketAddr,
}

impl DkimMilter {
    pub async fn spawn(config: Config) -> io::Result<Self> {
        let listener = match config.socket() {
            Socket::Inet(addr) => TcpListener::bind(addr).await?,
            Socket::Unix(_) => unimplemented!(),
        };

        let addr = listener.local_addr()?;

        let (reload_tx, reload_rx) = mpsc::channel(1);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let milter = tokio::spawn(dkim_milter::run(listener, config, reload_rx, shutdown_rx));

        Ok(Self {
            milter_handle: milter,
            reload: reload_tx,
            shutdown: shutdown_tx,
            addr,
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub async fn reload_config(&self) {
        self.reload.send(()).await.unwrap();

        time::sleep(Duration::from_millis(100)).await;
    }

    pub async fn shutdown(self) -> io::Result<()> {
        let _ = self.shutdown.send(());

        self.milter_handle.await?
    }
}
