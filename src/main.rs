use dkim_milter::{CliOptions, Config, LogDestination, Socket, MILTER_NAME, VERSION};
use futures::stream::StreamExt;
use indymilter::Listener;
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook_tokio::{Handle, Signals};
use std::{
    env,
    error::Error,
    io::{stderr, stdout, Write},
    os::unix::fs::FileTypeExt,
    path::Path,
    process,
};
use tokio::{
    fs,
    net::{TcpListener, UnixListener},
    sync::oneshot,
    task::JoinHandle,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

const PROGRAM_NAME: &str = env!("CARGO_BIN_NAME");

#[tokio::main]
async fn main() {
    let opts = match parse_args() {
        Ok(opts) => opts,
        Err(e) => {
            let _ = writeln!(stderr(), "{PROGRAM_NAME}: {e}");
            process::exit(1);
        }
    };

    let registry = tracing_subscriber::registry();
    let env_filter = EnvFilter::from_default_env();

    match opts.log_destination {
        None | Some(LogDestination::Journald) => {
            let journald = tracing_journald::layer().unwrap();
            registry.with(journald).with(env_filter).init();
        }
        Some(LogDestination::Stderr) => {
            let stderr = tracing_subscriber::fmt::layer().with_writer(stderr);
            registry.with(stderr).with(env_filter).init();
        }
    }

    // TODO config reading needs logging, but logging needs config read

    let config = match Config::read(opts).await {
        Ok(config) => config,
        Err(e) => {
            let _ = writeln!(stderr(), "{PROGRAM_NAME}: {e}");
            process::exit(1);
        }
    };

    let (shutdown_tx, shutdown) = oneshot::channel();

    let signals =
        Signals::new([SIGINT, SIGTERM]).expect("failed to install signal handler");
    let signals_handle = signals.handle();
    let signals_task = spawn_signals_task(signals, shutdown_tx);

    let addr;
    let mut socket_path = None;
    let listener = match &config.socket {
        Socket::Inet(socket) => {
            let listener = match TcpListener::bind(socket).await {
                Ok(listener) => listener,
                Err(e) => {
                    let _ = writeln!(stderr(), "{PROGRAM_NAME}: could not bind TCP socket: {e}");
                    process::exit(1);
                }
            };

            Listener::Tcp(listener)
        }
        Socket::Unix(socket) => {
            // Before creating the socket file, try removing any existing socket
            // at the target path. This is to clear out a leftover file from a
            // previous, aborted execution.
            try_remove_socket(&socket).await;

            let listener = match UnixListener::bind(socket) {
                Ok(listener) => listener,
                Err(e) => {
                    let _ = writeln!(stderr(), "{PROGRAM_NAME}: could not create UNIX domain socket: {e}");
                    process::exit(1);
                }
            };

            // Remember the socket file path, and delete it on shutdown.
            addr = listener.local_addr().unwrap();
            socket_path = addr.as_pathname();

            Listener::Unix(listener)
        }
    };

    let result = dkim_milter::run(listener, config, shutdown).await;

    cleanup(signals_handle, signals_task, socket_path).await;

    if let Err(e) = result {
        let _ = writeln!(stderr(), "{PROGRAM_NAME}: {e}");
        process::exit(1);
    }
}

const USAGE_TEXT: &str = "\
[options]

Options:
  -c, --config-file <path>          Path to configuration file
  -h, --help                        Print usage information
  -l, --log-destination <target>    Destination for log messages
  -p, --socket <socket>             Listening socket of the milter
  -V, --version                     Print version information
";

fn parse_args() -> Result<CliOptions, Box<dyn Error>> {
    let mut args = env::args_os()
        .skip(1)
        .map(|s| s.into_string().map_err(|_| "invalid UTF-8 bytes in argument"));

    let mut opts = CliOptions::default();

    while let Some(arg) = args.next() {
        let arg = arg?;

        let missing_value = || format!("missing value for option {arg}");

        match arg.as_str() {
            "-h" | "--help" => {
                write!(stdout(), "Usage: {PROGRAM_NAME} {USAGE_TEXT}")?;
                process::exit(0);
            }
            "-V" | "--version" => {
                writeln!(stdout(), "{MILTER_NAME} {VERSION}")?;
                process::exit(0);
            }
            "-c" | "--config-file" => {
                let path = args.next().ok_or_else(missing_value)??;

                opts.config_file = path.into();
            }
            "-l" | "--log-destination" => {
                let arg = args.next().ok_or_else(missing_value)??;
                let target = arg.parse()
                    .map_err(|_| format!("invalid value for log destination: \"{arg}\""))?;

                opts.log_destination = Some(target);
            }
            "-p" | "--socket" => {
                let arg = args.next().ok_or_else(missing_value)??;
                let socket = arg.parse()
                    .map_err(|_| format!("invalid value for socket: \"{arg}\""))?;

                opts.socket = Some(socket);
            }
            arg => return Err(format!("unrecognized option: \"{arg}\"").into()),
        }
    }

    Ok(opts)
}

fn spawn_signals_task(
    mut signals: Signals,
    shutdown_milter: oneshot::Sender<()>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(signal) = signals.next().await {
            match signal {
                SIGINT | SIGTERM => {
                    let _ = shutdown_milter.send(());
                    break;
                }
                _ => panic!("unexpected signal"),
            }
        }
    })
}

async fn cleanup(signals_handle: Handle, signals_task: JoinHandle<()>, socket_path: Option<&Path>) {
    signals_handle.close();
    signals_task.await.expect("signal handler task failed");

    if let Some(p) = socket_path {
        try_remove_socket(p).await;
    }
}

async fn try_remove_socket(path: impl AsRef<Path>) {
    if let Ok(metadata) = fs::metadata(&path).await {
        if metadata.file_type().is_socket() {
            let _ = fs::remove_file(path).await;
        }
    }
}
