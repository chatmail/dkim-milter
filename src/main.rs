use dkim_milter::{MILTER_NAME, VERSION};
use futures::stream::StreamExt;
use indymilter::Listener;
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook_tokio::{Handle, Signals};
use std::{env, error::Error, os::unix::fs::FileTypeExt, path::Path, process, str::FromStr};
use tokio::{
    fs,
    net::{TcpListener, UnixListener},
    sync::oneshot,
    task::JoinHandle,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() {
    match parse_args() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    }

    let journald = tracing_journald::layer().unwrap();

    tracing_subscriber::registry()
        // .with(tracing_subscriber::fmt::layer())  // TODO uncomment for stderr logging
        .with(journald)
        .with(EnvFilter::from_default_env())
        .init();

    // TODO
    // let config = match Config::read(opts).await {
    //     Ok(config) => config,
    //     Err(e) => {
    //         eprintln!("error: {}", e);
    //         process::exit(1);
    //     }
    // };

    let (shutdown_tx, shutdown) = oneshot::channel();

    let signals =
        Signals::new([SIGINT, SIGTERM]).expect("failed to install signal handler");
    let signals_handle = signals.handle();
    let signals_task = spawn_signals_task(signals, shutdown_tx);

    // TODO
    let socket: Socket = if true {
        "inet:127.0.0.1:3000".parse().unwrap()
    } else {
        todo!()
    };

    let addr;
    let mut socket_path = None;
    let listener = match socket {
        Socket::Inet(socket) => {
            let listener = match TcpListener::bind(socket).await {
                Ok(listener) => listener,
                Err(e) => {
                    eprintln!("error: could not bind TCP socket: {}", e);
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
                    eprintln!("error: could not create UNIX domain socket: {}", e);
                    process::exit(1);
                }
            };

            // Remember the socket file path, and delete it on shutdown.
            addr = listener.local_addr().unwrap();
            socket_path = addr.as_pathname();

            Listener::Unix(listener)
        }
    };

    let result = dkim_milter::run(listener, shutdown).await;

    cleanup(signals_handle, signals_task, socket_path).await;

    if let Err(e) = result {
        eprintln!("error: {}", e);
        process::exit(1);
    }
}

enum Socket {
    Inet(String),
    Unix(String),
}

impl FromStr for Socket {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(s) = s.strip_prefix("inet:") {
            Ok(Self::Inet(s.into()))
        } else if let Some(s) = s.strip_prefix("unix:") {
            Ok(Self::Unix(s.into()))
        } else {
            Err(format!("invalid value for socket: \"{}\"", s))
        }
    }
}

const USAGE_TEXT: &str = "\
Usage:
  dkim-milter [options...]

Options:
  -h, --help                        Print usage information
  -V, --version                     Print version information
";

fn parse_args() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os()
        .skip(1)
        .map(|s| s.into_string().map_err(|_| "invalid UTF-8 bytes in argument"));

    while let Some(arg) = args.next() {
        let arg = arg?;

        let _missing_value = || format!("missing value for option {}", arg);

        match arg.as_str() {
            "-h" | "--help" => {
                println!("{} {}", MILTER_NAME, VERSION);
                println!();
                print!("{}", USAGE_TEXT);
                process::exit(0);
            }
            "-V" | "--version" => {
                println!("{} {}", MILTER_NAME, VERSION);
                process::exit(0);
            }
            arg => return Err(format!("unrecognized option: \"{}\"", arg).into()),
        }
    }

    Ok(())
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
