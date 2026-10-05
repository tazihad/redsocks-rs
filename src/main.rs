use clap::Parser;
use std::process::ExitCode;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};

use redsocks_rs::base::{apply_base_config, daemonize, write_pid_file};
use redsocks_rs::config::ConfigParser;
use redsocks_rs::dnstc::DnstcServer;
use redsocks_rs::dnsu2t::Dnsu2tServer;
use redsocks_rs::logger::RedsocksLogger;
use redsocks_rs::redirector::Redirector;
use redsocks_rs::redsocks::RedsocksInstance;
use redsocks_rs::redudp::RedudpListener;
use redsocks_rs::stats::StatsTracker;

#[derive(Parser, Debug)]
#[command(
    name = "redsocks",
    version = env!("CARGO_PKG_VERSION"),
    about = "High-performance transparent TCP-to-proxy redirector in Rust",
    long_about = "A complete, modern reimplementation of redsocks in Rust.\nRedirects TCP and UDP connections transparently to SOCKS4, SOCKS5, or HTTP proxies."
)]
struct Cli {
    /// Path to config file
    #[arg(short = 'c', default_value = "redsocks.conf")]
    config: String,

    /// Test config syntax and exit
    #[arg(short = 't')]
    test: bool,

    /// Write PID to specified file
    #[arg(short = 'p')]
    pidfile: Option<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // 1. Parse configuration
    let config = match ConfigParser::parse_file(&cli.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Configuration error in {}: {}", cli.config, e);
            return ExitCode::FAILURE;
        }
    };

    if cli.test {
        println!("Configuration syntax is OK");
        return ExitCode::SUCCESS;
    }

    // 2. Initialize logger
    if let Err(e) = RedsocksLogger::init(&config.base) {
        eprintln!("Failed to initialize logger: {}", e);
        return ExitCode::FAILURE;
    }

    // 3. Daemonize if requested
    if config.base.daemon {
        if let Err(e) = daemonize() {
            log::error!("Failed to daemonize: {}", e);
            return ExitCode::FAILURE;
        }
    }

    // 4. Write PID file if requested
    if let Some(pid_path) = &cli.pidfile {
        if let Err(e) = write_pid_file(pid_path) {
            log::error!("Failed to write PID file {}: {}", pid_path, e);
            return ExitCode::FAILURE;
        }
    }

    // 5. Apply base configuration (rlimit, chroot, drop privileges)
    if let Err(e) = apply_base_config(&config.base) {
        log::error!("Failed to apply base configuration: {}", e);
        return ExitCode::FAILURE;
    }

    // 6. Build Tokio async runtime
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            log::error!("Failed to build Tokio runtime: {}", e);
            return ExitCode::FAILURE;
        }
    };

    rt.block_on(async_main(config))
}

async fn async_main(config: redsocks_rs::config::AppConfig) -> ExitCode {
    let stats = StatsTracker::new();
    let redirector = Arc::new(Redirector::new(&config.base.redirector));

    let mut handles = Vec::new();

    // Spawn redsocks instances (TCP transparent redirectors)
    for redsocks_cfg in config.redsocks {
        let instance = Arc::new(RedsocksInstance::new(
            redsocks_cfg,
            config.base.clone(),
            redirector.clone(),
            stats.clone(),
        ));
        handles.push(tokio::spawn(async move {
            if let Err(e) = instance.run().await {
                log::error!("Redsocks instance terminated: {}", e);
            }
        }));
    }

    // Spawn redudp instances (UDP transparent proxy via SOCKS5 UDP ASSOCIATE)
    for redudp_cfg in config.redudp {
        let listener = Arc::new(RedudpListener::new(redudp_cfg));
        handles.push(tokio::spawn(async move {
            if let Err(e) = listener.run().await {
                log::error!("Redudp instance terminated: {}", e);
            }
        }));
    }

    // Spawn dnstc instances (DNS TCP Enforcer)
    for dnstc_cfg in config.dnstc {
        let server = Arc::new(DnstcServer::new(dnstc_cfg));
        handles.push(tokio::spawn(async move {
            if let Err(e) = server.run().await {
                log::error!("Dnstc server terminated: {}", e);
            }
        }));
    }

    // Spawn dnsu2t instances (DNS UDP-to-TCP multiplexing relay)
    for dnsu2t_cfg in config.dnsu2t {
        let server = Arc::new(Dnsu2tServer::new(dnsu2t_cfg));
        handles.push(tokio::spawn(async move {
            if let Err(e) = server.run().await {
                log::error!("Dnsu2t server terminated: {}", e);
            }
        }));
    }

    log::info!(
        "redsocks-rs started successfully with {} services",
        handles.len()
    );

    // Signal handlers: SIGTERM, SIGINT for graceful shutdown; SIGUSR1 for status dump
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to register SIGTERM handler: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to register SIGINT handler: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let mut sigusr1 = match signal(SignalKind::user_defined1()) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to register SIGUSR1 handler: {}", e);
            return ExitCode::FAILURE;
        }
    };

    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                log::info!("Received SIGTERM, shutting down...");
                break;
            }
            _ = sigint.recv() => {
                log::info!("Received SIGINT, shutting down...");
                break;
            }
            _ = sigusr1.recv() => {
                stats.dump_clients();
            }
        }
    }

    for handle in handles {
        handle.abort();
    }

    log::info!("redsocks-rs stopped cleanly");
    ExitCode::SUCCESS
}
