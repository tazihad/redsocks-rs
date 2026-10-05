use log::{Level, LevelFilter, Metadata, Record};
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use std::time::SystemTime;

use crate::config::types::BaseConfig;

enum LogDestination {
    Stderr,
    File(Mutex<std::fs::File>),
    Syslog,
}

pub struct RedsocksLogger {
    dest: LogDestination,
    max_level: LevelFilter,
}

impl RedsocksLogger {
    pub fn init(config: &BaseConfig) -> Result<(), log::SetLoggerError> {
        let max_level = if config.log_debug {
            LevelFilter::Debug
        } else if config.log_info {
            LevelFilter::Info
        } else {
            LevelFilter::Warn
        };

        let dest = if config.log.starts_with("file:") {
            let path = config.log.strip_prefix("file:").unwrap().trim();
            match OpenOptions::new().create(true).append(true).open(path) {
                Ok(file) => LogDestination::File(Mutex::new(file)),
                Err(e) => {
                    eprintln!(
                        "Failed to open log file {}: {}, falling back to stderr",
                        path, e
                    );
                    LogDestination::Stderr
                }
            }
        } else if config.log.starts_with("syslog:") {
            LogDestination::Syslog
        } else {
            LogDestination::Stderr
        };

        let logger = Box::new(RedsocksLogger { dest, max_level });
        log::set_max_level(max_level);
        log::set_boxed_logger(logger)
    }
}

impl log::Log for RedsocksLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.max_level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let msg = format!("[{}] [{}] {}\n", now, record.level(), record.args());

        match &self.dest {
            LogDestination::Stderr => {
                let _ = std::io::stderr().write_all(msg.as_bytes());
            }
            LogDestination::File(file_mutex) => {
                if let Ok(mut f) = file_mutex.lock() {
                    let _ = f.write_all(msg.as_bytes());
                    let _ = f.flush();
                }
            }
            LogDestination::Syslog => {
                #[cfg(target_family = "unix")]
                {
                    use std::ffi::CString;
                    let prio = match record.level() {
                        Level::Error => libc::LOG_ERR,
                        Level::Warn => libc::LOG_WARNING,
                        Level::Info => libc::LOG_INFO,
                        Level::Debug | Level::Trace => libc::LOG_DEBUG,
                    };
                    if let Ok(c_msg) = CString::new(format!("{}", record.args())) {
                        unsafe {
                            libc::syslog(prio, c"%s".as_ptr(), c_msg.as_ptr());
                        }
                    }
                }
                #[cfg(not(target_family = "unix"))]
                {
                    let _ = std::io::stderr().write_all(msg.as_bytes());
                }
            }
        }
    }

    fn flush(&self) {
        match &self.dest {
            LogDestination::Stderr => {
                let _ = std::io::stderr().flush();
            }
            LogDestination::File(file_mutex) => {
                if let Ok(mut f) = file_mutex.lock() {
                    let _ = f.flush();
                }
            }
            LogDestination::Syslog => {}
        }
    }
}
