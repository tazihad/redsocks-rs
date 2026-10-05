use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use crate::config::types::BaseConfig;

pub fn apply_base_config(config: &BaseConfig) -> io::Result<()> {
    // 1. Set RLIMIT_NOFILE
    if config.rlimit_nofile > 0 {
        #[cfg(target_family = "unix")]
        {
            let rlim = libc::rlimit {
                rlim_cur: config.rlimit_nofile as libc::rlim_t,
                rlim_max: config.rlimit_nofile as libc::rlim_t,
            };
            let ret = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) };
            if ret != 0 {
                log::warn!(
                    "Failed to set rlimit_nofile to {}: errno {}",
                    config.rlimit_nofile,
                    std::io::Error::last_os_error()
                );
            } else {
                log::info!("rlimit_nofile set to {}", config.rlimit_nofile);
            }
        }
    }

    // 2. Chroot
    if let Some(chroot_dir) = &config.chroot {
        #[cfg(target_family = "unix")]
        {
            let c_dir = CString::new(chroot_dir.as_str())?;
            let ret = unsafe { libc::chroot(c_dir.as_ptr()) };
            if ret != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "Failed to chroot to '{}': {}",
                        chroot_dir,
                        io::Error::last_os_error()
                    ),
                ));
            }
            // chdir to / after chroot
            let root = CString::new("/")?;
            unsafe { libc::chdir(root.as_ptr()) };
            log::info!("chroot to '{}' completed", chroot_dir);
        }
    }

    // 3. Drop group privileges
    if let Some(group_name) = &config.group {
        #[cfg(target_family = "unix")]
        {
            let gid = lookup_gid(group_name)?;
            let ret = unsafe { libc::setgid(gid) };
            if ret != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "Failed to setgid to group '{}' (gid {}): {}",
                        group_name,
                        gid,
                        io::Error::last_os_error()
                    ),
                ));
            }
            log::info!("Switched to group '{}' (gid {})", group_name, gid);
        }
    }

    // 4. Drop user privileges
    if let Some(user_name) = &config.user {
        #[cfg(target_family = "unix")]
        {
            let uid = lookup_uid(user_name)?;
            let ret = unsafe { libc::setuid(uid) };
            if ret != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "Failed to setuid to user '{}' (uid {}): {}",
                        user_name,
                        uid,
                        io::Error::last_os_error()
                    ),
                ));
            }
            log::info!("Switched to user '{}' (uid {})", user_name, uid);
        }
    }

    Ok(())
}

pub fn daemonize() -> io::Result<()> {
    #[cfg(target_family = "unix")]
    {
        unsafe {
            let pid = libc::fork();
            if pid < 0 {
                return Err(io::Error::last_os_error());
            }
            if pid > 0 {
                // Exit parent process
                libc::_exit(0);
            }

            // Create new session
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }

            // Second fork to prevent acquiring controlling terminal
            let pid2 = libc::fork();
            if pid2 < 0 {
                return Err(io::Error::last_os_error());
            }
            if pid2 > 0 {
                libc::_exit(0);
            }

            // Change working directory to root
            libc::chdir(c"/".as_ptr());

            // Set file mode creation mask
            libc::umask(0);

            // Reopen standard descriptors to /dev/null
            let dev_null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
            if dev_null >= 0 {
                libc::dup2(dev_null, libc::STDIN_FILENO);
                libc::dup2(dev_null, libc::STDOUT_FILENO);
                libc::dup2(dev_null, libc::STDERR_FILENO);
                if dev_null > libc::STDERR_FILENO {
                    libc::close(dev_null);
                }
            }
        }
    }
    Ok(())
}

pub fn write_pid_file<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let pid = std::process::id();
    let mut file = File::create(path)?;
    writeln!(file, "{}", pid)?;
    file.flush()?;
    Ok(())
}

#[cfg(target_family = "unix")]
fn lookup_uid(username: &str) -> io::Result<libc::uid_t> {
    if let Ok(uid) = username.parse::<libc::uid_t>() {
        return Ok(uid);
    }
    let c_name = CString::new(username)?;
    unsafe {
        let pwd = libc::getpwnam(c_name.as_ptr());
        if pwd.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("User '{}' not found", username),
            ));
        }
        Ok((*pwd).pw_uid)
    }
}

#[cfg(target_family = "unix")]
fn lookup_gid(groupname: &str) -> io::Result<libc::gid_t> {
    if let Ok(gid) = groupname.parse::<libc::gid_t>() {
        return Ok(gid);
    }
    let c_name = CString::new(groupname)?;
    unsafe {
        let grp = libc::getgrnam(c_name.as_ptr());
        if grp.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Group '{}' not found", groupname),
            ));
        }
        Ok((*grp).gr_gid)
    }
}
