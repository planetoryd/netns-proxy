use std::env;
use std::path::PathBuf;

use anyhow::Ok;
use anyhow::Result;
use nix::sys::signal::kill;
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use procfs::process::Process;

pub fn convert_strings_to_strs(strings: &Vec<String>) -> Vec<&str> {
    strings.iter().map(|s| s.as_str()).collect()
}

pub fn get_non_priv_user(uid: Option<String>, gid: Option<String>) -> Result<(u32, u32)> {
    let r_ui: u32;
    let r_gi: u32;
    if let core::result::Result::Ok(log_name) = env::var("SUDO_USER") {
        // run from sudo
        let log_user = users::get_user_by_name(&log_name).unwrap();
        r_ui = log_user.uid();
        r_gi = log_user.primary_group_id();
    } else if uid.is_some() && gid.is_some() {
        // supplied
        r_gi = gid.unwrap().parse()?;
        r_ui = uid.unwrap().parse()?;
    } else {
        // as child process of some non-root
        let parent_pid = nix::unistd::getppid();
        let parent_process = match procfs::process::Process::new(parent_pid.into()) {
            core::result::Result::Ok(process) => process,
            Err(_) => panic!("cannot access parent process"),
        };
        r_ui = parent_process.status()?.euid;
        r_gi = parent_process.status()?.egid;
    }

    Ok((r_ui, r_gi))
}

#[test]
fn t_pidfd() -> Result<()> {
    use pidfd::PidFuture;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let f = unsafe { pidfd::PidFd::open(853481, 0)?.into_future() };
            println!("opened");
            f.await;
            println!("finished");
            Ok(())
        })
}

#[test]
fn get_all_child_pids() -> Result<()> {
    use procfs::process::Process;

    let su = Process::new(942129)?;
    let mt = su.task_main_thread()?;
    dbg!(mt.children()?);
    let chi: Vec<u32> = su
        .tasks()?
        .filter_map(|t| t.ok().and_then(|x| x.children().ok()))
        .flatten()
        .collect();

    dbg!(chi);
    Ok(())
}

pub fn kill_children(pid: i32) -> Result<()> {
    let su = Process::new(pid)?;
    let chi: Vec<u32> = su
        .tasks()?
        .filter_map(|t| t.ok().and_then(|x| x.children().ok()))
        .flatten()
        .collect();

    for c in chi {
        kill(Pid::from_raw(c.try_into()?), Signal::SIGTERM).map_err(anyhow::Error::from)?;
    }

    Ok(())
}

#[cfg(not(test))]
use log::{info, warn};

#[cfg(test)]
use std::{println as info, println as warn};

pub fn flatpak_perms_checkup(list: Vec<String>) -> Result<()> {
    let basedirs = xdg::BaseDirectories::with_prefix("flatpak")?;
    info!("trying to adapt flatpak app permissions");
    for appid in list {
        let mut sub = PathBuf::from("overrides");
        sub.push(appid);
        let p = basedirs.get_data_file(&sub);
        if p.exists() {
            let mut conf = ini::Ini::load_from_file(p.as_path())?;
            let k = conf.get_from(Some("Context"), "shared");
            if k.is_some() {
                if k.unwrap().contains("!network") {
                    info!("{} found. it has correct config", p.to_string_lossy());
                } else {
                    let o = k.unwrap().to_owned();
                    let v = o + ";!network";
                    conf.set_to(Some("Context"), "shared".to_owned(), v);
                    conf.write_to_file(p.as_path())?;
                    info!("{} written", p.to_string_lossy());
                }
            } else {
                conf.set_to(Some("Context"), "shared".to_owned(), "!network".to_owned());
                conf.write_to_file(p.as_path())?;
                info!("{} written", p.to_string_lossy());
            }
        } else {
            // create a new file for it
            let mut conf = ini::Ini::new();
            conf.set_to(Some("Context"), "shared".to_owned(), "!network".to_owned());
            info!("{} written. new file", p.to_string_lossy());
            conf.write_to_file(p.as_path())?;
        }
    }
    Ok(())
}

#[test]
fn test_flatpakperm() {
    flatpak_perms_checkup(
        [
            "org.mozilla.firefox".to_owned(),
            "im.fluffychat.Fluffychat".to_owned(),
        ]
        .to_vec(),
    )
    .unwrap();
}
