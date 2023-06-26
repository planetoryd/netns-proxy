use std::env;

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
