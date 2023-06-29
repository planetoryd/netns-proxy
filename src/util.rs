use std::env;
use std::fs::File;
use std::os::fd::FromRawFd;
use std::path::PathBuf;

use anyhow::Ok;
use anyhow::Result;
use nix::sys::signal::kill;
use nix::sys::signal::Signal;
use nix::sys::signal::Signal::SIGTERM;
use nix::unistd::Gid;
use nix::unistd::Pid;
use nix::unistd::Uid;
use procfs::process::Process;

pub fn convert_strings_to_strs(strings: &Vec<String>) -> Vec<&str> {
    strings.iter().map(|s| s.as_str()).collect()
}

pub fn get_non_priv_user(
    uid: Option<String>,
    gid: Option<String>,
    uid2: Option<Uid>,
    gid2: Option<Gid>,
) -> Result<(u32, u32)> {
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
    } else if uid2.is_some() && gid2.is_some() {
        r_gi = gid2.unwrap().as_raw();
        r_ui = uid2.unwrap().as_raw();
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

    if r_ui == 0 || r_gi == 0 {
        // when straceing
        Ok((1000, 1000))
    } else {
        Ok((r_ui, r_gi))
    }
}

#[test]
fn t_pidfd() -> Result<()> {
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
use log::info;
use sysinfo::PidExt;
use sysinfo::ProcessExt;
use sysinfo::SystemExt;

#[cfg(test)]
use std::println as info;

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

use std::collections::HashMap;

pub fn substitute_argv<'a>(n_info: &'a NetnsInfo, argv: &mut Vec<String>) {
    let mut sub_map: HashMap<String, &String> = HashMap::new();
    sub_map.insert(format!("${}", "subnet_veth"), &n_info.subnet_veth);
    sub_map.insert(format!("${}", "subnet6_veth"), &n_info.subnet6_veth);
    sub_map.insert(format!("${}", "ip_vh"), &n_info.ip_vh);
    sub_map.insert(format!("${}", "ip6_vh"), &n_info.ip6_vh);
    sub_map.insert(format!("${}", "ip_vn"), &n_info.ip_vn);
    sub_map.insert(format!("${}", "ip6_vn"), &n_info.ip6_vn);

    for s in argv.iter_mut() {
        let mut s_ = s.to_owned();
        for (key, value) in &sub_map {
            s_ = s_.replace(key, value);
        }
        *s = s_;
    }
}

use crate::NetnsInfo;
#[test]
fn test_substitute_argv() {
    let n_info = NetnsInfo {
        base_name: "x".to_owned(),
        subnet_veth: "eth0".to_string(),
        subnet6_veth: "eth1".to_string(),
        ip_vh: "192.168.0.1".to_string(),
        ip6_vh: "2001:db8::1".to_string(),
        ip_vn: "192.168.0.2".to_string(),
        ip6_vn: "2001:db8::2".to_string(),
        veth_base_name: "ss".to_owned(),
        id: 2,
        tun_ip: None,
        link_base_name: None,
    };

    let mut argv = vec![
        "ping".to_string(),
        "-c".to_string(),
        "1".to_string(),
        "$ip_vnxx".to_string(),
    ];

    substitute_argv(&n_info, &mut argv);

    assert_eq!(
        argv,
        vec![
            "ping".to_string(),
            "-c".to_string(),
            "1".to_string(),
            "192.168.0.2xx".to_string(),
        ]
    );
}

use sysinfo::System;

pub fn kill_suspected() -> Result<()> {
    let s = System::new_all();
    for (pid, process) in s.processes() {
        // kill by saved pids
        // or by matching commandlines
        let c = process.cmd();
        if c.into_iter().any(|x| x.contains("tun2socks"))
            || c.into_iter().any(|x| x.contains("gost"))
            || c.into_iter().any(|x| x.contains("dnsproxy"))
        {
            println!("killed {pid} {}", c[0]);
            kill(nix::unistd::Pid::from_raw(pid.as_u32() as i32), SIGTERM)?;
        }
    }
    Ok(())
}

// first four args must be Some()
use std::path::Path;

pub fn open_wo_cloexec(path: &Path) -> File {
    use nix::fcntl::{open, OFlag};
    use nix::sys::stat::Mode;
    let fd = open(path, OFlag::O_RDONLY, Mode::empty()).unwrap();
    unsafe { File::from_raw_fd(fd) }
}
