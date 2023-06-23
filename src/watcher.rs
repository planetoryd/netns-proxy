// watcher interfaces with the OS, by watching for apps to proxify.

// through any way, the client finds a new netns to proxify
// send command through the channel
// the server manipulates the netns as commanded
// specify netns by fd, or pid

// Warning: depending on the security model, the watching may be vulnerable in security
// one may trigger the watcher by faking that a new flatpak app is launched.
// however, starting a flatpak does not need superuser privileges, nor does faking a new instance
// the difference is that the user intends to do the former, but not the latter.
// It is recommended to sandbox untrusted apps, so the faking can not be done.
// TODO: validate what is being started by checking GetAppState

use anyhow::{Ok, Result};
use futures::StreamExt;
use inotify::{EventMask, WatchDescriptor, WatchMask};
use nix::sched::CloneFlags;
use serde::{Deserialize, Serialize};
use std::{
    cell::Ref,
    collections::{HashMap, HashSet},
    ffi::OsString,
    os::fd::AsRawFd,
    path::Path,
    path::PathBuf,
    result::Result as stdRes,
    sync::Arc,
};
use tokio::{io::AsyncReadExt, sync::RwLock, task::JoinSet};
use zbus::{dbus_interface, dbus_proxy, Connection};

use crate::{
    configurer::{self, get_self_netns_inode, ConfigRes, NetnsInfo, NetnspState},
    get_non_priv_user,
};
use ini;

struct NetnspDbus;

#[dbus_interface(name = "app.netnsp")]
impl NetnspDbus {
    fn transform_netns_by_pid(&self, pid: i32) {}
    fn transform_netns_by_path(&self, path: String) {}
}

// Portal backend APIs provided by flatpak.
// It also monitors non-flatpak apps

#[dbus_proxy(
    interface = "org.freedesktop.impl.portal.Background",
    default_service = "org.freedesktop.impl.portal.desktop.kde",
    default_path = "/org/freedesktop/portal/desktop"
)]
pub trait KDEPortal {
    #[dbus_proxy(signal)]
    fn RunningApplicationsChanged(&self) -> zbus::Result<()>;
    fn GetAppState(&self) -> zbus::Result<HashMap<String, zbus::zvariant::OwnedValue>>;
}

// track active profiles by pid

pub type ActiveProfiles = HashMap<i32, ProfileState>;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct ProfileState {
    // root-most process that is to be in the netns
    pub pid: i32,
    // eg. com.github.tchx84.Flatseal
    pub flatpak_app_id: String,
    // Netns Profile in effect
    pub profile: String,
    // Profile in demand, as configured
    pub default_pofile: String,
    // if configured
    pub net: Option<NetnsInfo>,
}

pub struct WatcherState {
    netnsp: NetnspState,
    daemons: RwLock<JoinSet<(String, Result<()>)>>,
    configurer: configurer::Configurer,
}

impl WatcherState {
    pub async fn create(
        configurer: configurer::Configurer,
        state: NetnspState
    ) -> Result<WatcherState> {
        log::info!("watcher started");

        let mut n = WatcherState {
            netnsp: state,
            daemons: RwLock::new(JoinSet::new()),
            configurer,
        };
        n.auth().await?;

        Ok(n)
    }
    pub async fn auth(&mut self) -> Result<()> {
        // If it is the first run, do nothing and record netns inode
        // If there is recorded inode, do auth.

        if self.netnsp.res.root_inode > 0 {
            let si = get_self_netns_inode()?;
            if si != self.netnsp.res.root_inode {
                log::error!("Access denied. This run is in a netns different from what is recorded in the netnsp.json");
                std::process::exit(1);
            } else {
                log::info!("Netns inodes match");
            }
        } else {
            // if the json does not contain inode (which is malformed), serde should error
            // therefore, here it is initalizing.
            self.netnsp.res.root_inode = crate::get_pid1_netns_inode().await?;
        }

        Ok(())
    }
    pub async fn start(self) -> Result<()> {
        // start all watching coroutines
        let arc = Arc::new(self);
        let mut takeit = arc.daemons.write().await;
        let arc1 = arc.clone();
        (*takeit).spawn(async move {
            let ownit = arc1;
            let res = fs_watcher(&ownit).await;
            ("fs_watcher".to_owned(), res)
        });

        Ok(())
    }
    pub async fn apply_profile_by_pid(&self, pid: i32, base_name: &str) -> Result<()> {
        let ex = self.netnsp.res.flatpak.as_ref().unwrap().get(&pid);
        if ex.is_some() {
            anyhow::bail!("unexpected repeated profile application")
        }
        let process = procfs::process::Process::new(pid)?;
        let o: OsString = OsString::from("net");
        let nss = process.namespaces()?;
        let proc_ns = nss
            .get(&o)
            .ok_or(anyhow::anyhow!("ns/net not found for given pid"))?;
        let r = std::fs::File::open(&proc_ns.path)?;
        configurer::config_pre_enter_ns(base_name, configurer::veth_from_base, &self.configurer, r.as_raw_fd())
            .await?;
        // let inames = ;
        Ok(())
    }
}

pub struct DBusClient<'a> {
    pub kde: KDEPortalProxy<'a>,
}

impl<'a> DBusClient<'a> {
    pub async fn new() -> Result<DBusClient<'a>> {
        let conn = Connection::session().await?;
        let proxy = KDEPortalProxy::new(&conn).await?;

        Ok(DBusClient { kde: proxy })
    }
    pub async fn watcher(self) -> Result<()> {
        let mut r = self.kde.receive_RunningApplicationsChanged().await?;
        loop {
            r.next().await;
            log::debug!("RunningApplicationsChanged");
            // find the newly started app. it could be a flatpak, or anything.
        }
        Ok(())
    }
}

use tokio::fs;

async fn read_pid_file_from_dir(dir_path: &Path) -> Result<Option<String>> {
    let mut pid_file_contents: Option<String> = None;
    let mut entries = fs::read_dir(dir_path).await?;
    while let Some(entry) = entries.next_entry().await? {
        if let Some(file_name) = entry.file_name().to_str() {
            if file_name.contains("pid") {
                let file_path = entry.path();
                pid_file_contents = Some(fs::read_to_string(file_path).await?);
                break;
            }
        }
    }
    Ok(pid_file_contents)
}

async fn process_event<'a>(
    ev: inotify::Event<std::ffi::OsString>,
    flatpak_dir: &PathBuf,
    watcher: &WatcherState,
    once_set: &mut HashSet<u32>,
) -> Result<()> {
    // it may be an instance dir, or elses
    if let Some(fname) = ev.name.clone() {
        let fname = fname.to_string_lossy().into_owned();
        if ev
            .mask
            .intersects(EventMask::ISDIR | EventMask::CLOSE_NOWRITE)
        {
            let instance = fname.parse::<u32>();

            if let stdRes::Ok(iid) = instance {
                if !once_set.contains(&iid) {
                    // do this once per instance start
                    once_set.insert(iid);
                    let mut instance_dir = flatpak_dir.clone();
                    instance_dir.push(fname.clone());

                    // we have only three files at this point
                    // "bwrapinfo.json" - empty
                    // "info" - filled
                    // ".ref" - empty

                    let mut info = instance_dir.clone();
                    info.push("info");

                    let mut info_file = tokio::fs::File::open(info).await?;
                    let mut instnace_info_str = String::new();
                    info_file.read_to_string(&mut instnace_info_str).await?;

                    log::debug!("flatpak instance {} detected", iid);

                    let c = ini::Ini::load_from_str(&instnace_info_str).unwrap();
                    // if any of the following ops fail, we'll just error and give up
                    let s_app = c
                        .section(Some("Application"))
                        .ok_or(anyhow::anyhow!("flatpak section missing"))?;
                    let flatpak_id = s_app
                        .get("name")
                        .ok_or(anyhow::anyhow!("unexpected flatpak data. name missing"))?;

                    let profile_or_not = watcher.netnsp.conf.flatpak.get(flatpak_id);

                    if let Some(profile_name) = profile_or_not {
                        let pid_f = read_pid_file_from_dir(&instance_dir).await?;
                        if pid_f.is_none() {
                            log::error!("unexpected, pid_f is none, {:?}", &ev);
                        } else {
                            let pid_f = pid_f.unwrap();
                            log::debug!("flatpak app with pid {}", pid_f);
                            let proc = procfs::process::Process::new(pid_f.parse()?)?;
                            // not sure about the task part. lets get the main thread then
                            let maint = proc.task_main_thread()?;
                            let children = maint.children()?;
                            if children.len() != 1 {
                                log::info!("unexpected number of threads, {:?}", proc);
                            }
                            let the_child_pid = children[0]; // pid of the process, in unshared netns
                            watcher
                                .apply_profile_by_pid(the_child_pid as i32, flatpak_id)
                                .await?;
                        }
                    } else {
                        log::info!(
                            "flatpak app {} has no associated profile, skipping",
                            flatpak_id
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

//   |-fish(632634)---bwrap(706664)---bwrap(706674)---com.github.tchx(706675)-+-{com.github+
//            |               |                 |                                                                        |-{com.github+
//            |               |                 |                                                                        |-{com.github+
//            |               |                 |                                                                        |-{com.github+
//            |               |                 |                                                                        |-{com.github+
//            |               |                 |                                                                        |-{com.github+
//            |               |                 |                                                                        |-{com.github+
//            |               |                 |                                                                        |-{com.github+
//            |               |                 |                                                                        |-{com.github+
//            |               |                 |                                                                        |-{com.github+
//            |               |                 |                                                                        |-{com.github+
//            |               |                 |                                                                        |-{com.github+
//            |               |                 |                                                                        |-{com.github+
//            |               |                 |                                                                        |-{com.github+
//            |               |                 |                                                                        |-{com.github+
//            |               |                 |                                                                        |-{com.github+
//            |               |                 |                                                                        |-{com.github+
//            |               |                 |                                                                        |-{com.github+
//            |               |                 |                                                                        |-{com.github+
//            |               |                 |                                                                        |-{com.github+
//            |               |                 |                |                                                        |-{com.github+
//                       detected pid
//                      NSpid:  706664,  NSpid:  706674  1,   NSpid:  706675  2
// /proc/706664/ns/net -> 'net:[4026531840]'
// /proc/706674/ns/net -> 'net:[4026534547]'
// /proc/706675/ns/net -> 'net:[4026534547]'
// /proc/self/ns/net -> 'net:[4026531840]' (my shell in default netns)
// ip netns identify 706674
// (blank)
// apparently we should take the immediate child
// ~> nsenter --target 706674  --net
// nsenter: reassociate to namespace 'ns/net' failed: Operation not permitted
// sudo nsenter --target 706674  --net
// # ip l
// 1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
//     link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
// ───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
//        │ File: /proc/706674/status
// ───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
//    1   │ Name:   bwrap
// ───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
//        │ File: /proc/706675/status
// ───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
//    1   │ Name:   com.github.tchx
//    2   │ Umask:  0022
//    3   │ State:  S (sleeping)
// GetAppState, 'com.github.tchx84.Flatseal': <uint32 1>,
// com.github.tchx84.Flatseal == its flatpak app id != process name
// non-flatpak names from GetAppState are derived in an unknown way
// but, `info` file links the flatpak id and the process

// for flatpak and more
pub async fn fs_watcher<'a>(watcher: &WatcherState) -> Result<()> {
    let (uid, _) = get_non_priv_user(None, None)?;
    let flatpak_dir = PathBuf::from(format!("/run/user/{}/.flatpak/", uid));
    let mut inoti = inotify::Inotify::init()?;
    inoti
        .watches()
        .add(&flatpak_dir, WatchMask::CLOSE_NOWRITE)?;
    // sometimes directories are opened without CREATE. no idea
    // CLOSE_NOWRITE seems to be the best

    // let mut wdmap: HashMap<WatchDescriptor, WdInfo> = HashMap::new(); // map wd to instance path
    let mut once_set: HashSet<u32> = HashSet::new(); // whether an instance has been examined. prevent looping.

    let mut buf = [0; 1024];
    let mut stream = inoti.into_event_stream(&mut buf)?;
    while let Some(event_or_error) = stream.next().await {
        // event that is triggered for each `flatpak run` (each run creates a new instance)
        // dir name is instance_id.
        // event: Event { wd: WatchDescriptor { id: 1, fd: (Weak) }, mask: CREATE | ISDIR, cookie: 0, name: Some("2005139353") }
        // pid file -> bwrap --args 41 com.github.tchx84.Flatseal
        match event_or_error {
            stdRes::Ok(ev) => {
                println!("event: {:?}", &ev);
                let ino = stream.into_inotify();
                match process_event(ev, &flatpak_dir, watcher, &mut once_set).await {
                    anyhow::Result::Ok(_) => {}
                    Err(e) => {
                        log::error!("fs watcher, {:?}", e);
                    }
                }
                inoti = ino;
                stream = inoti.into_event_stream(&mut buf)?;
            }
            Err(e) => {
                log::error!("fs watcher, {:?}", e);
            }
        }
    }

    Ok(())
}

#[test]
fn test_parse_flatpak_info() {
    let s = "[Application]
name=com.github.tchx84.Flatseal
runtime=runtime/org.gnome.Platform/x86_64/44

[Instance]
instance-id=742735114
";
    let c = ini::Ini::load_from_str(s).unwrap();
    dbg!(&c);
    let s_app = c.section(Some("Application"));
    let n = s_app.unwrap().get("name");
    dbg!(s_app, n);
}
