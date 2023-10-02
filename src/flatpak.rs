use amplify::{From, Wrapper};
use anyhow::Ok;
use log::info;

use std::{path::PathBuf, str::FromStr};

use anyhow::Result;

/// adapt the flatpak settings of given list
pub fn flatpak_perms_checkup(list: Vec<&FlatpakID>) -> Result<()> {
    let basedirs = xdg::BaseDirectories::with_prefix("flatpak")?;
    info!("Trying to adapt flatpak app permissions. \n This turns 'Network' off which causes flatpak to use isolated network namespaces. \n This must be done early to prevent accidental unsandboxed use of network");
    for appid in list {
        let mut sub = PathBuf::from("overrides");
        sub.push(&appid.0);
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
            conf.write_to_file(p.as_path())?;
            info!("{} written. New file", p.to_string_lossy());
        }
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq)]
pub struct FlatpakID(String);

impl FromStr for FlatpakID {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

#[test]
fn test_flatpakperm() -> Result<()> {
    flatpak_perms_checkup(
        [
            &"org.mozilla.firefox".parse()?,
            &"im.fluffychat.Fluffychat".parse()?,
        ]
        .to_vec(),
    )
    .unwrap();
    Ok(())
}
