//! Groups the executables that belong to one app, so helpers and extensions
//! count toward the app people recognise.

use std::path::{Component, Path, PathBuf};

/// The group an executable belongs to, as `(group_key, group_name)`.
///
/// - Inside a bundle, the outermost `.app` or `.appex`: every helper of
///   `/Applications/Claude.app` groups under `Claude`.
/// - `name:<process>` keys group by themselves.
/// - Legacy `pid:<pid>:<start>` keys group by process name.
/// - Anything else is its own group.
pub fn group_of(app_key: &str, display_name: &str) -> (String, String) {
    if app_key.starts_with("pid:") {
        return name_group(display_name);
    }
    if app_key.starts_with("name:") {
        return (app_key.to_string(), display_name.to_string());
    }
    if let Some(group) = bundle_group(app_key) {
        return group;
    }
    (app_key.to_string(), display_name.to_string())
}

fn name_group(name: &str) -> (String, String) {
    if name.is_empty() {
        return ("name:unknown".into(), "unknown".into());
    }
    (format!("name:{name}"), name.to_string())
}

fn bundle_group(path: &str) -> Option<(String, String)> {
    let mut prefix = PathBuf::new();
    for component in Path::new(path).components() {
        prefix.push(component);
        let Component::Normal(part) = component else { continue };
        let part = part.to_str()?;
        for ext in [".app", ".appex"] {
            if let Some(stem) = part.strip_suffix(ext) {
                if !stem.is_empty() {
                    return Some((prefix.to_str()?.to_string(), stem.to_string()));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers_group_under_the_outermost_app() {
        let helper = "/Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper";
        assert_eq!(
            group_of(helper, "Claude Helper"),
            ("/Applications/Claude.app".into(), "Claude".into())
        );
        let main = "/Applications/Claude.app/Contents/MacOS/Claude";
        assert_eq!(group_of(main, "Claude").0, "/Applications/Claude.app");
    }

    #[test]
    fn an_extension_inside_an_app_groups_with_the_app() {
        let ext = "/System/Applications/News.app/Contents/PlugIns/NewsToday2.appex/Contents/MacOS/NewsToday2";
        assert_eq!(group_of(ext, "NewsToday2").1, "News");
        let lone = "/System/Library/ExtensionKit/Extensions/Wallpaper.appex/Contents/MacOS/Wallpaper";
        assert_eq!(group_of(lone, "Wallpaper").1, "Wallpaper");
    }

    #[test]
    fn plain_binaries_and_names_are_their_own_group() {
        assert_eq!(
            group_of("/usr/bin/curl", "curl"),
            ("/usr/bin/curl".into(), "curl".into())
        );
        assert_eq!(group_of("name:curl", "curl").0, "name:curl");
        assert_eq!(group_of("pid:42:1700000000", "curl").0, "name:curl");
    }
}
