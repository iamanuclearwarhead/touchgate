use std::path::{Component, Path, PathBuf};

pub fn expand_home(s: &str, home: &Path) -> String {
    if s == "~" {
        return slashes(&home.to_string_lossy());
    }
    if let Some(rest) = s.strip_prefix("~/").or_else(|| s.strip_prefix("~\\")) {
        return format!("{}/{}", slashes(&home.to_string_lossy()).trim_end_matches('/'), rest);
    }
    if let Some(rest) = s.strip_prefix("$HOME/").or_else(|| s.strip_prefix("${HOME}/")) {
        return format!("{}/{}", slashes(&home.to_string_lossy()).trim_end_matches('/'), rest);
    }
    s.to_string()
}

pub fn candidates(raw: &str, cwd: Option<&Path>, home: &Path) -> Vec<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Vec::new();
    }
    let expanded = expand_home(raw, home);
    let p = PathBuf::from(&expanded);
    let abs = if p.is_absolute() || expanded.starts_with('/') {
        p
    } else if let Some(cwd) = cwd {
        cwd.join(p)
    } else {
        p
    };
    let lexical = normalize(&abs);
    let mut out = vec![slashes(&lexical.to_string_lossy())];
    if let Ok(real) = std::fs::canonicalize(&lexical) {
        let r = slashes(&real.to_string_lossy());
        let r = r.strip_prefix("//?/").map(str::to_string).unwrap_or(r);
        if !out.contains(&r) {
            out.push(r);
        }
    }
    out
}

fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

pub fn slashes(s: &str) -> String {
    s.replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_and_normalizes() {
        let home = Path::new("/home/u");
        assert_eq!(candidates("~/.ssh/../.ssh/id_rsa", None, home)[0], "/home/u/.ssh/id_rsa");
        assert_eq!(candidates(".env", Some(Path::new("/w/p")), home)[0], "/w/p/.env");
        assert_eq!(candidates("$HOME/.aws/credentials", None, home)[0], "/home/u/.aws/credentials");
    }
}
