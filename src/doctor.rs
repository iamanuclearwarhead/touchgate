use std::io::IsTerminal;
use std::path::Path;

use anyhow::Result;
use touchgate_agents::Agent;

use crate::install::agent_has_hook;
use crate::load_policy;
use crate::locations::{Locations, home, user_policy};

enum Level {
    Ok,
    Info,
    Warn,
    Fail,
}

struct Report {
    color: bool,
    fails: usize,
    warns: usize,
}

impl Report {
    fn line(&mut self, level: Level, what: &str, msg: impl AsRef<str>) {
        let (tag, code) = match level {
            Level::Ok => ("ok", "32"),
            Level::Info => ("--", "2"),
            Level::Warn => {
                self.warns += 1;
                ("warn", "33")
            }
            Level::Fail => {
                self.fails += 1;
                ("fail", "31")
            }
        };
        let tag = if self.color { format!("\x1b[{code}m{tag:<4}\x1b[0m") } else { format!("{tag:<4}") };
        println!("{tag}  {what:<10} {}", msg.as_ref());
    }
}

pub fn run() -> Result<()> {
    let locs = Locations::system();
    let mut r = Report {
        color: std::io::stdout().is_terminal(),
        fails: 0,
        warns: 0,
    };

    let v = touchgate_auth::platform();
    match v.probe() {
        Ok(d) if d.enrolled.is_empty() => r.line(Level::Fail, "reader", format!("{} found but no fingerprints enrolled", d.name)),
        Ok(d) => r.line(Level::Ok, "reader", format!("{} via {}, {} enrolled", d.name, v.backend(), d.enrolled.len())),
        Err(e) => r.line(Level::Fail, "reader", e),
    }

    if locs.policy.exists() {
        if writable(&locs.policy) {
            r.line(Level::Fail, "policy", format!("{} is writable by you, so an agent can edit it", locs.policy.display()));
        } else {
            r.line(Level::Ok, "policy", locs.policy.display().to_string());
        }
    } else {
        r.line(Level::Warn, "policy", "no system policy, built-in rules only. run `sudo touchgate install`");
    }
    match load_policy() {
        Ok(p) => r.line(Level::Ok, "rules", format!("{} rules load fine, {}s to touch", p.layers.iter().map(|l| l.rules.len()).sum::<usize>(), p.timeout_secs)),
        Err(e) => r.line(Level::Fail, "rules", format!("{e:#}, every hook call will be denied until this is fixed")),
    }
    if user_policy().exists() {
        r.line(Level::Info, "rules", format!("user rules from {} (can only tighten)", user_policy().display()));
    }

    if locs.bin.exists() {
        if writable(&locs.bin) {
            r.line(Level::Fail, "binary", format!("{} is writable by you", locs.bin.display()));
        } else {
            r.line(Level::Ok, "binary", locs.bin.display().to_string());
        }
    } else {
        r.line(Level::Warn, "binary", format!("{} missing, hooks point there", locs.bin.display()));
    }

    let mut any = false;
    for agent in Agent::ALL {
        let cli = match agent {
            Agent::Claude => "claude",
            Agent::Codex => "codex",
            Agent::Gemini => "gemini",
        };
        let installed = on_path(cli);
        let hooked = agent_has_hook(&locs, agent);
        let cfg = locs.agent_config(agent);
        match (installed, hooked) {
            (_, true) if writable(cfg) => {
                r.line(Level::Fail, agent.name(), format!("{} is writable by you", cfg.display()))
            }
            (_, true) => {
                any = true;
                r.line(Level::Ok, agent.name(), format!("managed hook in {}", cfg.display()))
            }
            (true, false) => r.line(Level::Fail, agent.name(), format!("{} is installed but not gated", agent.display())),
            (false, false) => r.line(Level::Info, agent.name(), "not installed"),
        }
    }
    if !any {
        r.line(Level::Warn, "hooks", "no agent is gated yet");
    }

    if std::env::var_os("GEMINI_CLI_SYSTEM_SETTINGS_PATH").is_some() {
        r.line(Level::Fail, "gemini", "GEMINI_CLI_SYSTEM_SETTINGS_PATH is set, gemini ignores the managed hook");
    }
    let gs = home().join(".gemini/settings.json");
    if let Ok(t) = std::fs::read_to_string(&gs) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) {
            let disabled = v["hooksConfig"]["disabled"].as_array().is_some_and(|a| a.iter().any(|x| x.as_str().is_some_and(|s| s.contains("touchgate"))));
            if disabled {
                r.line(Level::Fail, "gemini", format!("{} disables the touchgate hook", gs.display()));
            }
        }
    }

    #[cfg(unix)]
    {
        let nopass = std::process::Command::new("sudo")
            .args(["-k", "-n", "true"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if nopass {
            r.line(Level::Warn, "sudo", "sudo needs no password (NOPASSWD), an agent script could use it to undo touchgate");
        } else {
            r.line(Level::Ok, "sudo", "needs a password");
        }
    }

    println!();
    if r.fails == 0 && r.warns == 0 {
        println!("all good");
    } else {
        println!("{} problems, {} warnings", r.fails, r.warns);
    }
    Ok(())
}

fn on_path(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|d| {
        d.join(name).is_file() || (cfg!(windows) && (d.join(format!("{name}.exe")).is_file() || d.join(format!("{name}.cmd")).is_file()))
    })
}

#[cfg(unix)]
fn writable(p: &Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = CString::new(p.as_os_str().as_bytes()) else {
        return false;
    };
    let file = unsafe { libc::access(c.as_ptr(), libc::W_OK) } == 0;
    let dir = p
        .parent()
        .and_then(|d| CString::new(d.as_os_str().as_bytes()).ok())
        .is_some_and(|d| unsafe { libc::access(d.as_ptr(), libc::W_OK) } == 0);
    file || dir
}

#[cfg(not(unix))]
fn writable(p: &Path) -> bool {
    std::fs::OpenOptions::new().append(true).open(p).is_ok()
}
