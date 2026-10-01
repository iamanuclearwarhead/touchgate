mod doctor;
mod install;
mod locations;

use std::fs::{self, OpenOptions};
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use touchgate_agents::{Agent, Outcome, fail_closed, parse, respond};
use touchgate_auth::{AuthResult, Prompt, Verifier};
use touchgate_core::{Action, Decision, Policy, ToolKind, Verdict};

use crate::locations::{Locations, audit_log, home, user_policy};

#[derive(Parser)]
#[command(name = "touchgate", version, about = "fingerprint approval for risky ai agent actions")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    #[command(about = "run as an agent hook, reads the tool call on stdin")]
    Hook {
        #[arg(long)]
        agent: Agent,
    },
    #[command(about = "show what touchgate would do with a command or file")]
    Test {
        #[arg(long, conflicts_with_all = ["write", "fetch", "mcp"])]
        read: Option<String>,
        #[arg(long, conflicts_with_all = ["fetch", "mcp"])]
        write: Option<String>,
        #[arg(long, conflicts_with = "mcp")]
        fetch: Option<String>,
        #[arg(long)]
        mcp: Option<String>,
        #[arg(long)]
        cwd: Option<PathBuf>,
        #[arg(long, help = "actually ask for a fingerprint when the verdict is touch")]
        verify: bool,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    #[command(about = "install managed hooks for your agents (needs sudo or admin)")]
    Install {
        #[arg(long = "agent", help = "only these agents, default is every one touchgate supports")]
        agents: Vec<Agent>,
        #[arg(long, help = "also block hooks the agent or user add outside managed config")]
        lock: bool,
        #[arg(long, help = "do not copy this binary into the system bin dir")]
        no_copy: bool,
    },
    #[command(about = "remove touchgate hooks from managed agent config")]
    Uninstall {
        #[arg(long, help = "also delete the system policy file")]
        purge: bool,
    },
    #[command(about = "check the reader, the install and known bypasses")]
    Doctor,
    #[command(about = "show recent decisions")]
    Log {
        #[arg(short, default_value_t = 20)]
        n: usize,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let r = match cli.cmd {
        Cmd::Hook { agent } => return hook(agent),
        Cmd::Test {
            read,
            write,
            fetch,
            mcp,
            cwd,
            verify,
            command,
        } => test(read, write, fetch, mcp, cwd, verify, command),
        Cmd::Install { agents, lock, no_copy } => run_install(agents, lock, !no_copy),
        Cmd::Uninstall { purge } => {
            require_admin().and_then(|_| install::uninstall(&Locations::system(), purge, &mut |m| println!("{m}")))
        }
        Cmd::Doctor => doctor::run(),
        Cmd::Log { n } => log(n),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("touchgate: {e:#}");
            ExitCode::FAILURE
        }
    }
}

pub fn load_policy() -> Result<Policy> {
    let locs = Locations::system();
    let sys = match fs::read_to_string(&locs.policy) {
        Ok(t) => Some((locs.policy.to_string_lossy().into_owned(), t)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("read {}", locs.policy.display())),
    };
    let up = user_policy();
    let user = match fs::read_to_string(&up) {
        Ok(t) => Some((up.to_string_lossy().into_owned(), t)),
        Err(_) => None,
    };
    Ok(Policy::load(
        sys.as_ref().map(|(o, t)| (o.as_str(), t.as_str())),
        user.as_ref().map(|(o, t)| (o.as_str(), t.as_str())),
        &home(),
    )?)
}

fn hook(agent: Agent) -> ExitCode {
    std::panic::set_hook(Box::new(|info| {
        eprintln!("touchgate: internal error, blocking to be safe: {info}");
        std::process::exit(2);
    }));
    let mut input = String::new();
    let resp = match std::io::stdin().take(16 << 20).read_to_string(&mut input) {
        Err(e) => fail_closed(&format!("could not read hook input: {e}")),
        Ok(_) => match decide(agent, &input, touchgate_auth::platform().as_ref()) {
            Ok(outcome) => respond(agent, &outcome),
            Err(e) => fail_closed(&format!("{e:#}")),
        },
    };
    if !resp.stdout.is_empty() {
        println!("{}", resp.stdout);
    }
    if !resp.stderr.is_empty() {
        eprintln!("{}", resp.stderr);
    }
    ExitCode::from(resp.exit_code as u8)
}

fn decide(agent: Agent, input: &str, verifier: &dyn Verifier) -> Result<Outcome> {
    let action = parse(agent, input)?;
    let policy = load_policy()?;
    let decision = policy.evaluate(&action);
    let (outcome, auth) = outcome_for(agent, &action, &decision, policy.timeout_secs, verifier);
    audit(&action, &decision, &outcome, auth.as_deref());
    Ok(outcome)
}

fn outcome_for(
    agent: Agent,
    action: &Action,
    decision: &Decision,
    timeout_secs: u64,
    verifier: &dyn Verifier,
) -> (Outcome, Option<String>) {
    match decision.verdict {
        Verdict::Allow => (Outcome::Pass, None),
        Verdict::Deny => (
            Outcome::Denied(format!(
                "touchgate blocked this ({}). do not retry it another way, tell the user what you wanted to do",
                decision.reason
            )),
            None,
        ),
        Verdict::Touch => {
            let prompt = Prompt {
                agent: agent.display().to_string(),
                action: action.summary(200),
                reason: decision.reason.clone(),
                timeout: Duration::from_secs(timeout_secs),
            };
            match verifier.verify(&prompt) {
                AuthResult::Verified => (
                    Outcome::Approved("approved with a fingerprint via touchgate".into()),
                    Some("verified".into()),
                ),
                AuthResult::Rejected(why) => (
                    Outcome::Denied(format!(
                        "touchgate needs the user's fingerprint for this ({}) and it was not given: {why}. do not retry it another way, ask the user",
                        decision.reason
                    )),
                    Some(why),
                ),
            }
        }
    }
}

fn audit(action: &Action, decision: &Decision, outcome: &Outcome, auth: Option<&str>) {
    if decision.verdict == Verdict::Allow {
        return;
    }
    let path = audit_log();
    if let Some(d) = path.parent() {
        let _ = fs::create_dir_all(d);
    }
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let result = match outcome {
        Outcome::Pass => "pass",
        Outcome::Approved(_) => "approved",
        Outcome::Denied(_) => "denied",
    };
    let line = serde_json::json!({
        "ts": ts,
        "agent": action.agent,
        "tool": action.tool_name,
        "action": action.summary(300),
        "cwd": action.cwd,
        "verdict": decision.verdict,
        "rule": decision.rule,
        "result": result,
        "auth": auth,
    });
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{line}");
    }
}

fn test(
    read: Option<String>,
    write: Option<String>,
    fetch: Option<String>,
    mcp: Option<String>,
    cwd: Option<PathBuf>,
    verify: bool,
    command: Vec<String>,
) -> Result<()> {
    let cwd = cwd.or_else(|| std::env::current_dir().ok());
    let mut a = if let Some(p) = read.clone().or(write.clone()) {
        let mut a = Action::new("cli", if read.is_some() { "Read" } else { "Write" }, if read.is_some() { ToolKind::Read } else { ToolKind::Write });
        a.paths = vec![p];
        a
    } else if let Some(u) = fetch {
        let mut a = Action::new("cli", "WebFetch", ToolKind::Fetch);
        a.url = Some(u);
        a
    } else if let Some(m) = mcp {
        Action::new("cli", m, ToolKind::Mcp)
    } else {
        if command.is_empty() {
            bail!("give a command, or --read/--write/--fetch/--mcp");
        }
        let mut a = Action::new("cli", "Bash", ToolKind::Shell);
        a.command = Some(command.join(" "));
        a
    };
    a.cwd = cwd.map(|c| c.to_string_lossy().into_owned());
    let policy = load_policy()?;
    let d = policy.evaluate(&a);
    let color = std::io::stdout().is_terminal();
    let paint = |code: &str, s: &str| if color { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() };
    let v = match d.verdict {
        Verdict::Allow => paint("32", "allow"),
        Verdict::Touch => paint("33", "touch"),
        Verdict::Deny => paint("31", "deny"),
    };
    println!("{v}  {}", d.reason);
    if let Some(r) = &d.rule {
        println!("rule  {r}");
    }
    if verify && d.verdict == Verdict::Touch {
        let (o, _) = outcome_for(Agent::Claude, &a, &d, policy.timeout_secs, touchgate_auth::platform().as_ref());
        match o {
            Outcome::Approved(_) => println!("{}", paint("32", "fingerprint ok")),
            Outcome::Denied(m) => println!("{}  {m}", paint("31", "denied")),
            Outcome::Pass => {}
        }
    }
    Ok(())
}

fn log(n: usize) -> Result<()> {
    let path = audit_log();
    let text = fs::read_to_string(&path).with_context(|| format!("no log yet at {}", path.display()))?;
    let lines: Vec<&str> = text.lines().collect();
    for l in &lines[lines.len().saturating_sub(n)..] {
        let v: serde_json::Value = serde_json::from_str(l).unwrap_or_default();
        println!(
            "{:<10} {:<8} {:<8} {}",
            v["result"].as_str().unwrap_or("?"),
            v["agent"].as_str().unwrap_or("?"),
            v["rule"].as_str().unwrap_or("-"),
            v["action"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

fn run_install(agents: Vec<Agent>, lock: bool, copy_binary: bool) -> Result<()> {
    require_admin()?;
    let agents = if agents.is_empty() { Agent::ALL.to_vec() } else { agents };
    let locs = Locations::system();
    install::install(&locs, &install::Options { agents, lock, copy_binary }, &mut |m| println!("{m}"))?;
    if !lock {
        println!("tip: --lock also stops hooks added outside managed config, it disables your own user hooks too");
    }
    println!("done, run `touchgate doctor` as your normal user to check everything");
    Ok(())
}

#[cfg(unix)]
fn require_admin() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("this writes system config, run it with sudo");
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_admin() -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use touchgate_auth::Fixed;

    fn action(cmd: &str) -> Action {
        let mut a = Action::new("claude", "Bash", ToolKind::Shell);
        a.command = Some(cmd.into());
        a
    }

    #[test]
    fn touch_uses_the_verifier() {
        let p = Policy::builtin(&home()).unwrap();
        let a = action("rm -rf /tmp/x");
        let d = p.evaluate(&a);
        let yes = Fixed(AuthResult::Verified);
        let no = Fixed(AuthResult::Rejected("timed out".into()));
        assert!(matches!(outcome_for(Agent::Claude, &a, &d, 5, &yes).0, Outcome::Approved(_)));
        match outcome_for(Agent::Claude, &a, &d, 5, &no).0 {
            Outcome::Denied(m) => assert!(m.contains("timed out")),
            o => panic!("{o:?}"),
        }
        let safe = action("ls");
        let d = p.evaluate(&safe);
        assert_eq!(outcome_for(Agent::Claude, &safe, &d, 5, &no).0, Outcome::Pass);
    }
}
