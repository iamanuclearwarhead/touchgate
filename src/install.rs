use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};
use toml_edit::{ArrayOfTables, DocumentMut, Item, Table, value};
use touchgate_agents::Agent;

use crate::locations::{Locations, hook_command};

pub const HOOK_TIMEOUT_SECS: u64 = 90;

pub const POLICY_TEMPLATE: &str = r#"# touchgate system policy
# rules here run before the built-in ones, first match wins
# actions: allow, touch (needs a fingerprint), deny
# user rules in ~/.config/touchgate/policy.toml can only make things stricter

timeout = 45

# [[rule]]
# name = "my-build-dirs"
# tool = ["shell"]
# command = ['^rm -rf (target|dist|node_modules)$']
# action = "allow"
"#;

#[derive(Debug, Clone)]
pub struct Options {
    pub agents: Vec<Agent>,
    pub lock: bool,
    pub copy_binary: bool,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
pub struct State {
    pub agents: Vec<String>,
    pub lock: bool,
    pub bin: String,
}

pub fn install(locs: &Locations, opts: &Options, report: &mut dyn FnMut(String)) -> Result<()> {
    if opts.copy_binary {
        let me = std::env::current_exe().context("cannot find the running touchgate binary")?;
        let same = fs::canonicalize(&me).ok() == fs::canonicalize(&locs.bin).ok();
        if !same {
            ensure_parent(&locs.bin)?;
            fs::copy(&me, &locs.bin).with_context(|| format!("copy binary to {}", locs.bin.display()))?;
            set_mode(&locs.bin, 0o755)?;
            report(format!("installed binary to {}", locs.bin.display()));
        }
    }

    if !locs.policy.exists() {
        ensure_parent(&locs.policy)?;
        fs::write(&locs.policy, POLICY_TEMPLATE)?;
        set_mode(&locs.policy, 0o644)?;
        report(format!("wrote policy {}", locs.policy.display()));
    } else {
        report(format!("kept existing policy {}", locs.policy.display()));
    }

    for &agent in &opts.agents {
        let path = locs.agent_config(agent);
        backup(path)?;
        let cmd = hook_command(&locs.bin, agent);
        match agent {
            Agent::Claude => edit_json(path, |root| claude_add(root, &cmd, opts.lock))?,
            Agent::Codex => edit_toml(path, |doc| codex_add(doc, &cmd, &locs.bin, opts.lock))?,
            Agent::Gemini => edit_json(path, |root| gemini_add(root, &cmd))?,
        }
        set_mode(path, 0o644)?;
        report(format!("{}: managed hook in {}", agent.display(), path.display()));
    }

    let state = State {
        agents: opts.agents.iter().map(|a| a.name().to_string()).collect(),
        lock: opts.lock,
        bin: locs.bin.to_string_lossy().into_owned(),
    };
    ensure_parent(&locs.state)?;
    fs::write(&locs.state, serde_json::to_string_pretty(&state)?)?;
    set_mode(&locs.state, 0o644)?;
    Ok(())
}

pub fn uninstall(locs: &Locations, remove_policy: bool, report: &mut dyn FnMut(String)) -> Result<()> {
    let state: State = fs::read_to_string(&locs.state)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    for agent in Agent::ALL {
        let path = locs.agent_config(agent);
        if !path.exists() {
            continue;
        }
        let changed = match agent {
            Agent::Claude => edit_json(path, |root| claude_remove(root, state.lock))?,
            Agent::Codex => edit_toml(path, |doc| codex_remove(doc, state.lock))?,
            Agent::Gemini => edit_json(path, gemini_remove)?,
        };
        if changed {
            report(format!("{}: removed hook from {}", agent.display(), path.display()));
        }
    }
    let _ = fs::remove_file(&locs.state);
    if remove_policy && locs.policy.exists() {
        fs::remove_file(&locs.policy)?;
        report(format!("removed {}", locs.policy.display()));
    }
    Ok(())
}

fn ensure_parent(p: &Path) -> Result<()> {
    if let Some(d) = p.parent() {
        fs::create_dir_all(d).with_context(|| format!("create {}", d.display()))?;
    }
    Ok(())
}

fn backup(p: &Path) -> Result<()> {
    if p.exists() {
        let b = p.with_extension(format!(
            "{}.touchgate-backup",
            p.extension().and_then(|e| e.to_str()).unwrap_or("")
        ));
        if !b.exists() {
            fs::copy(p, &b).with_context(|| format!("back up {}", p.display()))?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode(p: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(mode)).with_context(|| format!("chmod {}", p.display()))
}

#[cfg(not(unix))]
fn set_mode(_: &Path, _: u32) -> Result<()> {
    Ok(())
}

fn edit_json<T>(path: &Path, f: impl FnOnce(&mut Map<String, Value>) -> T) -> Result<T> {
    let mut root = match fs::read_to_string(path) {
        Ok(s) if !s.trim().is_empty() => match serde_json::from_str::<Value>(&s)
            .with_context(|| format!("{} is not valid json, fix it first", path.display()))?
        {
            Value::Object(m) => m,
            _ => bail!("{} is not a json object", path.display()),
        },
        _ => Map::new(),
    };
    let out = f(&mut root);
    ensure_parent(path)?;
    fs::write(path, serde_json::to_string_pretty(&Value::Object(root))? + "\n")?;
    Ok(out)
}

fn edit_toml<T>(path: &Path, f: impl FnOnce(&mut DocumentMut) -> T) -> Result<T> {
    let text = fs::read_to_string(path).unwrap_or_default();
    let mut doc: DocumentMut = text
        .parse()
        .with_context(|| format!("{} is not valid toml, fix it first", path.display()))?;
    let out = f(&mut doc);
    ensure_parent(path)?;
    fs::write(path, doc.to_string())?;
    Ok(out)
}

fn is_ours(entry: &Value) -> bool {
    entry
        .get("hooks")
        .and_then(Value::as_array)
        .is_some_and(|hs| hs.iter().any(|h| h.get("command").and_then(Value::as_str).is_some_and(|c| c.contains("touchgate") && c.contains(" hook "))))
}

fn event_array<'a>(root: &'a mut Map<String, Value>, event: &str) -> &'a mut Vec<Value> {
    let hooks = root.entry("hooks").or_insert_with(|| json!({}));
    if !hooks.is_object() {
        *hooks = json!({});
    }
    let arr = hooks.as_object_mut().unwrap().entry(event).or_insert_with(|| json!([]));
    if !arr.is_array() {
        *arr = json!([]);
    }
    arr.as_array_mut().unwrap()
}

fn remove_event(root: &mut Map<String, Value>, event: &str) -> bool {
    let Some(hooks) = root.get_mut("hooks").and_then(Value::as_object_mut) else {
        return false;
    };
    let Some(arr) = hooks.get_mut(event).and_then(Value::as_array_mut) else {
        return false;
    };
    let before = arr.len();
    arr.retain(|e| !is_ours(e));
    let changed = arr.len() != before;
    if arr.is_empty() {
        hooks.remove(event);
    }
    if hooks.is_empty() {
        root.remove("hooks");
    }
    changed
}

pub fn claude_add(root: &mut Map<String, Value>, cmd: &str, lock: bool) {
    let arr = event_array(root, "PreToolUse");
    arr.retain(|e| !is_ours(e));
    arr.push(json!({
        "matcher": "*",
        "hooks": [{ "type": "command", "command": cmd, "timeout": HOOK_TIMEOUT_SECS }]
    }));
    if lock {
        root.insert("allowManagedHooksOnly".into(), Value::Bool(true));
    }
}

pub fn claude_remove(root: &mut Map<String, Value>, lock: bool) -> bool {
    let changed = remove_event(root, "PreToolUse");
    if lock {
        root.remove("allowManagedHooksOnly");
    }
    changed
}

pub fn gemini_add(root: &mut Map<String, Value>, cmd: &str) {
    let arr = event_array(root, "BeforeTool");
    arr.retain(|e| !is_ours(e));
    arr.push(json!({
        "matcher": "*",
        "hooks": [{
            "name": "touchgate",
            "type": "command",
            "command": cmd,
            "timeout": HOOK_TIMEOUT_SECS * 1000,
            "description": "fingerprint approval for risky actions"
        }]
    }));
    let cfg = root.entry("hooksConfig").or_insert_with(|| json!({}));
    if !cfg.is_object() {
        *cfg = json!({});
    }
    cfg.as_object_mut().unwrap().insert("enabled".into(), Value::Bool(true));
}

pub fn gemini_remove(root: &mut Map<String, Value>) -> bool {
    remove_event(root, "BeforeTool")
}

fn toml_is_ours(t: &Table) -> bool {
    t.get("hooks")
        .and_then(Item::as_array_of_tables)
        .is_some_and(|hs| hs.iter().any(|h| h.get("command").and_then(Item::as_str).is_some_and(|c| c.contains("touchgate") && c.contains(" hook "))))
}

pub fn codex_add(doc: &mut DocumentMut, cmd: &str, bin: &Path, lock: bool) {
    if !doc.contains_key("features") {
        let mut t = Table::new();
        t.set_implicit(false);
        doc.insert("features", Item::Table(t));
    }
    doc["features"]["hooks"] = value(true);
    if lock {
        doc["allow_managed_hooks_only"] = value(true);
    }
    if !doc.contains_key("hooks") {
        doc.insert("hooks", Item::Table(Table::new()));
    }
    let hooks = doc["hooks"].as_table_mut().expect("hooks is a table");
    let dir = bin.parent().map(|d| d.to_string_lossy().into_owned()).unwrap_or_default();
    if cfg!(windows) {
        if !hooks.contains_key("windows_managed_dir") {
            hooks["windows_managed_dir"] = value(dir);
        }
    } else if !hooks.contains_key("managed_dir") {
        hooks["managed_dir"] = value(dir);
    }
    if !hooks.contains_key("PreToolUse") {
        hooks.insert("PreToolUse", Item::ArrayOfTables(ArrayOfTables::new()));
    }
    let pre = hooks["PreToolUse"].as_array_of_tables_mut().expect("PreToolUse is an array of tables");
    pre.retain(|t| !toml_is_ours(t));
    let mut h = Table::new();
    h["type"] = value("command");
    h["command"] = value(cmd);
    h["command_windows"] = value(cmd);
    h["timeout"] = value(HOOK_TIMEOUT_SECS as i64);
    h["statusMessage"] = value("touchgate");
    let mut inner = ArrayOfTables::new();
    inner.push(h);
    let mut entry = Table::new();
    entry["matcher"] = value(".*");
    entry.insert("hooks", Item::ArrayOfTables(inner));
    pre.push(entry);
}

pub fn codex_remove(doc: &mut DocumentMut, lock: bool) -> bool {
    let mut changed = false;
    if let Some(hooks) = doc.get_mut("hooks").and_then(Item::as_table_mut) {
        if let Some(pre) = hooks.get_mut("PreToolUse").and_then(Item::as_array_of_tables_mut) {
            let before = pre.len();
            pre.retain(|t| !toml_is_ours(t));
            changed = pre.len() != before;
            if pre.is_empty() {
                hooks.remove("PreToolUse");
            }
        }
    }
    if lock {
        doc.remove("allow_managed_hooks_only");
    }
    changed
}

pub fn agent_has_hook(locs: &Locations, agent: Agent) -> bool {
    let path = locs.agent_config(agent);
    let Ok(text) = fs::read_to_string(path) else {
        return false;
    };
    match agent {
        Agent::Claude | Agent::Gemini => {
            let event = if agent == Agent::Claude { "PreToolUse" } else { "BeforeTool" };
            serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v.get("hooks")?.get(event)?.as_array().cloned())
                .is_some_and(|a| a.iter().any(is_ours))
        }
        Agent::Codex => text
            .parse::<DocumentMut>()
            .ok()
            .and_then(|d| d.get("hooks")?.get("PreToolUse")?.as_array_of_tables().map(|a| a.iter().any(toml_is_ours)))
            .unwrap_or(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("touchgate-test-{}-{}", std::process::id(), rand_suffix()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn rand_suffix() -> u128 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    }

    #[test]
    fn install_merges_and_uninstall_cleans_up() {
        let root = tmp();
        let locs = Locations::under(&root);
        fs::create_dir_all(locs.claude.parent().unwrap()).unwrap();
        fs::write(
            &locs.claude,
            r#"{"permissions":{"deny":["Bash(curl:*)"]},"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/opt/corp/audit.sh"}]}]}}"#,
        )
        .unwrap();
        fs::create_dir_all(locs.codex.parent().unwrap()).unwrap();
        fs::write(&locs.codex, "# corp\napproval_policy = \"on-request\"\n").unwrap();

        let opts = Options {
            agents: Agent::ALL.to_vec(),
            lock: true,
            copy_binary: false,
        };
        install(&locs, &opts, &mut |_| {}).unwrap();
        install(&locs, &opts, &mut |_| {}).unwrap();

        let c: Value = serde_json::from_str(&fs::read_to_string(&locs.claude).unwrap()).unwrap();
        let pre = c["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 2);
        assert_eq!(pre[0]["hooks"][0]["command"], "/opt/corp/audit.sh");
        assert!(pre[1]["hooks"][0]["command"].as_str().unwrap().ends_with("touchgate hook --agent claude"));
        assert_eq!(pre[1]["hooks"][0]["timeout"], 90);
        assert_eq!(c["allowManagedHooksOnly"], true);
        assert_eq!(c["permissions"]["deny"][0], "Bash(curl:*)");

        let g: Value = serde_json::from_str(&fs::read_to_string(&locs.gemini).unwrap()).unwrap();
        assert_eq!(g["hooks"]["BeforeTool"].as_array().unwrap().len(), 1);
        assert_eq!(g["hooks"]["BeforeTool"][0]["hooks"][0]["timeout"], 90000);
        assert_eq!(g["hooksConfig"]["enabled"], true);

        let codex = fs::read_to_string(&locs.codex).unwrap();
        assert!(codex.starts_with("# corp\napproval_policy = \"on-request\""), "{codex}");
        let d: DocumentMut = codex.parse().unwrap();
        assert_eq!(d["features"]["hooks"].as_bool(), Some(true));
        assert_eq!(d["allow_managed_hooks_only"].as_bool(), Some(true));
        assert_eq!(d["hooks"]["PreToolUse"].as_array_of_tables().unwrap().len(), 1);

        assert!(Agent::ALL.iter().all(|a| agent_has_hook(&locs, *a)));
        assert!(locs.policy.exists());
        assert!(locs.claude.with_extension("json.touchgate-backup").exists());

        uninstall(&locs, true, &mut |_| {}).unwrap();
        assert!(Agent::ALL.iter().all(|a| !agent_has_hook(&locs, *a)));
        let c: Value = serde_json::from_str(&fs::read_to_string(&locs.claude).unwrap()).unwrap();
        assert_eq!(c["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
        assert!(c.get("allowManagedHooksOnly").is_none());
        assert!(!locs.policy.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_to_clobber_broken_json() {
        let root = tmp();
        let locs = Locations::under(&root);
        fs::create_dir_all(locs.claude.parent().unwrap()).unwrap();
        fs::write(&locs.claude, "{ nope").unwrap();
        let opts = Options {
            agents: vec![Agent::Claude],
            lock: false,
            copy_binary: false,
        };
        assert!(install(&locs, &opts, &mut |_| {}).is_err());
        assert_eq!(fs::read_to_string(&locs.claude).unwrap(), "{ nope");
        fs::remove_dir_all(root).unwrap();
    }
}
