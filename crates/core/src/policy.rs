use std::collections::HashSet;
use std::path::{Path, PathBuf};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde::Deserialize;

use crate::action::{Action, Decision, ToolKind, Verdict};
use crate::paths::{candidates, expand_home, slashes};
use crate::shell::analyze;

pub const DEFAULT_POLICY: &str = include_str!("../policy/default.toml");

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("{origin}: invalid toml: {source}")]
    Toml {
        origin: String,
        source: toml::de::Error,
    },
    #[error("{origin}: rule `{rule}`: {msg}")]
    Rule {
        origin: String,
        rule: String,
        msg: String,
    },
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    builtin: Option<bool>,
    default: Option<Verdict>,
    #[serde(default, rename = "rule")]
    rules: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    name: String,
    description: Option<String>,
    #[serde(default)]
    tool: Vec<String>,
    #[serde(default)]
    command: Vec<String>,
    #[serde(default)]
    path: Vec<String>,
    #[serde(default)]
    url: Vec<String>,
    #[serde(default)]
    tool_name: Vec<String>,
    #[serde(default)]
    flag: Vec<String>,
    action: Verdict,
}

#[derive(Debug)]
pub struct Rule {
    pub name: String,
    pub description: Option<String>,
    pub action: Verdict,
    kinds: Option<HashSet<ToolKind>>,
    command: Vec<Regex>,
    path: Option<GlobSet>,
    url: Vec<Regex>,
    tool_name: Option<GlobSet>,
    flag: Vec<String>,
}

#[derive(Debug)]
pub struct Layer {
    pub origin: String,
    pub rules: Vec<Rule>,
    pub default: Verdict,
}

#[derive(Debug)]
pub struct Policy {
    pub layers: Vec<Layer>,
    home: PathBuf,
}

#[derive(Debug, Clone)]
struct Unit {
    kind: ToolKind,
    tool_name: String,
    command: Option<String>,
    paths: Vec<String>,
    url: Option<String>,
    flag: Option<String>,
    subject: String,
}

impl Policy {
    pub fn builtin(home: &Path) -> Result<Self, PolicyError> {
        Self::load(None, None, home)
    }

    pub fn load(system: Option<(&str, &str)>, user: Option<(&str, &str)>, home: &Path) -> Result<Self, PolicyError> {
        let mut layers = Vec::new();
        let (sys_raw, sys_origin) = match system {
            Some((origin, text)) => (parse(origin, text)?, origin.to_string()),
            None => (RawPolicy::default(), "builtin".to_string()),
        };
        let mut rules = compile_rules(&sys_origin, sys_raw.rules, home)?;
        if sys_raw.builtin.unwrap_or(true) {
            let builtin = parse("builtin", DEFAULT_POLICY)?;
            rules.extend(compile_rules("builtin", builtin.rules, home)?);
        }
        layers.push(Layer {
            origin: sys_origin,
            rules,
            default: sys_raw.default.unwrap_or(Verdict::Allow),
        });
        if let Some((origin, text)) = user {
            let raw = parse(origin, text)?;
            let tightening: Vec<RawRule> = raw.rules.into_iter().filter(|r| r.action != Verdict::Allow).collect();
            layers.push(Layer {
                origin: origin.to_string(),
                rules: compile_rules(origin, tightening, home)?,
                default: raw.default.unwrap_or(Verdict::Allow),
            });
        }
        Ok(Self {
            layers,
            home: home.to_path_buf(),
        })
    }

    pub fn evaluate(&self, action: &Action) -> Decision {
        let units = self.units(action);
        let mut best = Decision::allow();
        for layer in &self.layers {
            for unit in &units {
                let (verdict, rule) = match layer.rules.iter().find(|r| r.matches(unit)) {
                    Some(r) => (r.action, Some(r)),
                    None => (layer.default, None),
                };
                if verdict > best.verdict || (best.rule.is_none() && rule.is_some() && verdict == best.verdict && verdict != Verdict::Allow) {
                    best = Decision {
                        verdict,
                        rule: rule.map(|r| r.name.clone()),
                        reason: match rule {
                            Some(r) => match &r.description {
                                Some(d) => format!("{d}: {}", unit.subject),
                                None => format!("{}: {}", r.name, unit.subject),
                            },
                            None => format!("{} default: {}", layer.origin, unit.subject),
                        },
                    };
                }
            }
        }
        if units.is_empty() {
            for layer in &self.layers {
                if layer.default > best.verdict {
                    best = Decision {
                        verdict: layer.default,
                        rule: None,
                        reason: format!("{} default", layer.origin),
                    };
                }
            }
        }
        best
    }

    fn units(&self, action: &Action) -> Vec<Unit> {
        let cwd = action.cwd.as_deref().map(Path::new);
        let home = self.home.as_path();
        let base = Unit {
            kind: action.kind,
            tool_name: action.tool_name.clone(),
            command: None,
            paths: Vec::new(),
            url: action.url.clone(),
            flag: None,
            subject: action.summary(160),
        };
        let mut out = Vec::new();
        match action.kind {
            ToolKind::Shell => {
                let cmd = action.command.clone().unwrap_or_default();
                let a = analyze(&cmd);
                for c in &a.commands {
                    let mut paths = Vec::new();
                    for arg in &c.args {
                        if arg.starts_with('-') {
                            if let Some((_, v)) = arg.split_once('=') {
                                paths.extend(candidates(v, cwd, home));
                            }
                            continue;
                        }
                        paths.extend(candidates(arg, cwd, home));
                    }
                    out.push(Unit {
                        command: Some(c.text()),
                        paths,
                        subject: c.text(),
                        ..base.clone()
                    });
                }
                if !a.write_targets.is_empty() {
                    let mut paths = Vec::new();
                    for t in &a.write_targets {
                        paths.extend(candidates(t, cwd, home));
                    }
                    out.push(Unit {
                        kind: ToolKind::Write,
                        paths,
                        subject: format!("write {}", a.write_targets.join(", ")),
                        ..base.clone()
                    });
                }
                for (flag, detail) in &a.flags {
                    out.push(Unit {
                        flag: Some(flag.clone()),
                        subject: format!("{flag}: {detail}"),
                        ..base.clone()
                    });
                }
            }
            ToolKind::Read | ToolKind::Write => {
                let mut paths = Vec::new();
                for p in &action.paths {
                    paths.extend(candidates(p, cwd, home));
                }
                out.push(Unit { paths, ..base });
            }
            _ => out.push(base),
        }
        out
    }
}

impl Rule {
    fn matches(&self, u: &Unit) -> bool {
        if let Some(k) = &self.kinds {
            if !k.contains(&u.kind) {
                return false;
            }
        }
        let has_matchers = !self.command.is_empty()
            || self.path.is_some()
            || !self.url.is_empty()
            || self.tool_name.is_some()
            || !self.flag.is_empty();
        if !has_matchers {
            return u.flag.is_none();
        }
        if let Some(f) = &u.flag {
            return self.flag.iter().any(|x| x == f);
        }
        if let Some(c) = &u.command {
            if self.command.iter().any(|r| r.is_match(c)) {
                return true;
            }
        }
        if let Some(g) = &self.path {
            if u.paths.iter().any(|p| g.is_match(p)) {
                return true;
            }
        }
        if let Some(url) = &u.url {
            if self.url.iter().any(|r| r.is_match(url)) {
                return true;
            }
        }
        if let Some(g) = &self.tool_name {
            if g.is_match(&u.tool_name) {
                return true;
            }
        }
        false
    }
}

fn parse(origin: &str, text: &str) -> Result<RawPolicy, PolicyError> {
    toml::from_str(text).map_err(|source| PolicyError::Toml {
        origin: origin.to_string(),
        source,
    })
}

fn compile_rules(origin: &str, raw: Vec<RawRule>, home: &Path) -> Result<Vec<Rule>, PolicyError> {
    raw.into_iter().map(|r| compile_rule(origin, r, home)).collect()
}

fn compile_rule(origin: &str, r: RawRule, home: &Path) -> Result<Rule, PolicyError> {
    let err = |msg: String| PolicyError::Rule {
        origin: origin.to_string(),
        rule: r.name.clone(),
        msg,
    };
    let kinds = if r.tool.is_empty() || r.tool.iter().any(|t| t == "*") {
        None
    } else {
        let mut set = HashSet::new();
        for t in &r.tool {
            set.insert(ToolKind::parse(t).ok_or_else(|| err(format!("unknown tool `{t}`")))?);
        }
        Some(set)
    };
    let regexes = |pats: &[String]| -> Result<Vec<Regex>, PolicyError> {
        pats.iter()
            .map(|p| Regex::new(p).map_err(|e| err(format!("bad regex `{p}`: {e}"))))
            .collect()
    };
    let globs = |pats: &[String], expand: bool| -> Result<Option<GlobSet>, PolicyError> {
        if pats.is_empty() {
            return Ok(None);
        }
        let mut b = GlobSetBuilder::new();
        for p in pats {
            let p = if expand { slashes(&expand_home(p, home)) } else { p.clone() };
            let g = GlobBuilder::new(&p)
                .literal_separator(expand)
                .case_insensitive(cfg!(any(windows, target_os = "macos")) && expand)
                .backslash_escape(true)
                .build()
                .map_err(|e| err(format!("bad glob `{p}`: {e}")))?;
            b.add(g);
        }
        b.build().map(Some).map_err(|e| err(e.to_string()))
    };
    Ok(Rule {
        command: regexes(&r.command)?,
        url: regexes(&r.url)?,
        path: globs(&r.path, true)?,
        tool_name: globs(&r.tool_name, false)?,
        flag: r.flag.clone(),
        kinds,
        action: r.action,
        description: r.description.clone(),
        name: r.name,
    })
}
