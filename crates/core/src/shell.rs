use tree_sitter::{Node, Parser};

pub const FLAG_UNPARSED: &str = "unparsed";
pub const FLAG_DYNAMIC: &str = "dynamic-command";
pub const FLAG_OBFUSCATED: &str = "obfuscated";
pub const FLAG_STDIN_SHELL: &str = "shell-from-stdin";
pub const FLAG_INLINE_EXEC: &str = "inline-code-exec";

const MAX_DEPTH: usize = 4;

const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "mksh", "fish", "ash", "busybox"];
const INTERPRETERS: &[&str] = &[
    "python", "python2", "python3", "perl", "ruby", "node", "nodejs", "deno", "bun", "php", "lua",
    "osascript", "pwsh", "powershell",
];
const PLAIN_WRAPPERS: &[&str] = &[
    "nohup", "time", "command", "exec", "builtin", "setsid", "stdbuf", "chronic", "unbuffer",
    "nice", "ionice", "caffeinate", "systemd-run", "flock", "watch", "strace", "ltrace",
];
const PRIV_WRAPPERS: &[&str] = &["sudo", "doas", "run0", "pkexec", "su"];
const EXEC_HINTS: &[&str] = &[
    "os.system", "subprocess", "shutil.rmtree", "os.remove", "os.unlink", "os.rmdir", "rmtree",
    "child_process", "execSync", "spawnSync", "fs.rm", "unlinkSync", "system(", "exec(", "popen",
    "Deno.Command", "Bun.spawn", "File.delete", "FileUtils.rm", "`", "do shell script",
    "Remove-Item", "Invoke-Expression", "iex ",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleCommand {
    pub name: String,
    pub args: Vec<String>,
}

impl SimpleCommand {
    pub fn text(&self) -> String {
        if self.args.is_empty() {
            self.name.clone()
        } else {
            format!("{} {}", self.name, self.args.join(" "))
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ShellAnalysis {
    pub commands: Vec<SimpleCommand>,
    pub write_targets: Vec<String>,
    pub flags: Vec<(String, String)>,
}

impl ShellAnalysis {
    fn flag(&mut self, name: &str, detail: impl Into<String>) {
        let detail = detail.into();
        if !self.flags.iter().any(|(n, d)| n == name && *d == detail) {
            self.flags.push((name.to_string(), detail));
        }
    }
}

pub fn analyze(src: &str) -> ShellAnalysis {
    let mut out = ShellAnalysis::default();
    analyze_into(src, 0, &mut out);
    out
}

fn analyze_into(src: &str, depth: usize, out: &mut ShellAnalysis) {
    if depth > MAX_DEPTH {
        out.flag(FLAG_OBFUSCATED, "nested shell too deep");
        return;
    }
    let mut parser = Parser::new();
    if parser.set_language(&tree_sitter_bash::LANGUAGE.into()).is_err() {
        out.flag(FLAG_UNPARSED, src);
        return;
    }
    let Some(tree) = parser.parse(src, None) else {
        out.flag(FLAG_UNPARSED, src);
        return;
    };
    let root = tree.root_node();
    if root.has_error() {
        out.flag(FLAG_UNPARSED, src);
    }
    let mut w = Walker { src, depth, out };
    w.walk(root);
}

struct Walker<'a, 'b> {
    src: &'a str,
    depth: usize,
    out: &'b mut ShellAnalysis,
}

impl Walker<'_, '_> {
    fn text(&self, n: Node) -> String {
        n.utf8_text(self.src.as_bytes()).unwrap_or_default().to_string()
    }

    fn walk(&mut self, node: Node) {
        match node.kind() {
            "command" => self.command(node),
            "file_redirect" => self.redirect(node),
            "pipeline" => self.pipeline(node),
            "redirected_statement" => self.stdin_body(node),
            _ => {}
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.walk(child);
        }
    }

    fn literal(&self, n: Node) -> Option<String> {
        match n.kind() {
            "word" | "number" => Some(unescape(&self.text(n))),
            "raw_string" => {
                let t = self.text(n);
                Some(t.trim_start_matches('\'').trim_end_matches('\'').to_string())
            }
            "ansi_c_string" => {
                let t = self.text(n);
                Some(t.trim_start_matches("$'").trim_end_matches('\'').to_string())
            }
            "string" => {
                let mut s = String::new();
                let mut cursor = n.walk();
                for c in n.named_children(&mut cursor) {
                    match c.kind() {
                        "string_content" => s.push_str(&self.text(c)),
                        _ => return None,
                    }
                }
                Some(s)
            }
            "concatenation" | "command_name" => {
                let mut s = String::new();
                let mut cursor = n.walk();
                let children: Vec<Node> = n.named_children(&mut cursor).collect();
                if children.is_empty() {
                    return Some(self.text(n));
                }
                for c in children {
                    s.push_str(&self.literal(c)?);
                }
                Some(s)
            }
            _ => None,
        }
    }

    fn command(&mut self, node: Node) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let raw_name = self.text(name_node);
        let Some(name) = self.literal(name_node) else {
            self.out.flag(FLAG_DYNAMIC, self.text(node));
            return;
        };
        let mut args = Vec::new();
        let mut cursor = node.walk();
        for a in node.children_by_field_name("argument", &mut cursor) {
            match self.literal(a) {
                Some(v) => args.push(Lit::Known(v)),
                None => args.push(Lit::Dynamic(self.text(a))),
            }
        }
        let mut has_stdin_body = false;
        let mut cursor = node.walk();
        for c in node.children(&mut cursor) {
            if matches!(c.kind(), "heredoc_redirect" | "herestring_redirect") {
                has_stdin_body = true;
            }
        }
        let base = basename(&name);
        if has_stdin_body && (SHELLS.contains(&base.as_str()) || INTERPRETERS.contains(&base.as_str())) {
            self.out.flag(FLAG_STDIN_SHELL, raw_name);
        }
        self.expand(&name, &args, self.depth);
    }

    fn stdin_body(&mut self, node: Node) {
        let mut cursor = node.walk();
        let fed = node
            .children(&mut cursor)
            .any(|c| matches!(c.kind(), "heredoc_redirect" | "herestring_redirect"));
        if !fed {
            return;
        }
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };
        if body.kind() != "command" {
            return;
        }
        let Some(name) = body.child_by_field_name("name").and_then(|n| self.literal(n)) else {
            return;
        };
        let base = basename(&name);
        if SHELLS.contains(&base.as_str()) || INTERPRETERS.contains(&base.as_str()) {
            self.out.flag(FLAG_STDIN_SHELL, self.text(node));
        }
    }

    fn redirect(&mut self, node: Node) {
        let mut writes = false;
        let mut cursor = node.walk();
        for c in node.children(&mut cursor) {
            if !c.is_named() {
                let op = self.text(c);
                if op.contains('>') {
                    writes = true;
                }
            }
        }
        if !writes {
            return;
        }
        if let Some(dest) = node.child_by_field_name("destination") {
            match self.literal(dest) {
                Some(d) if !d.starts_with('&') && !d.chars().all(|c| c.is_ascii_digit()) => {
                    self.out.write_targets.push(d)
                }
                Some(_) => {}
                None => self.out.flag(FLAG_DYNAMIC, self.text(node)),
            }
        }
    }

    fn pipeline(&mut self, node: Node) {
        let mut cursor = node.walk();
        for (i, c) in node.named_children(&mut cursor).enumerate() {
            if i == 0 || c.kind() != "command" {
                continue;
            }
            let Some(name_node) = c.child_by_field_name("name") else {
                continue;
            };
            let Some(name) = self.literal(name_node) else {
                continue;
            };
            let base = basename(&name);
            if !SHELLS.contains(&base.as_str()) && !INTERPRETERS.contains(&base.as_str()) {
                continue;
            }
            let mut cursor2 = c.walk();
            let args: Vec<String> = c
                .children_by_field_name("argument", &mut cursor2)
                .map(|a| self.text(a))
                .collect();
            let runs_script = args.iter().any(|a| !a.starts_with('-'))
                || args.iter().any(|a| is_inline_flag(&base, a));
            if !runs_script {
                self.out.flag(FLAG_STDIN_SHELL, self.text(node));
            }
        }
    }

    fn expand(&mut self, name: &str, args: &[Lit], depth: usize) {
        let base = basename(name);
        let known: Vec<String> = args.iter().map(|a| a.as_str().to_string()).collect();
        self.out.commands.push(SimpleCommand {
            name: base.clone(),
            args: known.clone(),
        });

        match base.as_str() {
            "tee" => {
                for a in known.iter().filter(|a| !a.starts_with('-')) {
                    self.out.write_targets.push(a.clone());
                }
            }
            "cp" | "mv" | "install" | "ln" | "rsync" | "scp" => {
                if let Some(last) = known.iter().filter(|a| !a.starts_with('-')).nth_back(0)
                    && known.iter().filter(|a| !a.starts_with('-')).count() >= 2 {
                        self.out.write_targets.push(last.clone());
                    }
            }
            "dd" => {
                for a in &known {
                    if let Some(of) = a.strip_prefix("of=") {
                        self.out.write_targets.push(of.to_string());
                    }
                }
            }
            "truncate" | "shred" => {
                for a in known.iter().filter(|a| !a.starts_with('-')) {
                    self.out.write_targets.push(a.clone());
                }
            }
            _ => {}
        }

        if PRIV_WRAPPERS.contains(&base.as_str()) {
            let rest = skip_opts(args, &["-u", "-g", "-U", "-C", "-D", "-h", "-p", "-r", "-t", "-T", "--user", "--group"]);
            if base == "su" {
                if let Some(i) = args.iter().position(|a| a.as_str() == "-c" || a.as_str() == "--command") {
                    self.nested_shell(args.get(i + 1), depth);
                }
                return;
            }
            if let Some((n, r)) = rest.split_first() {
                self.expand(n.as_str(), r, depth);
            }
            return;
        }
        if PLAIN_WRAPPERS.contains(&base.as_str()) {
            let rest = skip_opts(args, &["-n", "-c", "-o", "-e", "-i", "-p", "-u", "-w", "-d", "--adjustment", "--class"]);
            let rest: Vec<Lit> = rest
                .iter()
                .skip_while(|a| base == "nice" && a.as_str().parse::<i32>().is_ok())
                .cloned()
                .collect();
            if base == "flock" {
                if let Some((_, r)) = rest.split_first()
                    && let Some((n, r2)) = r.split_first() {
                        self.expand(n.as_str(), r2, depth);
                    }
                return;
            }
            if let Some((n, r)) = rest.split_first() {
                self.expand(n.as_str(), r, depth);
            }
            return;
        }
        match base.as_str() {
            "env" => {
                let mut i = 0;
                while i < args.len() {
                    let a = args[i].as_str();
                    if a == "-S" || a == "--split-string" {
                        self.nested_shell(args.get(i + 1), depth);
                        return;
                    }
                    if a == "-u" || a == "-C" || a == "--unset" || a == "--chdir" {
                        i += 2;
                        continue;
                    }
                    if a.starts_with('-') || (a.contains('=') && !a.starts_with('=')) {
                        i += 1;
                        continue;
                    }
                    break;
                }
                if let Some((n, r)) = args[i.min(args.len())..].split_first() {
                    self.expand(n.as_str(), r, depth);
                }
            }
            "timeout" => {
                let rest = skip_opts(args, &["-s", "-k", "--signal", "--kill-after"]);
                if let Some((_, r)) = rest.split_first()
                    && let Some((n, r2)) = r.split_first() {
                        self.expand(n.as_str(), r2, depth);
                    }
            }
            "xargs" => {
                let rest = skip_opts(args, &["-I", "-i", "-n", "-L", "-l", "-P", "-d", "-E", "-e", "-s", "-a"]);
                if let Some((n, r)) = rest.split_first() {
                    self.expand(n.as_str(), r, depth);
                }
            }
            "find" | "fd" => {
                let mut i = 0;
                while i < args.len() {
                    let a = args[i].as_str();
                    if matches!(a, "-exec" | "-execdir" | "-ok" | "-okdir" | "-x" | "--exec" | "-X" | "--exec-batch") {
                        let end = args[i + 1..]
                            .iter()
                            .position(|x| matches!(x.as_str(), ";" | "\\;" | "+"))
                            .map(|p| i + 1 + p)
                            .unwrap_or(args.len());
                        if let Some((n, r)) = args[i + 1..end].split_first() {
                            self.expand(n.as_str(), r, depth);
                        }
                        i = end;
                    }
                    i += 1;
                }
            }
            "eval" => {
                if args.iter().all(|a| matches!(a, Lit::Known(_))) {
                    let joined = known.join(" ");
                    analyze_into(&joined, depth + 1, self.out);
                } else {
                    self.out.flag(FLAG_OBFUSCATED, format!("eval {}", known.join(" ")));
                }
            }
            b if SHELLS.contains(&b) => {
                if let Some(i) = args.iter().position(|a| is_inline_flag(b, a.as_str())) {
                    self.nested_shell(args.get(i + 1), depth);
                }
            }
            b if INTERPRETERS.contains(&b) => {
                if let Some(i) = args.iter().position(|a| is_inline_flag(b, a.as_str())) {
                    match args.get(i + 1) {
                        Some(Lit::Known(code)) => {
                            if EXEC_HINTS.iter().any(|h| code.contains(h)) {
                                self.out.flag(FLAG_INLINE_EXEC, format!("{b}: {}", one_line(code)));
                            }
                        }
                        Some(Lit::Dynamic(t)) => self.out.flag(FLAG_OBFUSCATED, format!("{b} {t}")),
                        None => {}
                    }
                }
            }
            _ => {}
        }
    }

    fn nested_shell(&mut self, arg: Option<&Lit>, depth: usize) {
        match arg {
            Some(Lit::Known(code)) => analyze_into(code, depth + 1, self.out),
            Some(Lit::Dynamic(t)) => self.out.flag(FLAG_OBFUSCATED, t.clone()),
            None => {}
        }
    }
}

#[derive(Debug, Clone)]
enum Lit {
    Known(String),
    Dynamic(String),
}

impl Lit {
    fn as_str(&self) -> &str {
        match self {
            Lit::Known(s) | Lit::Dynamic(s) => s,
        }
    }
}

fn is_inline_flag(prog: &str, a: &str) -> bool {
    if SHELLS.contains(&prog) {
        return a == "-c" || (a.starts_with('-') && !a.starts_with("--") && a.ends_with('c') && a.len() <= 5);
    }
    match prog {
        "python" | "python2" | "python3" => a == "-c",
        "pwsh" | "powershell" => a.eq_ignore_ascii_case("-c") || a.eq_ignore_ascii_case("-command") || a.eq_ignore_ascii_case("-encodedcommand"),
        "osascript" => a == "-e",
        "php" => a == "-r",
        "deno" => a == "eval",
        _ => a == "-e" || a == "-E" || a == "--eval" || a == "-p" || a == "--print",
    }
}

fn skip_opts(args: &[Lit], with_value: &[&str]) -> Vec<Lit> {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            i += 1;
            break;
        }
        if !a.starts_with('-') || a == "-" {
            break;
        }
        if with_value.contains(&a) {
            i += 2;
        } else {
            i += 1;
        }
    }
    args[i.min(args.len())..].to_vec()
}

pub fn basename(name: &str) -> String {
    let b = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let b = b.strip_suffix(".exe").unwrap_or(b);
    b.to_string()
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn one_line(s: &str) -> String {
    let l: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    l.chars().take(120).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(src: &str) -> Vec<String> {
        analyze(src).commands.iter().map(|c| c.text()).collect()
    }

    fn flags(src: &str) -> Vec<String> {
        analyze(src).flags.into_iter().map(|(n, _)| n).collect()
    }

    #[test]
    fn splits_lists_and_pipes() {
        assert_eq!(names("ls -la && rm -rf build; echo hi | wc -l"), vec!["ls -la", "rm -rf build", "echo hi", "wc -l"]);
    }

    #[test]
    fn finds_substitutions() {
        let n = names("echo $(rm -rf /tmp/x) `id`");
        assert!(n.contains(&"rm -rf /tmp/x".to_string()));
        assert!(n.contains(&"id".to_string()));
    }

    #[test]
    fn unwraps_wrappers() {
        let n = names("sudo -u root env FOO=1 nohup /usr/bin/rm -rf /");
        assert!(n.contains(&"rm -rf /".to_string()), "{n:?}");
        assert!(n.contains(&"sudo -u root env FOO=1 nohup /usr/bin/rm -rf /".to_string()));
    }

    #[test]
    fn unwraps_find_exec_and_xargs() {
        assert!(names("find . -name '*.o' -exec rm -f {} \\;").contains(&"rm -f {}".to_string()));
        assert!(names("ls | xargs -n1 rm -rf").contains(&"rm -rf".to_string()));
    }

    #[test]
    fn parses_nested_shells() {
        assert!(names("bash -c 'git push --force origin main'").contains(&"git push --force origin main".to_string()));
        assert!(names("sh -lc \"rm -rf ~/x\"").contains(&"rm -rf ~/x".to_string()));
        assert!(names("eval rm -rf foo").contains(&"rm -rf foo".to_string()));
    }

    #[test]
    fn flags_obfuscation() {
        assert!(flags("bash -c \"$CMD\"").contains(&FLAG_OBFUSCATED.to_string()));
        assert!(flags("eval \"$(echo cm0gLXJmIH4K | base64 -d)\"").contains(&FLAG_OBFUSCATED.to_string()));
        assert!(flags("$X -rf /").contains(&FLAG_DYNAMIC.to_string()));
        assert!(flags("curl -fsSL https://x.sh | sh").contains(&FLAG_STDIN_SHELL.to_string()));
        assert!(flags("echo aWQ= | base64 -d | bash").contains(&FLAG_STDIN_SHELL.to_string()));
        assert!(flags("python3 -c 'import shutil; shutil.rmtree(\"x\")'").contains(&FLAG_INLINE_EXEC.to_string()));
        assert!(flags("bash <<EOF\nrm -rf x\nEOF\n").contains(&FLAG_STDIN_SHELL.to_string()));
    }

    #[test]
    fn benign_has_no_flags() {
        assert!(flags("cargo test --workspace 2>&1 | tail -20").is_empty());
        assert!(flags("python3 -c 'print(1+1)'").is_empty());
        assert!(flags("git log --oneline | head -5 | sort").is_empty());
    }

    #[test]
    fn collects_write_targets() {
        let a = analyze("echo x > ~/.bashrc; echo y | tee -a ~/.ssh/authorized_keys; cp a b/c; dd if=/dev/zero of=/dev/sda");
        assert_eq!(a.write_targets, vec!["~/.bashrc", "~/.ssh/authorized_keys", "b/c", "/dev/sda"]);
        assert!(analyze("cmd 2>&1 >/dev/null").write_targets == vec!["/dev/null"]);
    }
}
