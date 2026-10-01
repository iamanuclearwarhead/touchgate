use std::fs::OpenOptions;
use std::io::Write;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use notify_rust::{Notification, Timeout, Urgency};
use zbus::blocking::Connection;
use zbus::proxy;
use zbus::zvariant::OwnedObjectPath;

use crate::{AuthResult, DeviceInfo, Prompt, Verifier};

const MAX_ATTEMPTS: u32 = 3;

#[proxy(
    interface = "net.reactivated.Fprint.Manager",
    default_service = "net.reactivated.Fprint",
    default_path = "/net/reactivated/Fprint/Manager"
)]
trait Manager {
    fn get_default_device(&self) -> zbus::Result<OwnedObjectPath>;
}

#[proxy(interface = "net.reactivated.Fprint.Device", default_service = "net.reactivated.Fprint")]
trait Device {
    fn claim(&self, username: &str) -> zbus::Result<()>;
    fn release(&self) -> zbus::Result<()>;
    fn verify_start(&self, finger_name: &str) -> zbus::Result<()>;
    fn verify_stop(&self) -> zbus::Result<()>;
    fn list_enrolled_fingers(&self, username: &str) -> zbus::Result<Vec<String>>;
    #[zbus(signal)]
    fn verify_status(&self, result: &str, done: bool) -> zbus::Result<()>;
    #[zbus(property, name = "name")]
    fn name(&self) -> zbus::Result<String>;
}

pub struct Fprintd;

fn device(conn: &Connection) -> Result<DeviceProxyBlocking<'static>, String> {
    let manager = ManagerProxyBlocking::new(conn).map_err(describe)?;
    let path = manager.get_default_device().map_err(describe)?;
    DeviceProxyBlocking::builder(conn)
        .path(path)
        .map_err(describe)?
        .build()
        .map_err(describe)
}

fn describe(e: zbus::Error) -> String {
    let s = e.to_string();
    if s.contains("NoSuchDevice") {
        "no fingerprint reader found".into()
    } else if s.contains("AlreadyInUse") {
        "fingerprint reader is busy, probably the lock screen or another prompt".into()
    } else if s.contains("PermissionDenied") || s.contains("NotAuthorized") {
        "polkit refused fingerprint access, touchgate needs an active local session".into()
    } else if s.contains("NoEnrolledPrints") {
        "no fingerprints enrolled, run fprintd-enroll".into()
    } else if s.contains("ServiceUnknown") || s.contains("was not provided by any") {
        "fprintd is not installed or not running".into()
    } else {
        s
    }
}

fn status_text(r: &str) -> &'static str {
    match r {
        "verify-no-match" => "fingerprint did not match",
        "verify-retry-scan" => "scan again",
        "verify-swipe-too-short" => "swipe was too short",
        "verify-finger-not-centered" => "finger not centered",
        "verify-remove-and-retry" => "lift your finger and try again",
        "verify-disconnected" => "fingerprint reader disconnected",
        _ => "fingerprint check failed",
    }
}

fn tty_note(msg: &str) {
    if let Ok(mut t) = OpenOptions::new().write(true).open("/dev/tty") {
        let _ = writeln!(t, "\r\n\x1b[1;33mtouchgate\x1b[0m {msg}\r");
    }
}

impl Verifier for Fprintd {
    fn backend(&self) -> &'static str {
        "fprintd"
    }

    fn probe(&self) -> Result<DeviceInfo, String> {
        let conn = Connection::system().map_err(describe)?;
        let dev = device(&conn)?;
        let name = dev.name().unwrap_or_else(|_| "fingerprint reader".into());
        let enrolled = dev.list_enrolled_fingers("").map_err(describe)?;
        Ok(DeviceInfo { name, enrolled })
    }

    fn verify(&self, prompt: &Prompt) -> AuthResult {
        match run(prompt) {
            Ok(r) => r,
            Err(e) => AuthResult::Rejected(e),
        }
    }
}

fn run(prompt: &Prompt) -> Result<AuthResult, String> {
    let conn = Connection::system().map_err(describe)?;
    let dev = device(&conn)?;
    dev.claim("").map_err(describe)?;

    let body = format!("{}\n\n{}\n\ntouch the sensor to allow, or wait to deny", prompt.reason, prompt.action);
    let note = Notification::new()
        .appname("touchgate")
        .summary(&prompt.headline())
        .body(&body)
        .icon("auth-fingerprint-symbolic")
        .urgency(Urgency::Critical)
        .timeout(Timeout::Milliseconds(prompt.timeout.as_millis() as u32))
        .show()
        .ok();
    tty_note(&format!("{}: {}\r\n          touch the sensor to allow", prompt.reason, prompt.action));

    let result = wait(&dev, prompt.timeout);

    let _ = dev.verify_stop();
    let _ = dev.release();
    if let Some(n) = note {
        n.close();
    }
    let msg = match &result {
        Ok(AuthResult::Verified) => "approved".to_string(),
        Ok(AuthResult::Rejected(r)) => format!("denied, {r}"),
        Err(e) => format!("denied, {e}"),
    };
    tty_note(&msg);
    result
}

fn wait(dev: &DeviceProxyBlocking<'static>, timeout: Duration) -> Result<AuthResult, String> {
    let signals = dev.receive_verify_status().map_err(describe)?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for s in signals {
            if let Ok(args) = s.args() {
                if tx.send((args.result().to_string(), *args.done())).is_err() {
                    break;
                }
            }
        }
    });

    let deadline = Instant::now() + timeout;
    let mut attempts = 0;
    dev.verify_start("any").map_err(describe)?;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(AuthResult::Rejected("timed out waiting for a fingerprint".into()));
        }
        let Ok((result, done)) = rx.recv_timeout(left) else {
            return Ok(AuthResult::Rejected("timed out waiting for a fingerprint".into()));
        };
        if result == "verify-match" {
            return Ok(AuthResult::Verified);
        }
        if !done {
            continue;
        }
        if result == "verify-no-match" {
            attempts += 1;
            if attempts >= MAX_ATTEMPTS {
                return Ok(AuthResult::Rejected(format!("fingerprint did not match {MAX_ATTEMPTS} times")));
            }
            tty_note("no match, try again");
            let _ = dev.verify_stop();
            dev.verify_start("any").map_err(describe)?;
            continue;
        }
        if matches!(result.as_str(), "verify-retry-scan" | "verify-swipe-too-short" | "verify-finger-not-centered" | "verify-remove-and-retry") {
            let _ = dev.verify_stop();
            dev.verify_start("any").map_err(describe)?;
            continue;
        }
        return Ok(AuthResult::Rejected(status_text(&result).into()));
    }
}
