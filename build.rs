use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    let version = env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>dev.touchgate.cli</string>
  <key>CFBundleName</key>
  <string>touchgate</string>
  <key>CFBundleShortVersionString</key>
  <string>{version}</string>
  <key>NSFaceIDUsageDescription</key>
  <string>touchgate asks before an ai agent does something risky</string>
</dict>
</plist>
"#
    );
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("Info.plist");
    fs::write(&out, plist).unwrap();
    println!("cargo:rustc-link-arg-bins=-Wl,-sectcreate,__TEXT,__info_plist,{}", out.display());
}
