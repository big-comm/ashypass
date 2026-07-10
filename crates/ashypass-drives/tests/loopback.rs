use ashypass_drives::fs::{mkfs, Filesystem};
use ashypass_drives::luks::{luks_close, luks_format, luks_open, FormatOptions};
use ashypass_drives::passphrase::Passphrase;
use ashypass_drives::runner::PlainRunner;
use std::path::PathBuf;
use std::process::Command;

struct Cleanup {
    device: PathBuf,
    mapper: String,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = Command::new("cryptsetup")
            .args(["close", &self.mapper])
            .status();
        let _ = Command::new("losetup").arg("-d").arg(&self.device).status();
    }
}

#[test]
#[ignore = "requires root, cryptsetup, losetup, and ASHYPASS_LOOPBACK_TEST=1"]
fn luks_roundtrip_on_temporary_loop_device() {
    if unsafe { libc::geteuid() } != 0 || std::env::var_os("ASHYPASS_LOOPBACK_TEST").is_none() {
        eprintln!("skipped: run as root with ASHYPASS_LOOPBACK_TEST=1");
        return;
    }

    let image = tempfile::NamedTempFile::new().unwrap();
    image.as_file().set_len(256 * 1024 * 1024).unwrap();
    let output = Command::new("losetup")
        .args(["--find", "--show"])
        .arg(image.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let device = PathBuf::from(String::from_utf8(output.stdout).unwrap().trim());
    let mapper = format!("ashypass_test_{}", std::process::id());
    let _cleanup = Cleanup {
        device: device.clone(),
        mapper: mapper.clone(),
    };

    let runner = PlainRunner;
    let passphrase = Passphrase::new(b"loopback integration passphrase".to_vec());
    luks_format(
        &runner,
        &device,
        &passphrase,
        &FormatOptions {
            label: "ashypass-test".into(),
            subsystem: Some("ashypass-test".into()),
            allow_discards: false,
        },
    )
    .unwrap();
    let mapped = luks_open(&runner, &device, &mapper, &passphrase, false).unwrap();
    mkfs(&runner, &mapped, Filesystem::Ext4, "ashypass-test").unwrap();
    luks_close(&runner, &mapper).unwrap();
    luks_open(&runner, &device, &mapper, &passphrase, false).unwrap();
    luks_close(&runner, &mapper).unwrap();
}
