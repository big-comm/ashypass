//! Pre-format wipe.
//!
//! For a fresh LUKS2 install, the *physical* sectors outside the LUKS data
//! region (and arguably inside it too, before the first write) still hold
//! whatever plaintext the device had previously. An attacker who later
//! recovers the disk can carve old files even though the LUKS header is
//! intact. We close that gap before formatting.
//!
//! ## Strategy: throwaway-key plain-mode wipe
//!
//! The naive approach — `dd if=/dev/urandom of=/dev/sdX` — is correct but
//! slow: throughput is bounded by `getrandom(2)`, typically 200–400 MB/s on a
//! modern CPU. The throughput-optimal alternative is to open the device as
//! a plain dm-crypt mapping with a key read from `/dev/urandom`, then write
//! zeros through that mapping. The kernel encrypts the zeros with AES-NI,
//! producing ciphertext that is indistinguishable from random — at SSD/NVMe
//! line rate (GB/s on modern hardware).
//!
//! For SSDs that expose secure-erase via TRIM, `blkdiscard -s` is even
//! faster (microseconds), but its guarantees depend on firmware honoring
//! the SECURITY ERASE UNIT command. We offer it as an explicit opt-in.

use crate::runner::{CommandSpec, Runner};
use crate::{Error, Result};
use std::path::Path;

/// Read the cumulative bytes-written counter for `device` from
/// `/proc/diskstats`. `device` may be `/dev/sda`, a `/dev/disk/by-id/...`
/// symlink, or `/dev/mapper/...`. Returns `None` if the device cannot be
/// located in diskstats (e.g. a loop device that just appeared).
///
/// We deliberately *don't* parse the dd subprocess's stderr for progress:
/// the chain `dd → sudo → our pipe` is subject to buffering surprises
/// (especially when sudo allocates a pty). The kernel's diskstats counter
/// is updated on every completed write and is impossible to buffer-out-of.
pub fn read_written_bytes(device: &Path) -> Option<u64> {
    let canonical = std::fs::canonicalize(device).ok()?;
    let dev_name = canonical.file_name()?.to_str()?.to_string();
    let contents = std::fs::read_to_string("/proc/diskstats").ok()?;
    for line in contents.lines() {
        // /proc/diskstats layout (kernel ≥ 4.18):
        //   major minor name reads_completed reads_merged sectors_read time_reading
        //   writes_completed writes_merged sectors_written time_writing ...
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        if fields[2] == dev_name {
            // Sector size is conventionally 512 in diskstats, regardless
            // of the actual physical sector size.
            let sectors: u64 = fields[9].parse().ok()?;
            return Some(sectors * 512);
        }
    }
    None
}

/// Run `body` while polling `/proc/diskstats` for the device's
/// bytes-written counter on a background thread. `on_bytes` is called from
/// the main thread (so it doesn't need `Send`), at a fixed 200 ms cadence.
/// Returns whatever `body` returned.
fn with_progress_poller<R: Send>(
    device: &Path,
    on_bytes: &mut dyn FnMut(u64),
    body: impl FnOnce() -> R + Send,
) -> R {
    use std::sync::atomic::{AtomicBool, Ordering};
    let stopped = AtomicBool::new(false);
    let baseline = read_written_bytes(device).unwrap_or(0);

    std::thread::scope(|s| {
        let worker = s.spawn(|| {
            let r = body();
            stopped.store(true, Ordering::Relaxed);
            r
        });
        while !stopped.load(Ordering::Relaxed) {
            if let Some(total) = read_written_bytes(device) {
                on_bytes(total.saturating_sub(baseline));
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        // One final read so the bar lands at the true terminal value.
        if let Some(total) = read_written_bytes(device) {
            on_bytes(total.saturating_sub(baseline));
        }
        worker.join().expect("dd worker thread panicked")
    })
}

/// Parse the byte counter out of a `dd status=progress` line.
///
/// dd lines look like:
///   `123456 bytes (123 kB, 121 KiB) copied, 0.5 s, 246 kB/s`
/// We just want the first run of digits.
pub fn parse_dd_bytes(line: &str) -> Option<u64> {
    let trimmed = line.trim_start();
    let digits: String = trimmed.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    let rest = &trimmed[digits.len()..];
    if !rest.starts_with(" bytes") {
        return None;
    }
    digits.parse().ok()
}

#[derive(Debug, Clone, Copy)]
pub enum WipeMode {
    /// Plain-mode dm-crypt with a random throwaway key, then zeros piped
    /// through the mapping. Fast, indistinguishable from random output.
    EncryptedZero,
    /// `blkdiscard -s` (SSD/NVMe only). Verifies the device advertises the
    /// secure-discard capability; falls back to error if it does not.
    SecureDiscard,
    /// Single pass of `/dev/urandom`. Slowest, no kernel dependency on
    /// dm-crypt being usable at wipe time.
    Random,
    /// Skip the wipe. Callers must surface a clear warning that previously
    /// written plaintext outside LUKS-managed sectors may survive.
    None,
}

const WIPE_MAPPER: &str = "ashypass_wipe_tmp";

pub fn wipe(runner: &dyn Runner, device: &Path, mode: WipeMode) -> Result<()> {
    wipe_with_progress(runner, device, mode, &mut |_| {})
}

/// Same as [`wipe`], but invokes `on_bytes` periodically with the running
/// count of bytes that have been written. Use for live progress reporting.
/// `on_bytes` is called on the same thread that drives the wipe — keep it
/// fast (no blocking work).
pub fn wipe_with_progress(
    runner: &dyn Runner,
    device: &Path,
    mode: WipeMode,
    on_bytes: &mut dyn FnMut(u64),
) -> Result<()> {
    match mode {
        WipeMode::None => Ok(()),
        WipeMode::Random => wipe_random(runner, device, on_bytes),
        WipeMode::EncryptedZero => wipe_encrypted_zero(runner, device, on_bytes),
        WipeMode::SecureDiscard => wipe_secure_discard(runner, device),
    }
}

fn wipe_random(runner: &dyn Runner, device: &Path, on_bytes: &mut dyn FnMut(u64)) -> Result<()> {
    let spec = CommandSpec::new("dd")
        .arg("if=/dev/urandom")
        .arg(format!("of={}", device.display()))
        .arg("bs=4M")
        .arg("conv=fsync")
        .arg("status=none");
    let expected = block_device_size(device);
    let mut observed = 0;
    let result = with_progress_poller(
        device,
        &mut |bytes| {
            observed = bytes;
            on_bytes(bytes);
        },
        || runner.run(spec),
    );
    tolerate_expected_device_full(result, observed, expected).map(|_| ())
}

fn wipe_secure_discard(runner: &dyn Runner, device: &Path) -> Result<()> {
    let spec = CommandSpec::new("blkdiscard")
        .arg("--secure")
        .arg(device.to_string_lossy().into_owned());
    runner.run(spec).map(|_| ())
}

fn wipe_encrypted_zero(
    runner: &dyn Runner,
    device: &Path,
    on_bytes: &mut dyn FnMut(u64),
) -> Result<()> {
    // 1. Open device as plain dm-crypt with a random throwaway key.
    //    We read exactly 64 random bytes (= 512-bit AES-XTS key) ourselves
    //    and feed them via stdin (`--key-file -`). This is more robust than
    //    pointing cryptsetup at `/dev/urandom` directly: depending on the
    //    cryptsetup version, `--keyfile-size` can be ignored for special
    //    files and cryptsetup ends up reading urandom forever.
    use std::io::Read as _;
    let mut key_bytes = vec![0u8; 64];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut key_bytes))
        .map_err(Error::Io)?;
    let open = CommandSpec::new("cryptsetup")
        .arg("open")
        .arg("--type")
        .arg("plain")
        .arg("--cipher")
        .arg("aes-xts-plain64")
        .arg("--key-size")
        .arg("512")
        .arg("--key-file")
        .arg("-")
        .arg(device.to_string_lossy().into_owned())
        .arg(WIPE_MAPPER)
        .with_stdin(key_bytes);
    runner.run(open)?;

    // 2. Write zeros across the mapping. The kernel encrypts them on the way
    //    out, so the disk sees indistinguishable-from-random ciphertext.
    //    Progress comes from `/proc/diskstats` polled in `with_progress_poller`;
    //    we therefore disable dd's own status output (which gets buffered by
    //    sudo's pty layer and never reaches us reliably).
    let zero = CommandSpec::new("dd")
        .arg("if=/dev/zero")
        .arg(format!("of=/dev/mapper/{WIPE_MAPPER}"))
        .arg("bs=4M")
        .arg("conv=fsync")
        .arg("status=none");
    let expected = block_device_size(device);
    let mut observed = 0;
    let dd_result = with_progress_poller(
        device,
        &mut |bytes| {
            observed = bytes;
            on_bytes(bytes);
        },
        || runner.run(zero),
    );

    // 3. Always tear down the mapping, even if dd failed.
    let close = CommandSpec::new("cryptsetup").arg("close").arg(WIPE_MAPPER);
    let close_result = runner.run(close);

    // dd is expected to terminate with ENOSPC once it fills the device — dd
    // surfaces that as exit code 1, but every preceding sector has been
    // written. We tolerate that specific case.
    match tolerate_expected_device_full(dd_result, observed, expected) {
        Ok(_) => {}
        Err(e) => {
            let _ = close_result;
            return Err(e);
        }
    }
    close_result.map(|_| ())
}

fn block_device_size(device: &Path) -> Option<u64> {
    let canonical = std::fs::canonicalize(device).ok()?;
    let name = canonical.file_name()?.to_str()?;
    let sectors = std::fs::read_to_string(format!("/sys/class/block/{name}/size"))
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()?;
    sectors.checked_mul(512)
}

fn tolerate_expected_device_full(
    result: Result<crate::runner::CommandOutput>,
    observed: u64,
    expected: Option<u64>,
) -> Result<crate::runner::CommandOutput> {
    match result {
        Err(Error::CommandFailed {
            status: 1, stderr, ..
        }) if stderr.to_ascii_lowercase().contains("no space left")
            && expected.is_some_and(|size| {
                let tolerance = (size / 100).clamp(1, 8 * 1024 * 1024);
                observed >= size.saturating_sub(tolerance)
            }) =>
        {
            log::debug!("dd reached the verified end of the block device");
            Ok(crate::runner::CommandOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dd_progress_line() {
        assert_eq!(
            parse_dd_bytes("123456 bytes (123 kB, 121 KiB) copied, 0.5 s, 246 kB/s"),
            Some(123456)
        );
        assert_eq!(
            parse_dd_bytes("4194304000 bytes (4.2 GB, 3.9 GiB) copied, 60 s, 69.9 MB/s"),
            Some(4194304000)
        );
        assert_eq!(parse_dd_bytes("0+1 records in"), None);
        assert_eq!(
            parse_dd_bytes("dd: writing to '/dev/sda': No space left"),
            None
        );
        assert_eq!(parse_dd_bytes(""), None);
    }

    #[test]
    fn only_tolerates_verified_enospc() {
        let error = || Error::CommandFailed {
            cmd: "dd".into(),
            status: 1,
            stderr: "No space left on device".into(),
        };
        assert!(tolerate_expected_device_full(Err(error()), 992, Some(1000)).is_ok());
        assert!(tolerate_expected_device_full(Err(error()), 1, Some(1000)).is_err());
        assert!(tolerate_expected_device_full(Err(error()), 1000, None).is_err());
    }
}
