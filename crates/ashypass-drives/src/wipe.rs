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

    /// Sets the flag when dropped, so the poll loop ends even if `body`
    /// panics (otherwise the scope would wait on the loop forever).
    struct StopOnDrop<'a>(&'a AtomicBool);
    impl Drop for StopOnDrop<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    let stopped = AtomicBool::new(false);
    let baseline = read_written_bytes(device).unwrap_or(0);

    std::thread::scope(|s| {
        let worker = s.spawn(|| {
            let _stop = StopOnDrop(&stopped);
            body()
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
        worker
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
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
    /// Skip the full wipe. Only the old signatures are cleared (`wipefs -a`
    /// plus the last MiB, where the backup GPT lives; the first MiB is
    /// overwritten by the LUKS2 header). Callers must surface a clear warning
    /// that previously written plaintext may survive.
    None,
}

const WIPE_MAPPER: &str = "ashypass_wipe_tmp";

/// True for mapper names the wipe step creates (`ashypass_wipe_tmp` and its
/// device-tagged variants).
pub fn is_wipe_mapper(name: &str) -> bool {
    name == WIPE_MAPPER || name.starts_with(&format!("{WIPE_MAPPER}_"))
}

/// Candidate wipe mapper names for `device`, in preference order.
fn wipe_mapper_candidates(device: &Path) -> Vec<String> {
    let tag = crate::mapper::device_tag(device, None);
    vec![
        WIPE_MAPPER.to_string(),
        format!("{WIPE_MAPPER}_{}", sanitize_tag(&tag)),
    ]
}

fn sanitize_tag(tag: &str) -> String {
    tag.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(32)
        .collect()
}

/// Pick the wipe mapper for `device`. A mapping left behind by an
/// interrupted run on the **same** device is closed and reused; a mapping
/// that belongs to another device is never touched (a device-specific name
/// is used instead).
fn prepare_wipe_mapper(runner: &dyn Runner, device: &Path) -> Result<String> {
    let node = std::fs::canonicalize(device).map_err(Error::Io)?;
    let (name, state) = crate::mapper::pick_mapper(&wipe_mapper_candidates(&node), |name| {
        crate::mapper::mapper_state(name, &node)
    })?;
    if state == crate::mapper::MapperState::SameDevice {
        log::warn!("closing stale wipe mapping /dev/mapper/{name}");
        runner.run(
            CommandSpec::new("cryptsetup")
                .arg("close")
                .arg(name.clone()),
        )?;
    }
    Ok(name)
}

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
        WipeMode::None => clear_signatures(runner, device),
        WipeMode::Random => wipe_random(runner, device, on_bytes),
        WipeMode::EncryptedZero => wipe_encrypted_zero(runner, device, on_bytes),
        WipeMode::SecureDiscard => wipe_secure_discard(runner, device),
    }
}

/// Bytes zeroed at the end of the device in quick mode. Covers the backup
/// GPT header and entry array (16 KiB + 512 B) with ample margin.
const TAIL_ZERO_BYTES: u64 = 1024 * 1024;

/// Quick mode: `luksFormat` only rewrites the start of the disk, so the
/// backup GPT at the end survives and tools (and some firmware) would keep
/// "seeing" the old partitions and offer to repair them. Clear every known
/// signature and zero the last MiB.
fn clear_signatures(runner: &dyn Runner, device: &Path) -> Result<()> {
    let size = match block_device_size(device) {
        Some(size) => size,
        None => query_device_size(runner, device)?,
    };
    clear_signatures_with_size(runner, device, size)
}

fn clear_signatures_with_size(runner: &dyn Runner, device: &Path, size: u64) -> Result<()> {
    runner.run(
        CommandSpec::new("wipefs")
            .arg("--all")
            .arg(device.to_string_lossy().into_owned()),
    )?;
    runner.run(build_tail_zero_spec(device, size)?)?;
    Ok(())
}

/// `dd` that zeroes the last [`TAIL_ZERO_BYTES`] of a device of `size`
/// bytes (the whole device if it is smaller). Block devices are always a
/// multiple of 512 bytes, which is the block size used here.
fn build_tail_zero_spec(device: &Path, size: u64) -> Result<CommandSpec> {
    const BS: u64 = 512;
    if size == 0 || !size.is_multiple_of(BS) {
        return Err(Error::Refused(format!(
            "unexpected size for {}: {size} bytes",
            device.display()
        )));
    }
    let count = TAIL_ZERO_BYTES.min(size) / BS;
    let seek = size / BS - count;
    Ok(CommandSpec::new("dd")
        .arg("if=/dev/zero")
        .arg(format!("of={}", device.display()))
        .arg(format!("bs={BS}"))
        .arg(format!("seek={seek}"))
        .arg(format!("count={count}"))
        .arg("conv=fsync")
        .arg("status=none"))
}

fn query_device_size(runner: &dyn Runner, device: &Path) -> Result<u64> {
    let out = runner.run(
        CommandSpec::new("blockdev")
            .arg("--getsize64")
            .arg(device.to_string_lossy().into_owned()),
    )?;
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .map_err(|_| Error::Refused(format!("could not read the size of {}", device.display())))
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
    let mapper = prepare_wipe_mapper(runner, device)?;

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
        .arg(mapper.clone())
        .with_stdin(key_bytes);
    runner.run(open)?;

    // 2. Write zeros across the mapping. The kernel encrypts them on the way
    //    out, so the disk sees indistinguishable-from-random ciphertext.
    //    Progress comes from `/proc/diskstats` polled in `with_progress_poller`;
    //    we therefore disable dd's own status output (which gets buffered by
    //    sudo's pty layer and never reaches us reliably).
    let zero = CommandSpec::new("dd")
        .arg("if=/dev/zero")
        .arg(format!("of=/dev/mapper/{mapper}"))
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

    // 3. Always tear down the mapping, even if dd failed. udev probes the
    //    freshly written mapping, so wait for it and retry while busy.
    let close_result = crate::luks::luks_close_settled(runner, &mapper);

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
    close_result
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
    fn wipe_mapper_names() {
        assert!(is_wipe_mapper("ashypass_wipe_tmp"));
        assert!(is_wipe_mapper("ashypass_wipe_tmp_sdb"));
        assert!(!is_wipe_mapper("ashypass_vault"));
        assert!(!is_wipe_mapper("ashypass_wipe_tmpfoo"));
        let candidates = wipe_mapper_candidates(Path::new("/dev/sdb"));
        assert_eq!(candidates, ["ashypass_wipe_tmp", "ashypass_wipe_tmp_sdb"]);
        for name in &candidates {
            assert!(is_wipe_mapper(name));
            crate::validate::validate_mapper_name(name).unwrap();
        }
    }

    #[test]
    fn stale_wipe_mapper_of_another_device_is_not_reused() {
        use crate::mapper::{pick_mapper, MapperState};
        let candidates = wipe_mapper_candidates(Path::new("/dev/sdb"));
        // Stale mapping on the same device: reuse (after closing it).
        let (name, state) = pick_mapper(&candidates, |n| {
            if n == WIPE_MAPPER {
                MapperState::SameDevice
            } else {
                MapperState::Free
            }
        })
        .unwrap();
        assert_eq!(
            (name.as_str(), state),
            (WIPE_MAPPER, MapperState::SameDevice)
        );
        // Mapping held by another device: fall back to the tagged name.
        let (name, state) = pick_mapper(&candidates, |n| {
            if n == WIPE_MAPPER {
                MapperState::OtherDevice
            } else {
                MapperState::Free
            }
        })
        .unwrap();
        assert_eq!(
            (name.as_str(), state),
            ("ashypass_wipe_tmp_sdb", MapperState::Free)
        );
    }

    #[test]
    fn quick_mode_clears_signatures_and_the_backup_gpt() {
        use crate::runner::fake::FakeRunner;
        // A path with no sysfs entry: the size comes from `blockdev`.
        let device = Path::new("/dev/disk/by-id/usb-ashypass-test-missing-0:0");
        let runner = FakeRunner::default().stdout("8053063680\n");
        wipe(&runner, device, WipeMode::None).unwrap();
        let sectors = 8_053_063_680u64 / 512;
        assert_eq!(
            runner.calls(),
            [
                format!("blockdev --getsize64 {}", device.display()),
                format!("wipefs --all {}", device.display()),
                format!(
                    "dd if=/dev/zero of={} bs=512 seek={} count=2048 conv=fsync status=none",
                    device.display(),
                    sectors - 2048
                ),
            ]
        );
    }

    #[test]
    fn tail_zero_covers_tiny_devices_and_rejects_odd_sizes() {
        let device = Path::new("/dev/sdz");
        let tiny = build_tail_zero_spec(device, 64 * 1024).unwrap();
        assert!(tiny.args.contains(&"seek=0".to_string()), "{:?}", tiny.args);
        assert!(
            tiny.args.contains(&"count=128".to_string()),
            "{:?}",
            tiny.args
        );
        assert!(build_tail_zero_spec(device, 0).is_err());
        assert!(build_tail_zero_spec(device, 1000).is_err());
    }

    #[test]
    fn quick_mode_stops_when_wipefs_fails() {
        use crate::runner::fake::FakeRunner;
        let runner = FakeRunner::default().reply(Err(Error::CommandFailed {
            cmd: "wipefs".into(),
            status: 1,
            stderr: "probing initialization failed: Device or resource busy".into(),
        }));
        let device = Path::new("/dev/sdz");
        assert!(clear_signatures_with_size(&runner, device, 1 << 30).is_err());
        assert_eq!(runner.calls(), ["wipefs --all /dev/sdz"]);
    }

    #[test]
    fn progress_poller_stops_when_the_worker_panics() {
        let device = Path::new("/dev/ashypass-test-missing");
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            with_progress_poller(device, &mut |_| {}, || -> u8 { panic!("dd worker") })
        }));
        // Without the guard the poll loop would spin forever.
        assert!(outcome.is_err());
        assert_eq!(with_progress_poller(device, &mut |_| {}, || 7), 7);
    }

    #[test]
    fn encrypted_zero_closes_the_wipe_mapping_through_udev_settle() {
        use crate::runner::fake::FakeRunner;
        // Nothing runs: the fake runner only records the commands. /dev/null
        // stands in for a device that exists but backs no mapping.
        let runner = FakeRunner::default();
        wipe(&runner, Path::new("/dev/null"), WipeMode::EncryptedZero).unwrap();
        let calls = runner.calls();
        let close = calls.last().unwrap();
        assert!(
            close.starts_with("cryptsetup close ashypass_wipe_tmp"),
            "{calls:?}"
        );
        assert_eq!(calls[calls.len() - 2], "udevadm settle --timeout=10");
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
