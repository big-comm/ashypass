//! Subprocess abstraction so destructive operations can be unit-tested.
//!
//! Production uses [`PkexecRunner`], which prepends `pkexec` so polkit handles
//! authentication and the GUI password prompt. Tests use a fake `Runner` that
//! captures argv without spawning anything.

use crate::passphrase::Passphrase;
use crate::{Error, Result};
use std::fmt;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use zeroize::Zeroize;

pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    /// Optional bytes to write to the child's stdin. Used for passphrases.
    pub stdin_bytes: Option<Vec<u8>>,
    /// If true, let the child's stderr stream straight to the parent's
    /// terminal instead of capturing it. Used for long-running tools that
    /// emit progress to stderr (e.g. `dd status=progress`).
    pub inherit_stderr: bool,
}

impl fmt::Debug for CommandSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandSpec")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("stdin_bytes", &self.stdin_bytes.as_ref().map(Vec::len))
            .field("inherit_stderr", &self.inherit_stderr)
            .finish()
    }
}

impl Drop for CommandSpec {
    fn drop(&mut self) {
        if let Some(bytes) = self.stdin_bytes.as_mut() {
            bytes.zeroize();
        }
    }
}

impl CommandSpec {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            stdin_bytes: None,
            inherit_stderr: false,
        }
    }
    pub fn inherit_stderr(mut self) -> Self {
        self.inherit_stderr = true;
        self
    }
    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }
    pub fn args<I, S>(mut self, it: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(it.into_iter().map(Into::into));
        self
    }
    pub fn with_stdin(mut self, bytes: Vec<u8>) -> Self {
        self.stdin_bytes = Some(bytes);
        self
    }
    pub fn with_passphrase(self, p: &Passphrase) -> Self {
        self.with_stdin(p.as_bytes().to_vec())
    }
}

pub trait Runner: Send + Sync {
    fn run(&self, spec: CommandSpec) -> Result<CommandOutput>;

    /// Like [`run`], but invokes `on_stderr_chunk` for every newline- or
    /// carriage-return-terminated chunk written to stderr. Used to drive
    /// progress UIs from tools that emit live updates to stderr
    /// (e.g. `dd status=progress`).
    ///
    /// Default implementation falls back to non-streaming `run` — concrete
    /// `Runner`s should override.
    fn run_streaming(
        &self,
        spec: CommandSpec,
        on_stderr_chunk: &mut dyn FnMut(&str),
    ) -> Result<CommandOutput> {
        let _ = on_stderr_chunk;
        self.run(spec)
    }
}

#[derive(Debug)]
pub struct CommandOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Runs commands directly, no privilege elevation. Used for non-privileged
/// helpers (`lsblk`, `udevadm info`).
pub struct PlainRunner;

impl Runner for PlainRunner {
    fn run(&self, spec: CommandSpec) -> Result<CommandOutput> {
        execute(
            &spec.program,
            &spec.args,
            spec.stdin_bytes.as_deref(),
            spec.inherit_stderr,
        )
    }
    fn run_streaming(
        &self,
        spec: CommandSpec,
        on_stderr_chunk: &mut dyn FnMut(&str),
    ) -> Result<CommandOutput> {
        execute_streaming(
            &spec.program,
            &spec.args,
            spec.stdin_bytes.as_deref(),
            on_stderr_chunk,
        )
    }
}

/// Runs commands via `sudo -n` first; if that fails, falls back to an
/// interactive `sudo` so the user gets a single password prompt for the
/// whole session (sudo caches the credential via its timestamp file).
/// Used by the CLI when the process is not already root.
pub struct SudoRunner;

impl Runner for SudoRunner {
    fn run(&self, spec: CommandSpec) -> Result<CommandOutput> {
        let mut argv = Vec::with_capacity(spec.args.len() + 2);
        argv.push("--".to_string());
        argv.push(spec.program.clone());
        argv.extend(spec.args.iter().cloned());
        execute(
            "sudo",
            &argv,
            spec.stdin_bytes.as_deref(),
            spec.inherit_stderr,
        )
    }
    fn run_streaming(
        &self,
        spec: CommandSpec,
        on_stderr_chunk: &mut dyn FnMut(&str),
    ) -> Result<CommandOutput> {
        let mut argv = Vec::with_capacity(spec.args.len() + 2);
        argv.push("--".to_string());
        argv.push(spec.program.clone());
        argv.extend(spec.args.iter().cloned());
        execute_streaming("sudo", &argv, spec.stdin_bytes.as_deref(), on_stderr_chunk)
    }
}

/// Picks the right runner for the current process: `PlainRunner` if we are
/// already uid 0, `SudoRunner` otherwise. Keeps CLI call sites uniform.
pub fn auto_runner() -> Box<dyn Runner> {
    // SAFETY: getuid is async-signal-safe and always succeeds.
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        Box::new(PlainRunner)
    } else {
        Box::new(SudoRunner)
    }
}

/// Runs commands via `pkexec`, triggering the polkit prompt configured by
/// our policy file. Reserved for the GUI; the CLI uses `SudoRunner`.
pub struct PkexecRunner;

impl Runner for PkexecRunner {
    fn run(&self, spec: CommandSpec) -> Result<CommandOutput> {
        let mut argv = Vec::with_capacity(spec.args.len() + 1);
        argv.push(spec.program.clone());
        argv.extend(spec.args.iter().cloned());
        execute(
            "pkexec",
            &argv,
            spec.stdin_bytes.as_deref(),
            spec.inherit_stderr,
        )
    }
    fn run_streaming(
        &self,
        spec: CommandSpec,
        on_stderr_chunk: &mut dyn FnMut(&str),
    ) -> Result<CommandOutput> {
        let mut argv = Vec::with_capacity(spec.args.len() + 1);
        argv.push(spec.program.clone());
        argv.extend(spec.args.iter().cloned());
        execute_streaming(
            "pkexec",
            &argv,
            spec.stdin_bytes.as_deref(),
            on_stderr_chunk,
        )
    }
}

fn execute(
    program: &str,
    args: &[String],
    stdin_bytes: Option<&[u8]>,
    inherit_stderr: bool,
) -> Result<CommandOutput> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    if stdin_bytes.is_some() {
        cmd.stdin(Stdio::piped());
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(if inherit_stderr {
        Stdio::inherit()
    } else {
        Stdio::piped()
    });

    let mut child = cmd.spawn().map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Error::MissingTool(program.to_string()),
        _ => Error::Io(e),
    })?;

    if let (Some(bytes), Some(mut stdin)) = (stdin_bytes, child.stdin.take()) {
        stdin.write_all(bytes)?;
        stdin.flush()?;
        drop(stdin);
    }

    let output = child.wait_with_output()?;
    if !output.status.success() {
        let display_cmd = format!("{} {}", program, args.join(" "));
        return Err(Error::CommandFailed {
            cmd: display_cmd,
            status: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(CommandOutput {
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

/// Streaming variant of [`execute`]: reads the child's stderr incrementally
/// and invokes `on_stderr_chunk` for every newline- or carriage-return-
/// delimited chunk. The full stderr is still accumulated for error reporting
/// in case the process exits non-zero.
fn execute_streaming(
    program: &str,
    args: &[String],
    stdin_bytes: Option<&[u8]>,
    on_stderr_chunk: &mut dyn FnMut(&str),
) -> Result<CommandOutput> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    if stdin_bytes.is_some() {
        cmd.stdin(Stdio::piped());
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Error::MissingTool(program.to_string()),
        _ => Error::Io(e),
    })?;

    if let (Some(bytes), Some(mut stdin)) = (stdin_bytes, child.stdin.take()) {
        stdin.write_all(bytes)?;
        stdin.flush()?;
        drop(stdin);
    }

    let stderr = child.stderr.take().expect("stderr was piped");
    let mut reader = BufReader::new(stderr);
    let mut chunk = Vec::new();
    let mut all_stderr = Vec::new();

    // Read until `\r` first — that's what `dd status=progress` uses to
    // overwrite the same line. Then read until `\n` for tools that only
    // emit newlines. `read_until` returns 0 on EOF.
    loop {
        chunk.clear();
        let n = reader.read_until(b'\r', &mut chunk).map_err(Error::Io)?;
        if n == 0 {
            break;
        }
        all_stderr.extend_from_slice(&chunk);
        // Strip the trailing \r and any embedded \n so the callback sees a
        // clean line.
        let trimmed_end = chunk
            .iter()
            .rposition(|b| *b != b'\r' && *b != b'\n')
            .map(|i| i + 1)
            .unwrap_or(0);
        let trimmed = &chunk[..trimmed_end];
        // dd progress updates are on a single line; tools that emit
        // multi-line stderr (e.g. cryptsetup errors) get split here too.
        for line in trimmed.split(|b| *b == b'\n') {
            if line.is_empty() {
                continue;
            }
            if let Ok(s) = std::str::from_utf8(line) {
                on_stderr_chunk(s);
            }
        }
    }

    // Drain anything left and capture stdout.
    let output = child.wait_with_output()?;
    all_stderr.extend_from_slice(&output.stderr);
    if !output.status.success() {
        return Err(Error::CommandFailed {
            cmd: format!("{} {}", program, args.join(" ")),
            status: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&all_stderr).into_owned(),
        });
    }
    Ok(CommandOutput {
        stdout: output.stdout,
        stderr: all_stderr,
    })
}
