//! Subprocess abstraction so destructive operations can be unit-tested.
//!
//! Production uses [`PkexecRunner`], which prepends `pkexec` so polkit handles
//! authentication and the GUI password prompt. Tests use a fake `Runner` that
//! captures argv without spawning anything.

use crate::passphrase::Passphrase;
use crate::{Error, Result};
use std::fmt;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
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
    cmd.stdin(stdin_for(stdin_bytes));
    cmd.stdout(Stdio::piped());
    cmd.stderr(if inherit_stderr {
        Stdio::inherit()
    } else {
        Stdio::piped()
    });

    let mut child = spawn(&mut cmd, program)?;
    let write_error = feed_stdin(&mut child, stdin_bytes);

    let output = child.wait_with_output()?;
    let display_cmd = || format!("{} {}", program, args.join(" "));
    if let Some(error) = write_error {
        return Err(stdin_failure(
            display_cmd(),
            output.status.code(),
            &error,
            &output.stderr,
        ));
    }
    if !output.status.success() {
        return Err(Error::CommandFailed {
            cmd: display_cmd(),
            status: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(CommandOutput {
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

/// A child never inherits our stdin: in the privileged helper that is the
/// request pipe, and a tool reading from it would swallow protocol lines.
fn stdin_for(stdin_bytes: Option<&[u8]>) -> Stdio {
    if stdin_bytes.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    }
}

fn spawn(cmd: &mut Command, program: &str) -> Result<Child> {
    cmd.spawn().map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Error::MissingTool(program.to_string()),
        _ => Error::Io(e),
    })
}

/// Write `stdin_bytes` to the child and close its stdin. A failed write
/// (typically a broken pipe because the child exited early) is returned
/// instead of propagated, so the caller still reaps the child and can report
/// its stderr, which usually explains why it stopped reading.
fn feed_stdin(child: &mut Child, stdin_bytes: Option<&[u8]>) -> Option<std::io::Error> {
    let (Some(bytes), Some(mut stdin)) = (stdin_bytes, child.stdin.take()) else {
        return None;
    };
    stdin.write_all(bytes).and_then(|()| stdin.flush()).err()
}

fn stdin_failure(cmd: String, status: Option<i32>, error: &std::io::Error, stderr: &[u8]) -> Error {
    Error::CommandFailed {
        cmd,
        status: status.unwrap_or(-1),
        stderr: format!(
            "could not write to stdin: {error}; {}",
            String::from_utf8_lossy(stderr).trim()
        ),
    }
}

/// Streaming variant of [`execute`]: reads the child's stderr incrementally
/// and invokes `on_stderr_chunk` for every newline- or carriage-return-
/// delimited chunk. The full stderr is still accumulated for error reporting
/// in case the process exits non-zero. Stdout is drained on its own thread so
/// a child that fills the stdout pipe cannot deadlock us while we block on
/// stderr.
fn execute_streaming(
    program: &str,
    args: &[String],
    stdin_bytes: Option<&[u8]>,
    on_stderr_chunk: &mut dyn FnMut(&str),
) -> Result<CommandOutput> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.stdin(stdin_for(stdin_bytes));
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = spawn(&mut cmd, program)?;
    let write_error = feed_stdin(&mut child, stdin_bytes);

    let mut stdout = child.stdout.take().expect("stdout was piped");
    let stdout_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        stdout.read_to_end(&mut buf).map(|_| buf)
    });

    let stderr = child.stderr.take().expect("stderr was piped");
    let mut reader = BufReader::new(stderr);
    let mut chunk = Vec::new();
    let mut all_stderr = Vec::new();

    // Read until `\r` first — that's what `dd status=progress` uses to
    // overwrite the same line. Then read until `\n` for tools that only
    // emit newlines. `read_until` returns 0 on EOF.
    let read_result = loop {
        chunk.clear();
        let n = match reader.read_until(b'\r', &mut chunk) {
            Ok(n) => n,
            Err(e) => break Err(e),
        };
        if n == 0 {
            break Ok(());
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
    };
    // Close our end before reaping, so a child still writing to stderr gets
    // EPIPE instead of blocking forever.
    drop(reader);

    let status = child.wait()?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| Error::Io(std::io::Error::other("stdout reader panicked")))??;
    read_result?;

    let display_cmd = || format!("{} {}", program, args.join(" "));
    if let Some(error) = write_error {
        return Err(stdin_failure(
            display_cmd(),
            status.code(),
            &error,
            &all_stderr,
        ));
    }
    if !status.success() {
        return Err(Error::CommandFailed {
            cmd: display_cmd(),
            status: status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&all_stderr).into_owned(),
        });
    }
    Ok(CommandOutput {
        stdout,
        stderr: all_stderr,
    })
}

/// Fake runner for unit tests: records every argv and answers from a queue
/// of scripted results (success with empty output once the queue is empty).
#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Default)]
    pub(crate) struct FakeRunner {
        pub calls: Mutex<Vec<String>>,
        pub replies: Mutex<VecDeque<Result<CommandOutput>>>,
    }

    impl FakeRunner {
        pub(crate) fn reply(self, result: Result<CommandOutput>) -> Self {
            self.replies.lock().unwrap().push_back(result);
            self
        }

        pub(crate) fn stdout(self, text: &str) -> Self {
            self.reply(Ok(CommandOutput {
                stdout: text.as_bytes().to_vec(),
                stderr: Vec::new(),
            }))
        }

        /// Every command run so far, as `program arg1 arg2 …`.
        pub(crate) fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl Runner for FakeRunner {
        fn run(&self, spec: CommandSpec) -> Result<CommandOutput> {
            let mut line = spec.program.clone();
            for arg in &spec.args {
                line.push(' ');
                line.push_str(arg);
            }
            self.calls.lock().unwrap().push(line);
            self.replies.lock().unwrap().pop_front().unwrap_or_else(|| {
                Ok(CommandOutput {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                })
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> CommandSpec {
        CommandSpec::new("sh").arg("-c").arg(script)
    }

    #[test]
    fn children_without_input_get_an_empty_stdin() {
        // `cat` would block forever if it inherited the test harness stdin.
        let out = PlainRunner.run(CommandSpec::new("cat")).unwrap();
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn stdin_bytes_reach_the_child() {
        let out = PlainRunner
            .run(CommandSpec::new("cat").with_stdin(b"secret".to_vec()))
            .unwrap();
        assert_eq!(out.stdout, b"secret");
    }

    #[test]
    fn broken_stdin_still_reports_the_child_stderr() {
        // The child exits without reading a large input: the write fails
        // with EPIPE, and the error must still carry the child's stderr.
        let input = vec![b'x'; 4 * 1024 * 1024];
        let error = PlainRunner
            .run(sh("echo refused >&2; exit 3").with_stdin(input))
            .unwrap_err();
        match error {
            Error::CommandFailed { status, stderr, .. } => {
                assert_eq!(status, 3);
                assert!(stderr.contains("refused"), "{stderr}");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn streaming_drains_large_stdout_and_stderr_together() {
        // 1 MiB on stdout before anything on stderr: without a concurrent
        // stdout reader the child blocks on a full pipe and we hang.
        let mut lines = Vec::new();
        let out = PlainRunner
            .run_streaming(
                sh("head -c 1048576 /dev/zero; echo one >&2; echo two >&2"),
                &mut |line| lines.push(line.to_string()),
            )
            .unwrap();
        assert_eq!(out.stdout.len(), 1_048_576);
        assert_eq!(lines, ["one", "two"]);
    }

    #[test]
    fn streaming_reports_failures_with_stderr() {
        let error = PlainRunner
            .run_streaming(sh("echo boom >&2; exit 4"), &mut |_| {})
            .unwrap_err();
        assert!(
            matches!(&error, Error::CommandFailed { status: 4, stderr, .. } if stderr.contains("boom")),
            "{error:?}"
        );
    }
}
