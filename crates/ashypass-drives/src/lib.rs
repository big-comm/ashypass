//! External drive encryption for Ashy Pass.
//!
//! Wraps the Linux kernel's LUKS2 stack (`cryptsetup` + `udisks2`) instead of
//! reimplementing block-level cryptography. See [`CRYPTO_SPEC.md`] § External
//! drives for the rationale and parameter set.
//!
//! Layered into independent modules so each piece is unit-testable in
//! isolation:
//!
//! - [`detect`] — read-only enumeration via `lsblk -J`.
//! - [`safety`] — pre-condition guards (rootfs, mounts, swap, crypttab).
//! - [`runner`] — subprocess abstraction; `PkexecRunner` for privileged ops.
//! - [`luks`] — `cryptsetup` argv construction + invocation.
//! - [`wipe`] — pre-format wipe strategies.
//! - [`fs`] — `mkfs.*` on the opened mapping.
//! - [`passphrase`] — zeroizing newtype that never appears in argv.
//!
//! The high-level orchestrator that ties these into a single
//! `encrypt_new_drive` pipeline lives in [`pipeline`].

pub mod detect;
pub mod error;
pub mod fs;
pub mod helper_client;
pub mod luks;
pub mod passphrase;
pub mod pipeline;
pub mod runner;
pub mod safety;
pub mod wipe;

pub use error::{Error, Result};
pub use passphrase::Passphrase;
