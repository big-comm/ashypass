//! Errors in words a person can act on.
//!
//! Messages put a translated sentence ("Could not save") before the error.
//! The core's own texts are English and technical ("database not
//! unlocked", "io: Permission denied (os error 13)"); the common cases get
//! a translated explanation here, and anything else keeps its technical
//! text, which still helps in a bug report.

use crate::tr;
use std::any::Any;
use std::fmt::Display;
use std::io::ErrorKind;

/// `error` for a person: the core's and the system's common errors
/// explained, any other error as it is.
pub fn describe<E: Display + Any>(error: &E) -> String {
    let any = error as &dyn Any;
    if let Some(core) = any.downcast_ref::<ashypass_core::Error>() {
        return describe_core(core);
    }
    if let Some(io) = any.downcast_ref::<std::io::Error>() {
        return describe_io(io);
    }
    error.to_string()
}

fn describe_core(error: &ashypass_core::Error) -> String {
    use ashypass_core::Error;
    match error {
        Error::Locked => tr!("the vault is locked; unlock it and try again").to_string(),
        Error::InvalidMasterPassword => tr!("incorrect master password").to_string(),
        Error::KeyMismatch => {
            tr!("this unlock no longer opens the vault; enter the master password").to_string()
        }
        Error::Io(io) => describe_io(io),
        other => other.to_string(),
    }
}

fn describe_io(error: &std::io::Error) -> String {
    let words = match error.kind() {
        ErrorKind::NotFound => tr!("the file or folder does not exist"),
        ErrorKind::PermissionDenied => tr!("no permission to read or write there"),
        ErrorKind::StorageFull => tr!("the disk is full"),
        ErrorKind::ReadOnlyFilesystem => tr!("that place is read-only"),
        _ => return error.to_string(),
    };
    words.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_errors_are_explained_others_kept() {
        // No translation catalog in tests: the English source texts.
        assert_eq!(
            describe(&ashypass_core::Error::Locked),
            "the vault is locked; unlock it and try again"
        );
        let denied = std::io::Error::from(ErrorKind::PermissionDenied);
        assert_eq!(describe(&denied), "no permission to read or write there");
        assert_eq!(
            describe(&ashypass_core::Error::Io(std::io::Error::from(
                ErrorKind::NotFound
            ))),
            "the file or folder does not exist"
        );
        let other = ashypass_core::Error::Other("server said 500".into());
        assert_eq!(describe(&other), "server said 500");
        assert_eq!(describe(&"plain text".to_string()), "plain text");
    }
}
