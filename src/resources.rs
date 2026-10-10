use std::{fs::Metadata, io, time::SystemTime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileResource {
    /// Path of the file, relative to the install directory
    pub path: String,
    pub size: i32,
    /// Hex encoded SHA-256 of the file
    pub sum: String,
    pub url: String,
    /// Name of the temporary file, relative to the temp directory
    pub tmp: String,
}

/// Size and last write time of a verified file, which a rename keeps
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint {
    pub len: u64,
    pub modified: SystemTime,
}

impl Fingerprint {
    pub fn of(metadata: &Metadata) -> io::Result<Fingerprint> {
        Ok(Fingerprint {
            len: metadata.len(),
            modified: metadata.modified()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fetched {
    pub status: Status,
    /// Fingerprint of the downloaded file, or of the one already up to date
    pub fingerprint: Option<Fingerprint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Downloaded,
    Skipped,
    Cancelled,
}
