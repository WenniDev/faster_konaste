use std::{
    fmt::Arguments,
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
    sync::{Mutex, PoisonError},
};

static LOG_FILE: Mutex<Option<File>> = Mutex::new(None);

pub fn init(path: &Path) {
    let file = OpenOptions::new().create(true).append(true).open(path).ok();
    *LOG_FILE.lock().unwrap_or_else(PoisonError::into_inner) = file;
}

pub fn write(args: Arguments) {
    if let Some(file) = LOG_FILE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_mut()
    {
        let _ = writeln!(file, "{}", args);
    }
}

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        $crate::logger::write(format_args!($($arg)*))
    };
}
