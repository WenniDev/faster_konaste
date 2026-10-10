mod avs;
mod downloader;
mod error;
mod hook;
mod logger;
mod pattern;
mod resources;
mod updater;

use std::ffi::c_void;

pub use downloader::*;
pub use error::*;
pub use resources::*;

const DLL_PROCESS_ATTACH: u32 = 1;

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(_module: *mut c_void, reason: u32, _reserved: *mut c_void) -> i32 {
    if reason == DLL_PROCESS_ATTACH
        && let Err(err) = updater::install()
    {
        log!("Failed to install hook: {}", err);
    }
    1
}
