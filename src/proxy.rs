use std::{ffi::c_void, sync::OnceLock};

use windows_sys::Win32::System::{
    LibraryLoader::{GetProcAddress, LoadLibraryW},
    SystemInformation::GetSystemDirectoryW,
};

use crate::log;

const E_FAIL: i32 = 0x80004005_u32 as i32;

static SYSTEM_D3D9: OnceLock<usize> = OnceLock::new();

/// Loaded by absolute path, as this DLL may itself be named d3d9.dll
fn system_d3d9() -> usize {
    *SYSTEM_D3D9.get_or_init(|| unsafe {
        let mut buffer = [0u16; 260];
        let len = GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) as usize;
        if len == 0 || len >= buffer.len() {
            log!("Failed to get the system directory, d3d9.dll calls are not forwarded");
            return 0;
        }
        let mut path = buffer[..len].to_vec();
        path.extend("\\d3d9.dll\0".encode_utf16());

        let module = LoadLibraryW(path.as_ptr());
        if module.is_null() {
            log!("Failed to load the system d3d9.dll");
        }
        module as usize
    })
}

unsafe fn system_function(name: &[u8]) -> Option<unsafe extern "system" fn() -> isize> {
    let module = system_d3d9();
    if module == 0 {
        return None;
    }
    unsafe { GetProcAddress(module as *mut c_void, name.as_ptr()) }
}

/// Exports `$name`, calling the function of the same name in the system d3d9.dll
macro_rules! forward {
    ($name:ident($($arg:ident: $ty:ty),*) -> $ret:ty, $fallback:expr) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $name($($arg: $ty),*) -> $ret {
            match unsafe { system_function(concat!(stringify!($name), "\0").as_bytes()) } {
                Some(function) => unsafe {
                    let function = std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        unsafe extern "system" fn($($ty),*) -> $ret,
                    >(function);
                    function($($arg),*)
                },
                None => $fallback,
            }
        }
    };
}

forward!(Direct3DCreate9(sdk_version: u32) -> *mut c_void, std::ptr::null_mut());
forward!(Direct3DCreate9Ex(sdk_version: u32, device: *mut *mut c_void) -> i32, E_FAIL);
forward!(Direct3DShaderValidatorCreate9() -> *mut c_void, std::ptr::null_mut());
forward!(D3DPERF_BeginEvent(color: u32, name: *const u16) -> i32, 0);
forward!(D3DPERF_EndEvent() -> i32, 0);
forward!(D3DPERF_GetStatus() -> u32, 0);
forward!(D3DPERF_QueryRepeatFrame() -> i32, 0);
forward!(D3DPERF_SetMarker(color: u32, name: *const u16) -> (), ());
forward!(D3DPERF_SetOptions(options: u32) -> (), ());
forward!(D3DPERF_SetRegion(color: u32, name: *const u16) -> (), ());
