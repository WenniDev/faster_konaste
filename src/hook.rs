use std::{ffi::c_void, io};

use windows_sys::Win32::System::{
    Diagnostics::Debug::FlushInstructionCache,
    Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect},
    Threading::GetCurrentProcess,
};

use crate::Error;

/// Overwrites 12 bytes with `mov rax, destination; jmp rax`, without a trampoline
#[cfg(target_arch = "x86_64")]
fn jump_code(_target: usize, destination: usize) -> Vec<u8> {
    let mut code = vec![0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0];
    code[2..10].copy_from_slice(&(destination as u64).to_le_bytes());
    code
}

/// Overwrites 5 bytes with `jmp destination`, without a trampoline
#[cfg(target_arch = "x86")]
fn jump_code(target: usize, destination: usize) -> Vec<u8> {
    let mut code = vec![0xE9, 0, 0, 0, 0];
    code[1..5].copy_from_slice(&(destination.wrapping_sub(target + 5) as u32).to_le_bytes());
    code
}

pub unsafe fn write_jump(target: usize, destination: usize) -> Result<(), Error> {
    let code = jump_code(target, destination);

    unsafe {
        let mut old_protect = 0;
        if VirtualProtect(
            target as *const c_void,
            code.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        ) == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        std::ptr::copy_nonoverlapping(code.as_ptr(), target as *mut u8, code.len());
        VirtualProtect(
            target as *const c_void,
            code.len(),
            old_protect,
            &mut old_protect,
        );
        FlushInstructionCache(GetCurrentProcess(), target as *const c_void, code.len());
    }

    Ok(())
}
