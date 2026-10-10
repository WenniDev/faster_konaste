use std::{ffi::c_void, io};

use windows_sys::Win32::System::{
    Diagnostics::Debug::FlushInstructionCache,
    Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
        VirtualAlloc, VirtualProtect,
    },
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
    unsafe { write_code(target, &jump_code(target, destination)) }
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn redirect_call(site: usize, destination: usize) -> Result<usize, Error> {
    unsafe {
        let original = crate::pattern::rel32(site + 1);

        // `jmp qword [rip]` followed by the address
        let stub = alloc_near(site)?;
        let mut code = vec![0xFF, 0x25, 0, 0, 0, 0];
        code.extend_from_slice(&(destination as u64).to_le_bytes());
        std::ptr::copy_nonoverlapping(code.as_ptr(), stub as *mut u8, code.len());
        let mut old_protect = 0;
        VirtualProtect(
            stub as *const c_void,
            code.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );

        let displacement = i32::try_from(stub as isize - (site as isize + 5))
            .map_err(|_| Error::InternalError("Hook stub out of range".to_string()))?;
        write_code(site + 1, &displacement.to_le_bytes())?;
        Ok(original)
    }
}

#[cfg(target_arch = "x86")]
pub unsafe fn redirect_call(site: usize, destination: usize) -> Result<usize, Error> {
    unsafe {
        let original = crate::pattern::rel32(site + 1);
        let displacement = destination.wrapping_sub(site + 5) as u32;
        write_code(site + 1, &displacement.to_le_bytes())?;
        Ok(original)
    }
}

/// Allocates a page within 2GB of `address`
#[cfg(target_arch = "x86_64")]
unsafe fn alloc_near(address: usize) -> Result<usize, Error> {
    // Allocations are aligned to 64KB
    const GRANULARITY: usize = 0x10000;
    const RANGE: usize = 0x7000_0000;
    let base = address & !(GRANULARITY - 1);
    for distance in (GRANULARITY..RANGE).step_by(GRANULARITY) {
        for candidate in [base.checked_sub(distance), base.checked_add(distance)]
            .into_iter()
            .flatten()
        {
            let page = unsafe {
                VirtualAlloc(
                    candidate as *const c_void,
                    0x1000,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                )
            };
            if !page.is_null() {
                return Ok(page as usize);
            }
        }
    }
    Err(Error::InternalError(
        "No free memory near the hooked function".to_string(),
    ))
}

unsafe fn write_code(target: usize, code: &[u8]) -> Result<(), Error> {
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
