use std::{
    ffi::{CString, c_char, c_void},
    sync::{Mutex, OnceLock, PoisonError},
};

use crate::{
    Error, hook,
    pattern::{self, Pattern},
};

/// `mov edx, x; mov ecx, 1; lea r8d, [rdx+dy]; call DrawText` for the TASK and TOTAL percentages
const PATTERN_PERCENT: &str = "BA ?? 00 00 00 B9 01 00 00 00 44 8D 42 ?? E8";
const PERCENT_CALL_OFFSET: usize = 14;
const PERCENT_CALLS: usize = 4;

/// `printf` like `DrawText(font, x, y, &color, "%d%%", percent)`
type DrawText = unsafe extern "C" fn(i32, i32, i32, *const c_void, *const c_char, i32) -> i64;

static DRAW_TEXT: OnceLock<DrawText> = OnceLock::new();
/// Formatted download speed, nothing is appended when `None`
static SPEED: Mutex<Option<String>> = Mutex::new(None);

pub unsafe fn install(image_base: usize) -> Result<(), Error> {
    let pattern = Pattern::new(PATTERN_PERCENT)?;
    let calls = unsafe { pattern::code_sections(image_base) }
        .iter()
        .flat_map(|section| {
            pattern
                .find_all(section)
                .map(|offset| section.as_ptr() as usize + offset + PERCENT_CALL_OFFSET)
        })
        .collect::<Vec<_>>();
    // TASK shadow, TASK, TOTAL shadow, TOTAL
    let &[task_shadow, task, ..] = calls.as_slice() else {
        return Err(Error::PatternNotFound("TASK percentage"));
    };
    let draw_text = unsafe { pattern::rel32(task + 1) };
    if calls.len() != PERCENT_CALLS || unsafe { pattern::rel32(task_shadow + 1) } != draw_text {
        return Err(Error::PatternNotFound("TASK percentage"));
    }

    unsafe {
        DRAW_TEXT.get_or_init(|| std::mem::transmute::<usize, DrawText>(draw_text));
        for site in [task_shadow, task] {
            hook::redirect_call(site, draw_percent as *const () as usize)?;
        }
    }
    Ok(())
}

pub fn set_speed(speed: Option<f64>) {
    let speed = speed.map(|speed| {
        if speed >= 1024.0 * 1024.0 {
            format!("{:.1} MB/s", speed / (1024.0 * 1024.0))
        } else {
            format!("{:.0} KB/s", speed / 1024.0)
        }
    });
    *SPEED.lock().unwrap_or_else(PoisonError::into_inner) = speed;
}

unsafe extern "C" fn draw_percent(
    font: i32,
    x: i32,
    y: i32,
    color: *const c_void,
    format: *const c_char,
    percent: i32,
) -> i64 {
    let Some(&draw_text) = DRAW_TEXT.get() else {
        return 0;
    };
    let speed = SPEED.lock().unwrap_or_else(PoisonError::into_inner);
    // The text is a format string
    match speed
        .as_ref()
        .and_then(|speed| CString::new(format!("{}%% ({})", percent, speed)).ok())
    {
        Some(text) => unsafe { draw_text(font, x, y, color, text.as_ptr(), 0) },
        None => unsafe { draw_text(font, x, y, color, format, percent) },
    }
}
