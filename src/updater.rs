use std::{
    collections::HashMap,
    ffi::{CString, c_void},
    fmt::{Debug, Formatter},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use reqwest::Client;
use tokio_util::sync::CancellationToken;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

use crate::{
    Error, Fetched, FileResource, Fingerprint, ParallelDownloader, Status,
    avs::{Avs, Node},
    downloader::sha256,
    hook, log, logger,
    pattern::{self, Pattern},
};

/// Prologue of `Updater::StateFuncDiffWait`, up to `if (file_count <= 0)`
const PATTERN_STATE_DIFF_WAIT: &str = "4C 8B DC 55 53 57 49 8D AB E8 FC FF FF 48 81 EC 00 04 00 00 48 8B 05 \
     ?? ?? ?? ?? 48 33 C4 48 89 85 F0 02 00 00 33 DB 48 8B F9 89 59 20 39 59 24 0F 8E";

// The original function is about 0x310 bytes long
const STATE_DIFF_WAIT_SIZE: usize = 0x400;

/// `lea rcx, [rdi+0x38]; lea rdx, [StateFuncDownloadInit]; call StateMachine::SetNext`
const PATTERN_SET_NEXT_DOWNLOAD_INIT: &str = "48 8D 4F 38 48 8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ??";

/// Prologue of `Updater::StateFuncDownloadWait`, up to `if (index >= file_count)`
const PATTERN_STATE_DOWNLOAD_WAIT: &str = "48 89 5C 24 20 56 48 81 EC 50 09 00 00 48 8B 05 ?? ?? ?? ?? \
     48 33 C4 48 89 84 24 40 09 00 00 8B 59 20 48 8B F1 3B 59 24 0F 8D";

// The original function is about 0x3a0 bytes long
const STATE_DOWNLOAD_WAIT_SIZE: usize = 0x400;

/// `add rcx, 0x38; lea rdx, [StateFuncInstallInit]; call StateMachine::SetNext`
const PATTERN_SET_NEXT_INSTALL_INIT: &str = "48 83 C1 38 48 8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ??";

/// `lea rcx, [rsi+0x38]; lea rdx, [StateFuncError]; call StateMachine::SetNext`
const PATTERN_SET_NEXT_ERROR: &str = "48 8D 4E 38 48 8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ??";

/// `mov rcx, rbx; call FileSumCheck; mov byte [rsi+0x68], 1; test al, al`
const PATTERN_FILE_SUM_CHECK: &str = "48 8B CB E8 ?? ?? ?? ?? C6 46 68 01 84 C0";

/// `Updater::SetError(this, 0xbb8, 9)` on a download start error
const PATTERN_SET_ERROR: &str = "BA B8 0B 00 00 41 B8 09 00 00 00 48 8B CE 40 B5 01 E8 ?? ?? ?? ??";

/// `Progress::Add(Progress::Instance(), 3, size)`
const PATTERN_PROGRESS_ADD: &str = "E8 ?? ?? ?? ?? 48 8B C8 4C 8B C3 BA 03 00 00 00 E8 ?? ?? ?? ??";

/// Found by scanning for the diff and download states and following their references
struct Functions {
    set_error: SetError,
    progress_instance: ProgressInstance,
    progress_add: ProgressAdd,
    state_diff_wait: usize,
    state_download_init: usize,
    state_download_wait: usize,
    state_install_init: usize,
    state_error: usize,
    state_machine_set_next: StateMachineSetNext,
    file_sum_check: usize,
}

impl Functions {
    unsafe fn find(image_base: usize) -> Result<Functions, Error> {
        let sections = unsafe { pattern::code_sections(image_base) };

        let diff_body = find_function(
            &sections,
            PATTERN_STATE_DIFF_WAIT,
            STATE_DIFF_WAIT_SIZE,
            "Updater::StateFuncDiffWait",
        )?;
        let set_next_download_init = find_in(
            diff_body,
            PATTERN_SET_NEXT_DOWNLOAD_INIT,
            "StateMachine::SetNext(StateFuncDownloadInit)",
        )?;

        let body = find_function(
            &sections,
            PATTERN_STATE_DOWNLOAD_WAIT,
            STATE_DOWNLOAD_WAIT_SIZE,
            "Updater::StateFuncDownloadWait",
        )?;
        let find = |pattern, name| find_in(body, pattern, name);

        let set_next_install_init = find(
            PATTERN_SET_NEXT_INSTALL_INIT,
            "StateMachine::SetNext(StateFuncInstallInit)",
        )?;
        let set_next_error = find(
            PATTERN_SET_NEXT_ERROR,
            "StateMachine::SetNext(StateFuncError)",
        )?;
        let set_error = find(PATTERN_SET_ERROR, "Updater::SetError")?;
        let file_sum_check = find(PATTERN_FILE_SUM_CHECK, "FileSumCheck")?;
        let progress_add = find(PATTERN_PROGRESS_ADD, "Progress::Add")?;

        unsafe {
            Ok(Functions {
                set_error: std::mem::transmute::<usize, SetError>(pattern::rel32(set_error + 18)),
                progress_instance: std::mem::transmute::<usize, ProgressInstance>(pattern::rel32(
                    progress_add + 1,
                )),
                progress_add: std::mem::transmute::<usize, ProgressAdd>(pattern::rel32(
                    progress_add + 17,
                )),
                state_diff_wait: diff_body.as_ptr() as usize,
                state_download_init: pattern::rel32(set_next_download_init + 7),
                state_download_wait: body.as_ptr() as usize,
                state_install_init: pattern::rel32(set_next_install_init + 7),
                state_error: pattern::rel32(set_next_error + 7),
                state_machine_set_next: std::mem::transmute::<usize, StateMachineSetNext>(
                    pattern::rel32(set_next_install_init + 12),
                ),
                file_sum_check: pattern::rel32(file_sum_check + 4),
            })
        }
    }
}

/// First `size` bytes of the function starting with `pattern`, which must match exactly once
fn find_function(
    sections: &[&'static [u8]],
    pattern: &'static str,
    size: usize,
    name: &'static str,
) -> Result<&'static [u8], Error> {
    let pattern = Pattern::new(pattern)?;
    let mut matches = sections.iter().filter_map(|section| {
        pattern
            .find_unique(section)
            .map(|start| &section[start..(start + size).min(section.len())])
    });
    match (matches.next(), matches.next()) {
        (Some(body), None) => Ok(body),
        _ => Err(Error::PatternNotFound(name)),
    }
}

fn find_in(body: &[u8], pattern: &'static str, name: &'static str) -> Result<usize, Error> {
    Pattern::new(pattern)?
        .find(body)
        .map(|offset| body.as_ptr() as usize + offset)
        .ok_or(Error::PatternNotFound(name))
}

impl Debug for Functions {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Functions")
            .field("set_error", &(self.set_error as *const ()))
            .field("progress_instance", &(self.progress_instance as *const ()))
            .field("progress_add", &(self.progress_add as *const ()))
            .field("state_diff_wait", &(self.state_diff_wait as *const ()))
            .field(
                "state_download_init",
                &(self.state_download_init as *const ()),
            )
            .field(
                "state_download_wait",
                &(self.state_download_wait as *const ()),
            )
            .field(
                "state_install_init",
                &(self.state_install_init as *const ()),
            )
            .field("state_error", &(self.state_error as *const ()))
            .field(
                "state_machine_set_next",
                &(self.state_machine_set_next as *const ()),
            )
            .field("file_sum_check", &(self.file_sum_check as *const ()))
            .finish()
    }
}

// Offsets in the Updater object
const OFFSET_CANCEL_REQUESTED: usize = 0x1d;
const OFFSET_FILE_INDEX: usize = 0x20;
const OFFSET_STATE_MACHINE: usize = 0x38;
const OFFSET_SERVER_LIST: usize = 0x78;
const OFFSET_LOCAL_LIST: usize = 0x80;
const OFFSET_UPDATE_LIST: usize = 0x90;

const PROGRESS_SLOT_DIFF: i32 = 2;
const PROGRESS_SLOT_DOWNLOAD: i32 = 3;

/// Arguments the original download state passes to `Updater::SetError` on a download error
const ERROR_DURATION: i32 = 0xbb8;
const ERROR_DOWNLOAD: i32 = 0xa;

const CONCURRENCY_VAR: &str = "KONASTE_DL_CONCURRENCY";

type SetError = unsafe extern "system" fn(*mut u8, i32, i32);
type ProgressInstance = unsafe extern "system" fn() -> *mut c_void;
type ProgressAdd = unsafe extern "system" fn(*mut c_void, i32, i64) -> i64;
type StateMachineSetNext = unsafe extern "system" fn(*mut u8, usize);

static FUNCTIONS: OnceLock<Functions> = OnceLock::new();
static INSTALL_DIR: OnceLock<PathBuf> = OnceLock::new();
static JOB: Mutex<Option<Job>> = Mutex::new(None);
/// Sum and fingerprint of the files verified by the downloader, by path
static VERIFIED: Mutex<Option<HashMap<String, (String, Fingerprint)>>> = Mutex::new(None);

pub fn install() -> Result<(), Error> {
    let exe = std::env::current_exe()?;
    if !exe
        .file_name()
        // updater.exe, or bm2dx_updater.exe for beatmania IIDX INFINITAS
        .is_some_and(|name| {
            name.to_string_lossy()
                .to_ascii_lowercase()
                .ends_with("updater.exe")
        })
    {
        return Ok(());
    }
    logger::init(&exe.with_file_name("faster_konaste.log"));

    // updater.exe lives in <install>/launcher/modules
    let install_dir = exe
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or_else(|| Error::InternalError(format!("Unexpected updater path {:?}", exe)))?
        .to_path_buf();
    INSTALL_DIR.get_or_init(|| install_dir);

    let image_base = unsafe { GetModuleHandleW(std::ptr::null()) } as usize;
    let functions = unsafe { Functions::find(image_base) }?;
    let functions = FUNCTIONS.get_or_init(|| functions);
    log!("Found {:?}", functions);

    unsafe {
        hook::write_jump(
            functions.state_diff_wait,
            state_diff_wait as *const () as usize,
        )?;
        hook::write_jump(
            functions.state_download_wait,
            state_download_wait as *const () as usize,
        )?;
        hook::write_jump(
            functions.file_sum_check,
            file_sum_check as *const () as usize,
        )?;
    }
    log!("Hooked Updater::StateFuncDiffWait, Updater::StateFuncDownloadWait and FileSumCheck");

    Ok(())
}

/// Called once by the state machine, after `Updater::StateFuncDiffInit` counted the files
unsafe extern "system" fn state_diff_wait(updater: *mut u8) -> i64 {
    let started = Instant::now();
    match unsafe { diff(updater) } {
        Ok((total, changed)) => {
            log!(
                "Compared {} files in {:?}, {} to update",
                total,
                started.elapsed(),
                changed
            );
            unsafe {
                add_progress(PROGRESS_SLOT_DIFF, total as i64);
                *(updater.add(OFFSET_FILE_INDEX) as *mut i32) = total as i32;
                set_next_state(updater, functions().state_download_init);
            }
        }
        Err(err) => {
            log!("Failed to compare files: {}", err);
            unsafe { fail(updater) };
        }
    }
    0
}

/// Returns the number of server files and the number of files to update
unsafe fn diff(updater: *mut u8) -> Result<(usize, usize), Error> {
    let avs = Avs::get()?;
    let list = |offset| unsafe { *(updater.add(offset) as *const *mut c_void) };
    let resource_info = |list| unsafe { avs.search(list, std::ptr::null_mut(), c"resource_info") };

    let update_list = resource_info(list(OFFSET_UPDATE_LIST))
        .ok_or_else(|| Error::InternalError("Missing update list".to_string()))?;

    // Same buffer sizes as the original state, the first entry wins on duplicate paths
    let mut local_sums = HashMap::new();
    if let Some(local_list) = resource_info(list(OFFSET_LOCAL_LIST)) {
        for node in unsafe { avs.children(local_list, c"file") } {
            local_sums
                .entry(unsafe { avs.read_bytes(node, c"path", 0x104) })
                .or_insert_with(|| unsafe { avs.read_bytes(node, c"sum", 0x41) });
        }
    }

    let Some(server_list) = resource_info(list(OFFSET_SERVER_LIST)) else {
        return Ok((0, 0));
    };
    let mut total = 0;
    let mut changed = Vec::new();
    for node in unsafe { avs.children(server_list, c"file") } {
        total += 1;
        let path = unsafe { avs.read_bytes(node, c"path", 0x104) };
        let sum = unsafe { avs.read_bytes(node, c"sum", 0x41) };
        if !local_sums
            .get(&path)
            .is_some_and(|local_sum: &Vec<u8>| local_sum.eq_ignore_ascii_case(&sum))
        {
            changed.push(node);
        }
    }

    // Clone only after iterating, so the tree is not modified during the traversal
    for node in &changed {
        unsafe { avs.clone_node(update_list, *node) };
    }

    Ok((total, changed.len()))
}

/// Called by the state machine on every tick (~16ms) until it moves to another state
unsafe extern "system" fn state_download_wait(updater: *mut u8) -> i64 {
    let mut job = JOB.lock().unwrap_or_else(PoisonError::into_inner);
    if job.is_none() {
        match unsafe { Job::start(updater) } {
            Ok(started) => *job = Some(started),
            Err(err) => {
                log!("Failed to start download: {}", err);
                unsafe { fail(updater) };
                return 0;
            }
        }
    }

    let Some(running) = job.as_mut() else {
        return 0;
    };
    if unsafe { *updater.add(OFFSET_CANCEL_REQUESTED) } != 0 {
        running.cancellation_token.cancel();
    }
    unsafe { running.report_progress() };
    if !running.handle.is_finished() {
        return 0;
    }

    if let Some(finished) = job.take() {
        unsafe { finished.finish(updater) };
    }
    0
}

/// Called by `Updater::StateFuncInstallWait` after moving each file, returns 0 if it matches
unsafe extern "system" fn file_sum_check(node: Node) -> i64 {
    match unsafe { check_file(node) } {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(err) => {
            log!("Failed to check file: {}", err);
            1
        }
    }
}

unsafe fn check_file(node: Node) -> Result<bool, Error> {
    let avs = Avs::get()?;
    // Same buffer sizes as the original function
    let path = unsafe { avs.read_str(node, c"path", 0x104) };
    let sum = unsafe { avs.read_str(node, c"sum", 0x41) };
    let output_path = install_dir().join(&path);

    let Ok(metadata) = std::fs::metadata(&output_path) else {
        return Ok(false);
    };
    let verified = VERIFIED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .and_then(|verified| verified.get(&path).cloned());
    if let Some((verified_sum, fingerprint)) = verified
        && verified_sum.eq_ignore_ascii_case(&sum)
        && Fingerprint::of(&metadata)? == fingerprint
    {
        return Ok(true);
    }

    log!("Hashing {}", path);
    Ok(sha256(&output_path)?.0.eq_ignore_ascii_case(&sum))
}

struct Job {
    /// Nodes of the update list, in the same order as the downloaded files
    nodes: Vec<usize>,
    /// Path and sum of each file
    sums: Vec<(String, String)>,
    /// Value of the `tmp` node to create for each downloaded file
    tmps: Vec<CString>,
    progress: Arc<AtomicU64>,
    reported: u64,
    cancellation_token: CancellationToken,
    handle: JoinHandle<Result<Vec<Fetched>, Error>>,
}

impl Job {
    unsafe fn start(updater: *mut u8) -> Result<Job, Error> {
        let avs = Avs::get()?;
        let update_list = unsafe { *(updater.add(OFFSET_UPDATE_LIST) as *const *mut c_void) };

        let mut nodes = Vec::new();
        let mut files = Vec::new();
        for index in 0.. {
            let path = CString::new(format!("resource_info/file#{}", index))
                .map_err(|err| Error::InternalError(err.to_string()))?;
            let Some(node) = (unsafe { avs.search(update_list, std::ptr::null_mut(), &path) })
            else {
                break;
            };

            // Same buffer sizes as the original state
            files.push(unsafe {
                FileResource {
                    path: avs.read_str(node, c"path", 0x104),
                    size: avs.read_s32(node, c"size"),
                    sum: avs.read_str(node, c"sum", 0x41),
                    url: avs.read_str(node, c"url", 0x800),
                    tmp: format!("kpd_{}", index),
                }
            });
            nodes.push(node as usize);
        }

        let install_dir = install_dir().to_path_buf();
        // The updater mounts /TEMP on <install>/Temp
        let temp_dir = install_dir.join("Temp");
        let sums = files
            .iter()
            .map(|file| (file.path.clone(), file.sum.clone()))
            .collect();

        let tmps = files
            .iter()
            .map(|file| CString::new(format!("/TEMP/{}", file.tmp)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| Error::InternalError(err.to_string()))?;

        let downloader = ParallelDownloader::builder()
            .install_dir(install_dir)
            .temp_dir(temp_dir)
            .concurrency(concurrency())
            .build();
        log!("Downloading {} files with {:?}", files.len(), downloader);

        let progress = downloader.progress();
        let cancellation_token = downloader.cancellation_token();
        let handle = std::thread::spawn(move || {
            let client = Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .read_timeout(Duration::from_secs(60))
                .build()?;
            downloader.run(client, files)
        });

        Ok(Job {
            nodes,
            sums,
            tmps,
            progress,
            reported: 0,
            cancellation_token,
            handle,
        })
    }

    unsafe fn report_progress(&mut self) {
        let progress = self.progress.load(Ordering::Relaxed);
        if progress > self.reported {
            unsafe { add_progress(PROGRESS_SLOT_DOWNLOAD, (progress - self.reported) as i64) };
            self.reported = progress;
        }
    }

    unsafe fn finish(self, updater: *mut u8) {
        let result = self
            .handle
            .join()
            .map_err(|_| Error::InternalError("Download thread panicked".to_string()))
            .and_then(|result| result);

        let fetched = match result {
            Ok(fetched) => fetched,
            Err(err) => {
                log!("Download failed: {}", err);
                unsafe { fail(updater) };
                return;
            }
        };
        if fetched.len() != self.nodes.len()
            || fetched
                .iter()
                .any(|fetched| fetched.status == Status::Cancelled)
        {
            // Cancelled by the user, the updater already left this state
            log!("Download cancelled");
            return;
        }

        let avs = match Avs::get() {
            Ok(avs) => avs,
            Err(err) => {
                log!("Download failed: {}", err);
                unsafe { fail(updater) };
                return;
            }
        };
        for ((node, tmp), fetched) in self.nodes.iter().zip(&self.tmps).zip(&fetched) {
            if fetched.status == Status::Downloaded {
                unsafe { avs.write_str(*node as Node, c"tmp", tmp) };
            }
        }

        // Let FileSumCheck skip the files verified here
        let verified = self
            .sums
            .into_iter()
            .zip(&fetched)
            .filter_map(|((path, sum), fetched)| {
                fetched
                    .fingerprint
                    .map(|fingerprint| (path, (sum, fingerprint)))
            })
            .collect();
        *VERIFIED.lock().unwrap_or_else(PoisonError::into_inner) = Some(verified);

        let downloaded = fetched
            .iter()
            .filter(|fetched| fetched.status == Status::Downloaded)
            .count();
        log!(
            "Download finished: {} downloaded, {} skipped",
            downloaded,
            fetched.len() - downloaded
        );
        unsafe { set_next_state(updater, functions().state_install_init) };
    }
}

fn concurrency() -> usize {
    std::env::var(CONCURRENCY_VAR)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(8)
}

fn install_dir() -> &'static Path {
    INSTALL_DIR
        .get()
        .expect("hook installed without an install directory")
}

fn functions() -> &'static Functions {
    FUNCTIONS.get().expect("hook installed without functions")
}

unsafe fn add_progress(slot: i32, amount: i64) {
    unsafe {
        let progress = (functions().progress_instance)();
        (functions().progress_add)(progress, slot, amount);
    }
}

unsafe fn set_next_state(updater: *mut u8, state: usize) {
    unsafe { (functions().state_machine_set_next)(updater.add(OFFSET_STATE_MACHINE), state) };
}

unsafe fn fail(updater: *mut u8) {
    unsafe {
        (functions().set_error)(updater, ERROR_DURATION, ERROR_DOWNLOAD);
        set_next_state(updater, functions().state_error);
    }
}
