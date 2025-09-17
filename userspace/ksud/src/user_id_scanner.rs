use log::{error, info, warn};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;
use std::thread;
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher, Event, EventKind};
use std::sync::mpsc;
use anyhow::Result;

const KERNEL_SU_OPTION: u32 = 0xDEADBEEF;
const CMD_UPDATE_UID_LIST: u32 = 50;
const USER_DATA_PATH: &str = "/data/user_de/0";
const PACKAGES_LIST_PATH: &str = "/data/system/packages.list";
const MAX_PACKAGE_NAME: usize = 256;
const MAX_UID_ENTRIES: usize = 4096;

#[repr(C)]
#[derive(Clone, Copy)]
struct UidPackageEntry {
    uid: u32,
    package: [i8; MAX_PACKAGE_NAME],
}

#[repr(C)]
struct UidListData {
    count: u32,
    entries: [UidPackageEntry; MAX_UID_ENTRIES],
}

impl UidListData {
    fn new() -> Self {
        Self {
            count: 0,
            entries: [UidPackageEntry {
                uid: 0,
                package: [0; MAX_PACKAGE_NAME],
            }; MAX_UID_ENTRIES],
        }
    }

    fn add_entry(&mut self, uid: u32, package: &str) -> bool {
        if self.count as usize >= MAX_UID_ENTRIES {
            return false;
        }

        let package_bytes = package.as_bytes();
        let copy_len = std::cmp::min(package_bytes.len(), MAX_PACKAGE_NAME - 1);

        let mut package_array = [0i8; MAX_PACKAGE_NAME];
        for i in 0..copy_len {
            package_array[i] = package_bytes[i] as i8;
        }

        self.entries[self.count as usize] = UidPackageEntry {
            uid,
            package: package_array,
        };

        self.count += 1;
        true
    }
}

fn ksuctl(cmd: u32, arg1: *const u8, arg2: *const u8) -> bool {
    let mut result: i32 = 0;
    let rtn = unsafe {
        libc::prctl(
            KERNEL_SU_OPTION as i32,
            cmd as libc::c_ulong,
            arg1 as libc::c_ulong,
            arg2 as libc::c_ulong,
            &mut result as *mut i32 as libc::c_ulong,
        )
    };

    result == KERNEL_SU_OPTION as i32 && rtn == -1
}

fn scan_user_data_directory() -> Result<HashMap<String, u32>, Box<dyn std::error::Error>> {
    let mut uid_map = HashMap::new();
    let user_data_path = Path::new(USER_DATA_PATH);

    if !user_data_path.exists() {
        return Err(format!("Path {} does not exist", USER_DATA_PATH).into());
    }

    info!("Scanning user data directory: {}", USER_DATA_PATH);

    let entries = fs::read_dir(user_data_path)?;
    let mut total_found = 0;
    let mut errors_encountered = 0;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!("Failed to read directory entry: {}", e);
                errors_encountered += 1;
                continue;
            }
        };

        let path = entry.path();
        
        if !path.is_dir() {
            continue;
        }

        let package_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name,
            None => {
                warn!("Invalid package name for path: {:?}", path);
                errors_encountered += 1;
                continue;
            }
        };

        if package_name.len() >= MAX_PACKAGE_NAME {
            warn!("Package name too long: {}", package_name);
            errors_encountered += 1;
            continue;
        }

        let metadata = match path.metadata() {
            Ok(m) => m,
            Err(e) => {
                warn!("Failed to get metadata for {}: {}", package_name, e);
                errors_encountered += 1;
                continue;
            }
        };

        let uid = metadata.uid();
        uid_map.insert(package_name.to_string(), uid);
        total_found += 1;

        info!("Found package: {}, uid: {}", package_name, uid);
    }

    if errors_encountered > 0 {
        warn!(
            "Encountered {} errors while scanning user data directory",
            errors_encountered
        );
    }

    info!(
        "Scanned user data directory, found {} packages with {} errors",
        total_found, errors_encountered
    );

    Ok(uid_map)
}

fn send_uid_list_to_kernel(uid_map: &HashMap<String, u32>) -> Result<(), Box<dyn std::error::Error>> {
    let mut uid_data = UidListData::new();

    for (package, &uid) in uid_map {
        if !uid_data.add_entry(uid, package) {
            warn!("Maximum UID entries reached, truncating list");
            break;
        }
    }

    info!("Sending {} UID entries to kernel", uid_data.count);

    let success = ksuctl(
        CMD_UPDATE_UID_LIST,
        &uid_data as *const UidListData as *const u8,
        std::ptr::null(),
    );

    if success {
        info!("Successfully sent UID list to kernel");
        Ok(())
    } else {
        Err("Failed to send UID list to kernel".into())
    }
}

/// Perform a UID scan and update
pub fn perform_scan_and_update() {
    match scan_user_data_directory() {
        Ok(uid_map) => {
            if let Err(e) = send_uid_list_to_kernel(&uid_map) {
                error!("Failed to send UID list to kernel: {}", e);
            }
        }
        Err(e) => {
            error!("Failed to scan user data directory: {}", e);
        }
    }
}

/// Launch the UID scanner, including initial scanning and file monitoring.
pub fn start_uid_scanner() -> Result<()> {
    info!("Launch KSU UID Scanner");

    // Perform initial scan
    perform_scan_and_update();

    // Set up file monitoring in a background thread
    thread::spawn(move || {
        let _watcher = match setup_file_watcher() {
            Ok(w) => {
                info!("File monitoring setup successful");
                w
            }
            Err(e) => {
                error!("Failed to set up file monitoring: {}", e);
                return;
            }
        };

        info!("UID scanner is running, monitoring changes....");

        loop {
            thread::sleep(Duration::from_secs(60));
        }
    });

    Ok(())
}

fn setup_file_watcher() -> Result<RecommendedWatcher, Box<dyn std::error::Error>> {
    let (tx, rx) = mpsc::channel();

    let mut watcher = RecommendedWatcher::new(
        move |result: Result<Event, notify::Error>| {
            if let Err(e) = tx.send(result) {
                warn!("Failed to send file monitoring event: {}", e);
            }
        },
        Config::default(),
    )?;

    let packages_list_path = Path::new(PACKAGES_LIST_PATH);
    if packages_list_path.exists() {
        if let Some(parent) = packages_list_path.parent() {
            watcher.watch(parent, RecursiveMode::NonRecursive)?;
            info!("Started watching packages.list directory for changes");
        }
    } else {
        warn!("packages.list not found, file watching disabled");
    }

    thread::spawn(move || {
        for result in rx {
            match result {
                Ok(event) => {
                    if let EventKind::Create(_) | EventKind::Modify(_) = event.kind {
                        let should_trigger = event.paths.iter().any(|path| {
                            path.ends_with("packages.list") || 
                            path.ends_with("packages.list.tmp")
                        });

                        if should_trigger {
                            info!("Detected packages.list change, triggering UID scan");
                            thread::sleep(Duration::from_millis(100)); // Brief delay for file stability
                            perform_scan_and_update();
                        }
                    }
                }
                Err(e) => {
                    warn!("File watcher error: {}", e);
                }
            }
        }
    });

    Ok(watcher)
}

pub fn trigger_uid_scan() -> Result<()> {
    info!("Manually trigger UID scan");
    perform_scan_and_update();
    Ok(())
}