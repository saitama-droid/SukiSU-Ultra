use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;
use std::thread;
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher, Event, EventKind};
use std::sync::mpsc;
use anyhow::Result;

// Constants for kernel communication
const KERNEL_SU_OPTION: u32 = 0xDEADBEEF;
const CMD_UPDATE_UID_LIST: u32 = 50;

// System paths
const USER_DATA_BASE_PATH: &str = "/data/user_de";
const PACKAGES_LIST_PATH: &str = "/data/system/packages.list";
const SCANNER_CONFIG_PATH: &str = "/data/adb/ksu/scanner_config.json";
const SCANNER_PID_FILE: &str = "/data/adb/ksu/scanner.pid";

// Limits
const MAX_PACKAGE_NAME: usize = 256;
const MAX_UID_ENTRIES: usize = 4096;

// Default configuration values
const DEFAULT_SCAN_INTERVAL: u64 = 300; // 5 minutes
const DEFAULT_FILE_WATCH_ENABLED: bool = true;
const DEFAULT_AUTO_START: bool = true;

/// Scanner configuration structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScannerConfig {
    /// Scan all users by default
    pub scan_all_users: bool,
    /// Automatic scan interval in seconds
    pub scan_interval: u64,
    /// Enable file system monitoring
    pub file_watch_enabled: bool,
    /// Auto-start scanner on system boot
    pub auto_start: bool,
    /// Custom user data paths to monitor
    pub custom_paths: Vec<String>,
    /// Log level for scanner operations
    pub log_level: String,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            scan_all_users: false,
            scan_interval: DEFAULT_SCAN_INTERVAL,
            file_watch_enabled: DEFAULT_FILE_WATCH_ENABLED,
            auto_start: DEFAULT_AUTO_START,
            custom_paths: Vec::new(),
            log_level: "info".to_string(),
        }
    }
}

/// UID package entry for kernel communication
#[repr(C)]
#[derive(Clone, Copy)]
struct UidPackageEntry {
    uid: u32,
    package: [i8; MAX_PACKAGE_NAME],
}

/// UID list data structure for kernel
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

/// Global scanner state
static SCANNER_STATE: Mutex<Option<ScannerState>> = Mutex::new(None);

#[derive(Debug)]
struct ScannerState {
    running: bool,
    config: ScannerConfig,
}

/// System call to communicate with kernel
fn ksu_kernel_call(cmd: u32, arg1: *const u8, arg2: *const u8) -> bool {
    let mut result: i32 = 0;
    let return_value = unsafe {
        libc::prctl(
            KERNEL_SU_OPTION as i32,
            cmd as libc::c_ulong,
            arg1 as libc::c_ulong,
            arg2 as libc::c_ulong,
            &mut result as *mut i32 as libc::c_ulong,
        )
    };

    result == KERNEL_SU_OPTION as i32 && return_value == -1
}

/// Load scanner configuration from file
fn load_scanner_config() -> Result<ScannerConfig> {
    let config_path = Path::new(SCANNER_CONFIG_PATH);
    
    if !config_path.exists() {
        info!("Config file not found, creating default configuration");
        let default_config = ScannerConfig::default();
        save_scanner_config(&default_config)?;
        return Ok(default_config);
    }

    let config_data = fs::read_to_string(config_path)?;
    let config: ScannerConfig = serde_json::from_str(&config_data)
        .unwrap_or_else(|e| {
            warn!("Failed to parse config file: {}, using defaults", e);
            ScannerConfig::default()
        });

    Ok(config)
}

/// Save scanner configuration to file
fn save_scanner_config(config: &ScannerConfig) -> Result<()> {
    let config_path = Path::new(SCANNER_CONFIG_PATH);
    
    // Ensure parent directory exists
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let config_json = serde_json::to_string_pretty(config)?;
    fs::write(config_path, config_json)?;
    
    info!("Configuration saved successfully");
    Ok(())
}

/// Scan user directory and extract package UIDs
fn scan_user_directory(user_id: u32) -> Result<HashMap<String, u32>, Box<dyn std::error::Error>> {
    let mut uid_map = HashMap::new();
    let user_path = format!("{}/{}", USER_DATA_BASE_PATH, user_id);
    let user_data_path = Path::new(&user_path);

    if !user_data_path.exists() {
        info!("User {} data directory not found: {}", user_id, user_path);
        return Ok(uid_map);
    }

    info!("Scanning user {} directory: {}", user_id, user_path);

    let entries = fs::read_dir(user_data_path)?;
    let mut packages_found = 0;
    let mut scan_errors = 0;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!("Failed to read directory entry: {}", e);
                scan_errors += 1;
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
                warn!("Invalid package directory name: {:?}", path);
                scan_errors += 1;
                continue;
            }
        };

        if package_name.len() >= MAX_PACKAGE_NAME {
            warn!("Package name too long (max {}): {}", MAX_PACKAGE_NAME, package_name);
            scan_errors += 1;
            continue;
        }

        let metadata = match path.metadata() {
            Ok(m) => m,
            Err(e) => {
                warn!("Failed to get metadata for package {}: {}", package_name, e);
                scan_errors += 1;
                continue;
            }
        };

        let uid = metadata.uid();
        uid_map.insert(package_name.to_string(), uid);
        packages_found += 1;

        info!("Package found: {} (uid: {}, user: {})", package_name, uid, user_id);
    }

    if scan_errors > 0 {
        warn!("Scan completed with {} errors for user {}", scan_errors, user_id);
    }

    info!(
        "User {} scan complete: {} packages found, {} errors",
        user_id, packages_found, scan_errors
    );

    Ok(uid_map)
}

/// Get all available user IDs from system
fn get_available_user_ids() -> Result<Vec<u32>, Box<dyn std::error::Error>> {
    let mut user_ids = Vec::new();
    let base_path = Path::new(USER_DATA_BASE_PATH);

    if !base_path.exists() {
        return Err(format!("Base user data path not found: {}", USER_DATA_BASE_PATH).into());
    }

    let entries = fs::read_dir(base_path)?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if !path.is_dir() {
            continue;
        }

        if let Some(dir_name) = path.file_name().and_then(|n| n.to_str()) {
            if let Ok(user_id) = dir_name.parse::<u32>() {
                user_ids.push(user_id);
            }
        }
    }

    user_ids.sort();
    info!("Available user IDs: {:?}", user_ids);
    Ok(user_ids)
}

/// Perform comprehensive UID scan
fn perform_uid_scan(scan_all_users: bool) -> Result<HashMap<String, u32>, Box<dyn std::error::Error>> {
    if scan_all_users {
        info!("Starting comprehensive scan for all users");
        let user_ids = get_available_user_ids()?;
        let mut combined_uid_map = HashMap::new();

        for user_id in user_ids {
            match scan_user_directory(user_id) {
                Ok(uid_map) => {
                    for (package, uid) in uid_map {
                        // Create unique package identifier with user info
                        let unique_package = if user_id == 0 {
                            package
                        } else {
                            format!("{}:u{}", package, user_id)
                        };
                        combined_uid_map.insert(unique_package, uid);
                    }
                }
                Err(e) => {
                    warn!("Failed to scan user {}: {}", user_id, e);
                }
            }
        }

        info!("Multi-user scan complete: {} total packages found", combined_uid_map.len());
        Ok(combined_uid_map)
    } else {
        info!("Starting scan for primary user only");
        scan_user_directory(0)
    }
}

/// Send UID list to kernel
fn send_uid_list_to_kernel(uid_map: &HashMap<String, u32>) -> Result<(), Box<dyn std::error::Error>> {
    let mut uid_data = UidListData::new();

    for (package, &uid) in uid_map {
        if !uid_data.add_entry(uid, package) {
            warn!("UID entry limit reached, list truncated at {} entries", MAX_UID_ENTRIES);
            break;
        }
    }

    info!("Sending {} UID entries to kernel", uid_data.count);

    let success = ksu_kernel_call(
        CMD_UPDATE_UID_LIST,
        &uid_data as *const UidListData as *const u8,
        std::ptr::null(),
    );

    if success {
        info!("UID list successfully sent to kernel");
        Ok(())
    } else {
        Err("Kernel communication failed: unable to send UID list".into())
    }
}

/// Execute complete scan and update process
pub fn execute_scan_and_update(scan_all_users: bool) {
    match perform_uid_scan(scan_all_users) {
        Ok(uid_map) => {
            if let Err(e) = send_uid_list_to_kernel(&uid_map) {
                error!("Failed to send UID list to kernel: {}", e);
            }
        }
        Err(e) => {
            error!("UID scan failed: {}", e);
        }
    }
}

/// Start UID scanner with monitoring capability
pub fn start_uid_scanner(scan_all_users: bool) -> Result<()> {
    info!("Initializing UID scanner daemon");

    // Load configuration
    let config = load_scanner_config().unwrap_or_default();

    // Update global state
    {
        let mut state = SCANNER_STATE.lock().unwrap();
        *state = Some(ScannerState {
            running: true,
            config: config.clone(),
        });
    }

    // Perform initial scan
    execute_scan_and_update(scan_all_users);

    // Set up file monitoring in background thread
    if config.file_watch_enabled {
        thread::spawn(move || {
            let _watcher = match setup_file_monitoring(scan_all_users) {
                Ok(w) => {
                    info!("File monitoring initialized successfully");
                    w
                }
                Err(e) => {
                    error!("File monitoring setup failed: {}", e);
                    return;
                }
            };

            info!("UID scanner running with file monitoring enabled");

            // Keep thread alive
            loop {
                thread::sleep(Duration::from_secs(60));
            }
        });
    } else {
        info!("File monitoring disabled by configuration");
    }

    Ok(())
}

/// Set up file system monitoring
fn setup_file_monitoring(scan_all_users: bool) -> Result<RecommendedWatcher, Box<dyn std::error::Error>> {
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
            info!("File monitoring active for packages.list");
        }
    } else {
        warn!("packages.list not found, file monitoring limited");
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
                            info!("packages.list modified, triggering UID scan");
                            thread::sleep(Duration::from_millis(200)); // Wait for file stability
                            execute_scan_and_update(scan_all_users);
                        }
                    }
                }
                Err(e) => {
                    warn!("File monitoring error: {}", e);
                }
            }
        }
    });

    Ok(watcher)
}

// New public functions for CLI interface

/// Start scanner daemon with configuration
pub fn start_scanner_daemon(all_users: bool, config_file: Option<PathBuf>) -> Result<()> {
    if let Some(config_path) = config_file {
        // Load custom config
        let config_data = fs::read_to_string(config_path)?;
        let config: ScannerConfig = serde_json::from_str(&config_data)?;
        save_scanner_config(&config)?;
        info!("Using custom configuration file");
    }

    // Write PID file
    fs::write(SCANNER_PID_FILE, std::process::id().to_string())?;
    
    start_uid_scanner(all_users)
}

/// Stop scanner daemon
pub fn stop_scanner_daemon() -> Result<()> {
    {
        let mut state = SCANNER_STATE.lock().unwrap();
        if let Some(ref mut scanner_state) = state.as_mut() {
            scanner_state.running = false;
        }
    }

    // Remove PID file
    if Path::new(SCANNER_PID_FILE).exists() {
        fs::remove_file(SCANNER_PID_FILE)?;
    }

    info!("Scanner daemon stopped");
    Ok(())
}

/// Trigger manual UID scan
pub fn trigger_manual_scan(all_users: bool) -> Result<()> {
    info!("Manual scan initiated");
    execute_scan_and_update(all_users);
    Ok(())
}

/// Get scanner status
pub fn get_scanner_status() -> Result<String> {
    let state = SCANNER_STATE.lock().unwrap();
    let status = if let Some(ref scanner_state) = *state {
        if scanner_state.running {
            "Running"
        } else {
            "Stopped"
        }
    } else {
        "Not initialized"
    };

    Ok(status.to_string())
}

/// Get configuration value
pub fn get_config(key: Option<String>) -> Result<()> {
    let config = load_scanner_config()?;
    
    match key.as_deref() {
        Some("scan_all_users") => println!("{}", config.scan_all_users),
        Some("scan_interval") => println!("{}", config.scan_interval),
        Some("file_watch_enabled") => println!("{}", config.file_watch_enabled),
        Some("auto_start") => println!("{}", config.auto_start),
        Some("log_level") => println!("{}", config.log_level),
        Some(k) => println!("Unknown configuration key: {}", k),
        None => {
            println!("Scanner Configuration:");
            println!("  scan_all_users: {}", config.scan_all_users);
            println!("  scan_interval: {}", config.scan_interval);
            println!("  file_watch_enabled: {}", config.file_watch_enabled);
            println!("  auto_start: {}", config.auto_start);
            println!("  log_level: {}", config.log_level);
        }
    }
    
    Ok(())
}

/// Set configuration value
pub fn set_config(key: String, value: String) -> Result<()> {
    let mut config = load_scanner_config()?;

    match key.as_str() {
        "scan_all_users" => config.scan_all_users = value.parse()?,
        "scan_interval" => config.scan_interval = value.parse()?,
        "file_watch_enabled" => config.file_watch_enabled = value.parse()?,
        "auto_start" => config.auto_start = value.parse()?,
        "log_level" => config.log_level = value,
        _ => return Err(anyhow::anyhow!("Unknown configuration key: {}", key)),
    }

    save_scanner_config(&config)?;
    Ok(())
}

/// Reset configuration to defaults
pub fn reset_config() -> Result<()> {
    let default_config = ScannerConfig::default();
    save_scanner_config(&default_config)?;
    Ok(())
}

/// Get configuration file path
pub fn get_config_path() -> PathBuf {
    PathBuf::from(SCANNER_CONFIG_PATH)
}

// Legacy function for backward compatibility
pub fn trigger_uid_scan(all_users: bool) -> Result<()> {
    trigger_manual_scan(all_users)
}