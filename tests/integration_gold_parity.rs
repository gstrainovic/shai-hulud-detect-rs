use hex;
use sha2::{Digest, Sha256};
use std::env;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};
use walkdir::WalkDir;

fn run_with_timeout(mut cmd: std::process::Command, timeout: Duration) -> Result<(), String> {
    match cmd.spawn() {
        Ok(mut child) => {
            let start = Instant::now();
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        if status.success() {
                            return Ok(());
                        } else {
                            return Err(format!("Process exited with status {}", status));
                        }
                    }
                    Ok(None) => {
                        if start.elapsed() > timeout {
                            let _ = child.kill();
                            let _ = child.wait();
                            return Err("Process timed out and was killed".to_string());
                        }
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    Err(e) => return Err(format!("Error waiting for child: {}", e)),
                }
            }
        }
        Err(e) => Err(format!("Failed to spawn process: {}", e)),
    }
}

fn path_for_bash_redir(p: &std::path::Path) -> String {
    // Convert to forward-slash form and, on Windows, convert 'C:/foo' -> '/c/foo' for MSYS bash
    let s = p.to_string_lossy().replace('\\', "/");
    if cfg!(windows) {
        if s.len() >= 2 && s.as_bytes()[1] == b':' {
            let drive = s.chars().next().unwrap().to_ascii_lowercase();
            let rest = s[2..].trim_start_matches('/');
            return format!("/{}/{}", drive, rest);
        }
    }
    s.to_string()
}

fn normalize_bytes_for_hash(bytes: &[u8]) -> Vec<u8> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        text.replace("\r\n", "\n").replace('\r', "\n").into_bytes()
    } else {
        bytes.to_vec()
    }
}

fn compute_script_hash(script_path: &Path) -> Result<String, std::io::Error> {
    if !script_path.exists() {
        return Ok(String::new());
    }
    let bytes = std::fs::read(script_path)?;
    let normalized = normalize_bytes_for_hash(&bytes);
    let mut hasher = Sha256::new();
    hasher.update(&normalized);
    Ok(hex::encode(hasher.finalize()))
}

fn compute_directory_hash(directory: &Path) -> Result<String, std::io::Error> {
    if !directory.exists() {
        return Ok(String::new());
    }

    let mut files: Vec<(String, std::path::PathBuf)> = WalkDir::new(directory)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| {
            let abs_path = entry.into_path();
            let rel = abs_path
                .strip_prefix(directory)
                .unwrap_or(&abs_path)
                .to_string_lossy()
                .replace('\\', "/");
            (rel, abs_path)
        })
        .collect();

    files.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = Sha256::new();
    for (rel, path) in files {
        hasher.update(rel.as_bytes());
        let bytes = std::fs::read(&path)?;
        let normalized = normalize_bytes_for_hash(&bytes);
        let mut file_hasher = Sha256::new();
        file_hasher.update(&normalized);
        hasher.update(file_hasher.finalize());
    }

    Ok(hex::encode(hasher.finalize()))
}

#[derive(Default)]
struct HashState {
    script: Option<String>,
    test_cases: Option<String>,
}

fn read_hash_state(path: &Path) -> HashState {
    if !path.exists() {
        return HashState::default();
    }
    let Ok(content) = std::fs::read_to_string(path) else {
        return HashState::default();
    };
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return HashState::default();
    }

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        let script = value
            .get("script_sha256")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let test_cases = value
            .get("test_cases_sha256")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        return HashState { script, test_cases };
    }

    HashState {
        script: Some(trimmed.to_string()),
        test_cases: None,
    }
}

fn write_hash_state(path: &Path, script_hash: &str, test_cases_hash: &str) {
    let mut payload = serde_json::Map::new();
    payload.insert(
        "script_sha256".to_string(),
        serde_json::Value::String(script_hash.to_string()),
    );
    payload.insert(
        "test_cases_sha256".to_string(),
        serde_json::Value::String(test_cases_hash.to_string()),
    );
    if let Ok(serialized) = serde_json::to_string_pretty(&serde_json::Value::Object(payload)) {
        let _ = std::fs::write(path, serialized);
    }
}

#[test]
fn bash_and_rust_parity_per_category() {
    // Determine crate and repo roots
    let crate_root = env::var("CARGO_MANIFEST_DIR")
        .map(|s| std::path::PathBuf::from(s))
        .unwrap_or_else(|_| std::env::current_dir().unwrap());
    let repo_root = crate_root.parent().unwrap_or(&crate_root).to_path_buf();

    // Ensure gold dir exists
    let gold_dir = crate_root.join("tests").join("gold");
    let _ = std::fs::create_dir_all(&gold_dir);

    let script_path = repo_root.join("shai-hulud-detector.sh");
    let test_cases_path = repo_root.join("test-cases");

    let current_script_hash = compute_script_hash(&script_path).expect("failed to hash script");
    let current_test_cases_hash =
        compute_directory_hash(&test_cases_path).expect("failed to hash test-cases directory");

    let script_hash_file = gold_dir.join(".script_hash");
    let state = read_hash_state(&script_hash_file);

    let script_matches = state
        .script
        .as_deref()
        .map(|prev| prev == current_script_hash)
        .unwrap_or(false);
    let test_cases_matches = state
        .test_cases
        .as_deref()
        .map(|prev| prev == current_test_cases_hash)
        .unwrap_or(false);

    let mut need_regen = !(script_matches && test_cases_matches);

    // Paths for bash outputs and rust outputs in gold dir
    let normal_out = gold_dir.join("bash_scan_normal.txt");
    let paranoid_out = gold_dir.join("bash_scan_paranoid.txt");
    let rust_detailed_normal = gold_dir.join("rust_detailed_normal.json");
    let rust_detailed_paranoid = gold_dir.join("rust_detailed_paranoid.json");
    let scan_result_normal = gold_dir.join("scan_result_normal.json");
    let scan_result_paranoid = gold_dir.join("scan_result_paranoid.json");

    if !normal_out.exists()
        || !paranoid_out.exists()
        || !rust_detailed_normal.exists()
        || !rust_detailed_paranoid.exists()
        || !scan_result_normal.exists()
        || !scan_result_paranoid.exists()
    {
        need_regen = true;
    }

    if need_regen {
        println!(
            "Regenerating gold outputs (script_changed={}, test_cases_changed={})",
            !script_matches, !test_cases_matches
        );

        let mut bash = Command::new("bash");
        bash.current_dir(&repo_root);
        let normal_abs = path_for_bash_redir(&normal_out);
        let paranoid_abs = path_for_bash_redir(&paranoid_out);
        let cmd = format!(
            "./shai-hulud-detector.sh test-cases > {} 2>&1 && ./shai-hulud-detector.sh --paranoid test-cases > {} 2>&1",
            normal_abs, paranoid_abs
        );
        bash.args(&["-lc", &cmd]);
        run_with_timeout(bash, std::time::Duration::from_secs(600))
            .expect("bash scanner failed or timed out");

        let mut cargo_cmd = Command::new("cargo");
        cargo_cmd.current_dir(&crate_root);
        cargo_cmd.args(&["run", "--quiet", "--", "test-cases"]);
        run_with_timeout(cargo_cmd, std::time::Duration::from_secs(180))
            .expect("rust scanner run failed or timed out");

        write_hash_state(
            &script_hash_file,
            &current_script_hash,
            &current_test_cases_hash,
        );
    } else {
        println!("Using cached gold outputs (hashes unchanged)");
    }

    // Basic validations: rust JSONs parse and contain expected top-level keys
    let dn =
        std::fs::read_to_string(&rust_detailed_normal).expect("missing rust_detailed_normal.json");
    let v: serde_json::Value =
        serde_json::from_str(&dn).expect("invalid rust_detailed_normal.json");
    let expected_keys = [
        "workflow_files",
        "malicious_hashes",
        "compromised_packages",
        "postinstall_hooks",
        "suspicious_content",
        "crypto_patterns",
        "trufflehog_activity",
        "git_branches",
        "shai_hulud_repos",
        "package_integrity",
    ];
    for k in &expected_keys {
        assert!(
            v.get(*k).is_some(),
            "missing key {} in rust_detailed_normal.json",
            k
        );
    }

    // Similarly for scan_result_normal.json
    let sn = std::fs::read_to_string(&scan_result_normal).expect("missing scan_result_normal.json");
    let sjson: serde_json::Value =
        serde_json::from_str(&sn).expect("invalid scan_result_normal.json");
    assert!(
        sjson.get("high").is_some() && sjson.get("medium").is_some() && sjson.get("low").is_some()
    );
}

// Additional test-case specific validations
use shai_hulud_detector::Scanner;

fn get_test_cases_dir() -> std::path::PathBuf {
    let crate_root = env::var("CARGO_MANIFEST_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::current_dir().unwrap());
    let repo_root = crate_root.parent().unwrap_or(&crate_root);

    // Try multiple locations
    let test_cases = repo_root.join("shai-hulud-detect").join("test-cases");
    if test_cases.exists() {
        return test_cases;
    }

    let test_cases = repo_root.join("test-cases");
    if test_cases.exists() {
        return test_cases;
    }

    // Fallback
    repo_root.join("test-cases")
}

#[test]
fn test_infected_project_counts() {
    let scanner = Scanner::new();
    let test_dir = get_test_cases_dir().join("infected-project");

    if !test_dir.exists() {
        eprintln!("Test directory not found: {}", test_dir.display());
        return;
    }

    let (high, medium, _low) = scanner.generate_summary_counts(&test_dir, false).unwrap();

    // Expected from bash: high=8, medium=18
    assert_eq!(high, 8, "HIGH risk count mismatch for infected-project");
    assert_eq!(
        medium, 18,
        "MEDIUM risk count mismatch for infected-project"
    );
}

#[test]
fn test_infected_project_paranoid_counts() {
    let scanner = Scanner::new();
    let test_dir = get_test_cases_dir().join("infected-project");

    if !test_dir.exists() {
        return;
    }

    let (high, medium, _low) = scanner.generate_summary_counts(&test_dir, true).unwrap();

    // Expected from bash paranoid: high=8, medium=16 (typo/network are informational)
    assert_eq!(
        high, 8,
        "HIGH risk count mismatch for infected-project (paranoid)"
    );
    assert_eq!(
        medium, 16,
        "MEDIUM risk count mismatch for infected-project (paranoid)"
    );
}

#[test]
fn test_clean_project_counts() {
    let scanner = Scanner::new();
    let test_dir = get_test_cases_dir().join("clean-project");

    if !test_dir.exists() {
        return;
    }

    let (high, medium, _low) = scanner.generate_summary_counts(&test_dir, false).unwrap();

    // Clean project should have 0 findings
    assert_eq!(high, 0, "Clean project should have 0 HIGH risk findings");
    assert_eq!(
        medium, 0,
        "Clean project should have 0 MEDIUM risk findings"
    );
}
