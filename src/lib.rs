//! Shai-Hulud detector library - Rust port of the bash scanner

use anyhow::Result;
use rayon::prelude::*;
use regex::Regex;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

mod semver;
pub use semver::{semver_match, SemVer};

#[macro_use]
extern crate lazy_static;
lazy_static! {
    static ref RE_PKG_SIMPLE: Regex = Regex::new(r"^[a-zA-Z@][^:]+:[0-9]+\.[0-9]+\.[0-9]+$").unwrap();
    static ref RE_POSTINSTALL: Regex = Regex::new(r#"postinstall"\s*:\s*"([^"]+)"#).unwrap();
    static ref RE_WEBHOOK: Regex = Regex::new(r"webhook\.site").unwrap();
    static ref RE_UUID: Regex = Regex::new(r"bb8ca5f6-4175-45d2-b042-fc9ebb8170b7").unwrap();
    static ref RE_ETH_ADDR: Regex = Regex::new(r"0x[a-fA-F0-9]{40}").unwrap();
    static ref RE_XMLHTTPPROT: Regex = Regex::new(r"XMLHttpRequest\\.prototype\\.send").unwrap();
    static ref RE_KNOWN_CRYPTO: Regex = Regex::new(r"checkethereumw|runmask|newdlocal|_0x19ca67").unwrap();
    static ref RE_ATT_WALLETS: Regex = Regex::new(r"0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976|1H13VnQJKtT4HjD5ZFKaaiZEetMbG7nDHx|TB9emsCq6fQw6wRk4HBxxNnU6Hwt1DnV67").unwrap();
    static ref RE_PHISHING: Regex = Regex::new(r"npmjs\.help").unwrap();
    static ref RE_OBF: Regex = Regex::new(r"javascript-obfuscator").unwrap();
    static ref RE_ETH_KEYWORDS: Regex = Regex::new(r"ethereum|wallet|address|crypto").unwrap();
    static ref RE_CRED_KEYS: Regex = Regex::new(r"AWS_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN").unwrap();
    static ref RE_PROCESS_ENV: Regex = Regex::new(r"process\.env|os\.environ|getenv").unwrap();
    static ref RE_INTEGRITY: Regex = Regex::new(r#"integrity": "sha[0-9]+-[A-Za-z0-9+/=]*"#).unwrap();
    static ref RE_DEPS_BLOCK: Regex = Regex::new(r#""dependencies""\s*:\s*\{([\s\S]*?)\}"#).unwrap();
    static ref RE_DEP_NAME: Regex = Regex::new(r#""\s*([a-zA-Z@][^"\s]+)"\s*:"#).unwrap();
    static ref RE_IP: Regex = Regex::new(r"[0-9]{1,3}(\.[0-9]{1,3}){3}").unwrap();
    static ref RE_WSS: Regex = Regex::new(r#"wss?://[^"'\s]*"#).unwrap();
    static ref RE_NETWORK_CALLS: Regex = Regex::new(r"(fetch|XMLHttpRequest|axios)").unwrap();
    static ref RE_AUTH_HEADER: Regex = Regex::new(r"(Authorization:|Basic |Bearer )").unwrap();
    // additional precompiled regexes
    static ref RE_CRYPTO_SNIPPET: Regex = Regex::new(r"ethereum.*0x\[a-fA-F0-9\]|bitcoin.*\[13\]\[a-km-zA-HJ-NP-Z1-9\]").unwrap();
}

// Load compromised packages from a file
fn load_compromised_packages() -> Result<Vec<String>, anyhow::Error> {
    fn read_list(path: &Path) -> Result<Vec<String>, anyhow::Error> {
        let content = fs::read_to_string(path)?;
        let mut packages = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if RE_PKG_SIMPLE.is_match(line) {
                packages.push(line.to_string());
            }
        }
        Ok(packages)
    }

    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(current) = env::current_dir() {
        candidates.push(current.join("compromised-packages.txt"));
        if let Some(parent) = current.parent() {
            candidates.push(parent.join("compromised-packages.txt"));
        }
    }

    if let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") {
        let manifest = PathBuf::from(manifest_dir);
        candidates.push(manifest.join("compromised-packages.txt"));
        if let Some(parent) = manifest.parent() {
            candidates.push(parent.join("compromised-packages.txt"));
        }
    }

    for candidate in candidates {
        if candidate.exists() {
            return read_list(&candidate);
        }
    }

    let fallback = Path::new("compromised-packages.txt");
    if fallback.exists() {
        return read_list(fallback);
    }

    anyhow::bail!("compromised-packages.txt not found");
}

pub struct Scanner {
    pub malicious_hashes: HashSet<String>,
    pub compromised_packages: Vec<String>,
    pub compromised_namespaces: Vec<String>,
    pub parallelism: usize,
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner {
    pub fn new() -> Self {
        let compromised_namespaces = vec![
            "@crowdstrike".to_string(),
            "@art-ws".to_string(),
            "@ngx".to_string(),
            "@ctrl".to_string(),
            "@nativescript-community".to_string(),
            "@ahmedhfarag".to_string(),
            "@operato".to_string(),
            "@teselagen".to_string(),
            "@things-factory".to_string(),
            "@hestjs".to_string(),
            "@nstudio".to_string(),
            "@basic-ui-components-stc".to_string(),
            "@nexe".to_string(),
            "@thangved".to_string(),
            "@tnf-dev".to_string(),
            "@ui-ux-gang".to_string(),
            "@yoobic".to_string(),
        ];

        // Known malicious SHA-256 hashes (copied from bash script)
        let malicious_hashes_raw = vec![
            "de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6",
            "81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3",
            "83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e",
            "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db",
            "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c",
            "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09",
            "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777",
            "86532ed94c5804e1ca32fa67257e1bb9de628e3e48a1f56e67042dc055effb5b",
            "aba1fcbd15c6ba6d9b96e34cec287660fff4a31632bf76f2a766c499f55ca1ee",
        ];

        let malicious_hashes = malicious_hashes_raw
            .into_iter()
            .map(|s| s.to_string())
            .collect();

        let compromised_packages = load_compromised_packages().unwrap_or_else(|_| {
            vec![
                "@ctrl/tinycolor:4.1.0".to_string(),
                "@ctrl/tinycolor:4.1.1".to_string(),
                "@ctrl/tinycolor:4.1.2".to_string(),
                "@ctrl/deluge:1.2.0".to_string(),
                "angulartics2:14.1.2".to_string(),
                "koa2-swagger-ui:5.11.1".to_string(),
                "koa2-swagger-ui:5.11.2".to_string(),
            ]
        });

        Scanner {
            malicious_hashes,
            compromised_packages,
            compromised_namespaces,
            parallelism: num_cpus::get(),
        }
    }

    pub fn set_parallelism(&mut self, p: usize) {
        self.parallelism = p;
    }

    pub fn check_workflow_files(&self, scan_dir: &Path) -> Vec<PathBuf> {
        let mut findings = Vec::new();
        for entry in WalkDir::new(scan_dir).into_iter().filter_map(Result::ok) {
            if entry.file_type().is_file() && entry.file_name() == "shai-hulud-workflow.yml" {
                let p = entry.path().to_path_buf();
                findings.push(p);
            }
        }
        findings
    }

    pub fn check_file_hashes(&self, scan_dir: &Path) -> Result<Vec<(PathBuf, String)>> {
        // Collect files with given extensions
        let exts = ["js", "ts", "json"];
        let walker: Vec<_> = WalkDir::new(scan_dir)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|s| s.to_str())
                    .map(|s| exts.contains(&s))
                    .unwrap_or(false)
            })
            .map(|e| e.into_path())
            .collect();

        // Compute sha256 in parallel
        let results: Vec<(PathBuf, String)> = walker
            .par_iter()
            .map(|path| {
                let data = fs::read(path);
                let p = path.clone();
                if let Ok(bytes) = data {
                    let mut hasher = Sha256::new();
                    hasher.update(&bytes);
                    let hash = hex::encode(hasher.finalize());
                    Some((p, hash))
                } else {
                    None
                }
            })
            .filter_map(|opt| opt)
            .filter(|(_, hash)| self.malicious_hashes.contains(hash))
            .collect();

        Ok(results)
    }

    /// Check packages - returns three separate result types like bash
    /// Returns: (compromised_exact, suspicious_semver, namespace_warnings)
    pub fn check_packages(
        &self,
        scan_dir: &Path,
    ) -> Result<(
        Vec<(PathBuf, String)>,
        Vec<(PathBuf, String)>,
        Vec<(PathBuf, String)>,
    )> {
        let mut compromised_found = Vec::new();
        let mut suspicious_found = Vec::new();
        let mut namespace_warnings = Vec::new();

        for entry in WalkDir::new(scan_dir).into_iter().filter_map(Result::ok) {
            if entry.file_type().is_file() && entry.file_name() == "package.json" {
                let path = entry.path().to_path_buf();
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(root) = serde_json::from_str::<JsonValue>(&content) {
                        let mut added_namespaces: HashSet<String> = HashSet::new();

                        // Check all dependency sections
                        for dep_key in [
                            "dependencies",
                            "devDependencies",
                            "peerDependencies",
                            "optionalDependencies",
                        ]
                        .iter()
                        {
                            if let Some(deps) = root.get(*dep_key).and_then(|d| d.as_object()) {
                                for (package_name, version_value) in deps.iter() {
                                    let package_version = version_value.as_str().unwrap_or("");

                                    // Check against compromised packages
                                    for malicious_info in &self.compromised_packages {
                                        let mut parts = malicious_info.splitn(2, ':');
                                        let malicious_name = parts.next().unwrap_or("");
                                        let malicious_version = parts.next().unwrap_or("");

                                        if package_name != malicious_name {
                                            continue;
                                        }

                                        // Exact match (with or without semver operators)
                                        let clean_version =
                                            package_version.trim().trim_start_matches(|c: char| {
                                                c == '^'
                                                    || c == '~'
                                                    || c == '>'
                                                    || c == '='
                                                    || c == '<'
                                            });

                                        if clean_version == malicious_version {
                                            // Exact match - definitely compromised
                                            compromised_found.push((
                                                path.clone(),
                                                format!("{}@{}", package_name, malicious_version),
                                            ));
                                        } else if semver_match(malicious_version, package_version) {
                                            // Semver pattern match - potentially compromised
                                            suspicious_found.push((
                                                path.clone(),
                                                format!("{}@{}", package_name, package_version),
                                            ));
                                        }
                                    }

                                    // Check for compromised namespaces
                                    for namespace in &self.compromised_namespaces {
                                        if package_name.starts_with(namespace)
                                            && !added_namespaces.contains(namespace)
                                        {
                                            namespace_warnings.push((
                                                path.clone(),
                                                format!("Contains packages from compromised namespace: {}", namespace),
                                            ));
                                            added_namespaces.insert(namespace.clone());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok((compromised_found, suspicious_found, namespace_warnings))
    }

    pub fn check_postinstall_hooks(&self, scan_dir: &Path) -> Result<Vec<(PathBuf, String)>> {
        let mut findings = Vec::new();
        for entry in WalkDir::new(scan_dir).into_iter().filter_map(Result::ok) {
            if entry.file_type().is_file() {
                // Accept package.json and other json files that start with "package" (e.g. package-with-postinstall.json)
                let fname = entry.file_name().to_string_lossy().to_string();
                if !fname.starts_with("package")
                    || entry.path().extension().and_then(|s| s.to_str()) != Some("json")
                {
                    continue;
                }
                let path = entry.path().to_path_buf();
                if let Ok(content) = fs::read_to_string(&path) {
                    if content.contains("\"postinstall\"") {
                        // crude extraction
                        if let Some(caps) = RE_POSTINSTALL.captures(&content) {
                            let cmd = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                            if cmd.contains("curl")
                                || cmd.contains("wget")
                                || cmd.contains("node -e")
                                || cmd.contains("eval")
                            {
                                findings.push((
                                    path.clone(),
                                    format!("Suspicious postinstall: {}", cmd),
                                ));
                            }
                        }
                    }
                }
            }
        }
        Ok(findings)
    }

    pub fn check_content(&self, scan_dir: &Path) -> Result<Vec<(PathBuf, String)>> {
        let mut findings = Vec::new();
        let re_webhook = &*RE_WEBHOOK;
        let re_uuid = &*RE_UUID;

        for entry in WalkDir::new(scan_dir).into_iter().filter_map(Result::ok) {
            if entry.file_type().is_file() {
                if let Some(ext) = entry.path().extension().and_then(|s| s.to_str()) {
                    if ["js", "ts", "json", "yml", "yaml"].contains(&ext) {
                        if let Ok(content) = fs::read_to_string(entry.path()) {
                            let p = entry.path().to_path_buf();
                            if re_webhook.is_match(&content) {
                                findings.push((p.clone(), "webhook.site reference".to_string()));
                            }
                            if re_uuid.is_match(&content) {
                                findings
                                    .push((p.clone(), "malicious webhook endpoint".to_string()));
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    pub fn check_crypto_theft_patterns(&self, scan_dir: &Path) -> Result<Vec<(PathBuf, String)>> {
        let mut findings = Vec::new();
        let re_eth_addr = &*RE_ETH_ADDR;
        let re_xmlhttpprot = &*RE_XMLHTTPPROT;
        let re_known = &*RE_KNOWN_CRYPTO;
        let re_attacker_wallets = &*RE_ATT_WALLETS;
        let re_phishing = &*RE_PHISHING;
        let re_obf = &*RE_OBF;

        for entry in WalkDir::new(scan_dir).into_iter().filter_map(Result::ok) {
            if entry.file_type().is_file() {
                if let Some(ext) = entry.path().extension().and_then(|s| s.to_str()) {
                    if ["js", "ts", "json"].contains(&ext) {
                        if let Ok(content) = fs::read_to_string(entry.path()) {
                            let p = entry.path().to_path_buf();
                            if re_eth_addr.is_match(&content) && RE_ETH_KEYWORDS.is_match(&content)
                            {
                                findings.push((
                                    p.clone(),
                                    "Ethereum wallet address patterns detected".to_string(),
                                ));
                            }
                            if re_xmlhttpprot.is_match(&content) {
                                // Context-aware XMLHttpRequest detection (matching bash logic)
                                let path_str = p.to_string_lossy();
                                let is_framework = path_str.contains("/react-native/Libraries/Network/")
                                    || path_str.contains("/next/dist/compiled/");
                                let has_crypto_patterns = re_eth_addr.is_match(&content)
                                    || re_known.is_match(&content)
                                    || content.contains("webhook.site")
                                    || re_phishing.is_match(&content);

                                if is_framework {
                                    if has_crypto_patterns {
                                        findings.push((
                                            p.clone(),
                                            "XMLHttpRequest prototype modification with crypto patterns detected - HIGH RISK"
                                                .to_string(),
                                        ));
                                    } else {
                                        findings.push((
                                            p.clone(),
                                            "XMLHttpRequest prototype modification detected in framework code - LOW RISK"
                                                .to_string(),
                                        ));
                                    }
                                } else {
                                    if has_crypto_patterns {
                                        findings.push((
                                            p.clone(),
                                            "XMLHttpRequest prototype modification with crypto patterns detected - HIGH RISK"
                                                .to_string(),
                                        ));
                                    } else {
                                        findings.push((
                                            p.clone(),
                                            "XMLHttpRequest prototype modification detected - MEDIUM RISK"
                                                .to_string(),
                                        ));
                                    }
                                }
                            }
                            if re_known.is_match(&content) {
                                findings.push((
                                    p.clone(),
                                    "Known crypto theft function names detected".to_string(),
                                ));
                            }
                            if re_attacker_wallets.is_match(&content) {
                                findings.push((
                                    p.clone(),
                                    "Known attacker wallet address detected - HIGH RISK"
                                        .to_string(),
                                ));
                            }
                            if re_phishing.is_match(&content) {
                                findings.push((
                                    p.clone(),
                                    "Phishing domain npmjs.help detected".to_string(),
                                ));
                            }
                            if re_obf.is_match(&content) {
                                findings.push((
                                    p.clone(),
                                    "JavaScript obfuscation detected".to_string(),
                                ));
                            }
                            if RE_CRYPTO_SNIPPET.is_match(&content) {
                                findings.push((
                                    p.clone(),
                                    "Cryptocurrency regex patterns detected".to_string(),
                                ));
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    pub fn check_trufflehog_activity(
        &self,
        scan_dir: &Path,
    ) -> Result<Vec<(PathBuf, String, String)>> {
        // return tuple (path, risk_level, info)
        let mut findings = Vec::new();

        // Look for trufflehog binaries
        for entry in WalkDir::new(scan_dir).into_iter().filter_map(Result::ok) {
            if entry.file_type().is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.to_lowercase().contains("trufflehog") {
                        findings.push((
                            entry.path().to_path_buf(),
                            "HIGH".to_string(),
                            "Trufflehog binary found".to_string(),
                        ));
                    }
                }
            }
        }

        // search content for trufflehog references
        for entry in WalkDir::new(scan_dir).into_iter().filter_map(Result::ok) {
            if entry.file_type().is_file() {
                if let Some(ext) = entry.path().extension().and_then(|s| s.to_str()) {
                    if ["js", "py", "sh", "json"].contains(&ext) {
                        if let Ok(content) = fs::read_to_string(entry.path()) {
                            let p = entry.path().to_path_buf();
                            if content.contains("trufflehog") || content.contains("TruffleHog") {
                                let context = Self::get_file_context(&p);
                                match context.as_str() {
                                    "documentation" => continue,
                                    "node_modules" | "type_definitions" | "build_output" => {
                                        findings.push((
                                            entry.path().to_path_buf(),
                                            "MEDIUM".to_string(),
                                            format!(
                                                "Contains trufflehog references in {}",
                                                context
                                            ),
                                        ));
                                    }
                                    _ => {
                                        let sample =
                                            content.lines().take(20).collect::<Vec<_>>().join(" ");
                                        if sample.contains("subprocess") && sample.contains("curl")
                                        {
                                            findings.push((
                                                entry.path().to_path_buf(),
                                                "HIGH".to_string(),
                                                "Suspicious trufflehog execution pattern"
                                                    .to_string(),
                                            ));
                                        } else {
                                            findings.push((
                                                entry.path().to_path_buf(),
                                                "MEDIUM".to_string(),
                                                "Contains trufflehog references in source code"
                                                    .to_string(),
                                            ));
                                        }
                                    }
                                }
                            }

                            if RE_CRED_KEYS.is_match(&content) {
                                let context = Self::get_file_context(&p);
                                match context.as_str() {
                                    "type_definitions" | "documentation" => continue,
                                    "node_modules" => findings.push((
                                        entry.path().to_path_buf(),
                                        "LOW".to_string(),
                                        "Credential patterns in node_modules".to_string(),
                                    )),
                                    "configuration" => {
                                        let sample =
                                            content.lines().take(20).collect::<Vec<_>>().join(" ");
                                        if sample.contains("DefinePlugin")
                                            || sample.contains("webpack")
                                        {
                                            continue;
                                        }
                                        findings.push((
                                            entry.path().to_path_buf(),
                                            "MEDIUM".to_string(),
                                            "Credential patterns in configuration".to_string(),
                                        ));
                                    }
                                    _ => {
                                        let sample =
                                            content.lines().take(20).collect::<Vec<_>>().join(" ");
                                        if sample.contains("webhook.site")
                                            || sample.contains("curl")
                                            || sample.contains("https.request")
                                        {
                                            findings.push((
                                                entry.path().to_path_buf(),
                                                "HIGH".to_string(),
                                                "Credential patterns with potential exfiltration"
                                                    .to_string(),
                                            ));
                                        } else {
                                            findings.push((
                                                entry.path().to_path_buf(),
                                                "MEDIUM".to_string(),
                                                "Contains credential scanning patterns".to_string(),
                                            ));
                                        }
                                    }
                                }
                            }

                            if RE_PROCESS_ENV.is_match(&content) {
                                let context = Self::get_file_context(&p);
                                match context.as_str() {
                                    "type_definitions" | "documentation" => continue,
                                    "node_modules" | "build_output" => {
                                        if Self::is_legitimate_pattern(&p, &content) {
                                            continue;
                                        }
                                        findings.push((
                                            entry.path().to_path_buf(),
                                            "LOW".to_string(),
                                            format!("Environment variable access in {}", context),
                                        ));
                                    }
                                    "configuration" => continue,
                                    _ => {
                                        let sample =
                                            content.lines().take(20).collect::<Vec<_>>().join(" ");
                                        if sample.contains("webhook.site")
                                            && sample.contains("exfiltrat")
                                        {
                                            findings.push((
                                                entry.path().to_path_buf(),
                                                "HIGH".to_string(),
                                                "Environment scanning with exfiltration"
                                                    .to_string(),
                                            ));
                                        } else if (sample.contains("scan")
                                            || sample.contains("harvest")
                                            || sample.contains("steal"))
                                            && !Self::is_legitimate_pattern(&p, &content)
                                        {
                                            findings.push((entry.path().to_path_buf(), "MEDIUM".to_string(), "Potentially suspicious environment variable access".to_string()));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    pub fn check_shai_hulud_repos(&self, scan_dir: &Path) -> Result<Vec<(PathBuf, String)>> {
        let mut findings = Vec::new();
        for entry in WalkDir::new(scan_dir).into_iter().filter_map(Result::ok) {
            if entry.file_type().is_dir() && entry.file_name() == ".git" {
                let repo_dir = entry.path().parent().unwrap().to_path_buf();
                if let Some(repo_name) = repo_dir.file_name().and_then(|s| s.to_str()) {
                    if repo_name.contains("shai-hulud") || repo_name.contains("Shai-Hulud") {
                        findings.push((
                            repo_dir.clone(),
                            "Repository name contains 'Shai-Hulud'".to_string(),
                        ));
                    }
                    if repo_name.ends_with("-migration") {
                        findings.push((
                            repo_dir.clone(),
                            "Repository name contains migration pattern".to_string(),
                        ));
                    }
                }
                // check config remote
                let git_config = entry.path().join("config");
                if git_config.exists() {
                    if let Ok(cfg) = fs::read_to_string(&git_config) {
                        if cfg.contains("shai-hulud") || cfg.contains("Shai-Hulud") {
                            findings.push((
                                repo_dir.clone(),
                                "Git remote contains 'Shai-Hulud'".to_string(),
                            ));
                        }
                    }
                }
                // check data.json
                let data_json = repo_dir.join("data.json");
                if data_json.exists() {
                    if let Ok(sample) = fs::read_to_string(&data_json) {
                        if sample.contains("eyJ") && sample.contains("==") {
                            findings.push((repo_dir.clone(), "Contains suspicious data.json (possible base64-encoded credentials)".to_string()));
                        }
                    }
                }
            }
        }
        Ok(findings)
    }

    pub fn check_package_integrity(&self, scan_dir: &Path) -> Result<Vec<(PathBuf, String)>> {
        let mut findings = Vec::new();
        for entry in WalkDir::new(scan_dir).into_iter().filter_map(Result::ok) {
            if entry.file_type().is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    if name == "package-lock.json"
                        || name == "yarn.lock"
                        || name == "pnpm-lock.yaml"
                    {
                        let lock_path = entry.path().to_path_buf();
                        let mut org_file = lock_path.clone();
                        let mut working_path = lock_path.clone();
                        if name == "pnpm-lock.yaml" {
                            // transform pnpm into pseudo package-lock - crude approach using serde_yaml
                            if let Ok(y) = fs::read_to_string(&lock_path) {
                                if let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&y) {
                                    if let Some(pkgs) = doc.get("packages") {
                                        if let Ok(tmp) = tempfile::NamedTempFile::new() {
                                            let mut out = String::from("{\n  \"packages\": {\n");
                                            if let Some(map) = pkgs.as_mapping() {
                                                for (k, _v) in map {
                                                    if let Some(kstr) = k.as_str() {
                                                        // split name@version
                                                        if kstr.contains('@') {
                                                            let parts: Vec<_> =
                                                                kstr.split('@').collect();
                                                            if parts.len() == 2 {
                                                                out.push_str(&format!("    \"{}\": {{\n      \"version\": \"{}\"\n    }},\n", parts[0], parts[1]));
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            out.push_str("  }\n}\n");
                                            fs::write(tmp.path(), out).ok();
                                            working_path = tmp.path().to_path_buf();
                                            org_file = lock_path.clone();
                                        }
                                    }
                                }
                            }
                        }

                        if let Ok(content) = fs::read_to_string(&working_path) {
                            for pkg in &self.compromised_packages {
                                let package_name = pkg.split(':').next().unwrap_or("");
                                let version = pkg.split(':').nth(1).unwrap_or("");
                                // look for the package key followed by a nearby "version": "x.y.z"
                                let pkg_pattern = format!(
                                    r#""{}"\s*:\s*\{{[\s\S]{{0,200}}"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)""#,
                                    regex::escape(package_name)
                                );
                                if let Ok(re_pkg) = Regex::new(&pkg_pattern) {
                                    if let Some(caps) = re_pkg.captures(&content) {
                                        if let Some(found_version) = caps.get(1) {
                                            if found_version.as_str() == version {
                                                findings.push((
                                                    org_file.clone(),
                                                    format!(
                                                        "Compromised package in lockfile: {}@{}",
                                                        package_name, version
                                                    ),
                                                ));
                                            }
                                        }
                                    }
                                }
                            }

                            let count = RE_INTEGRITY.find_iter(&content).count();
                            if count > 0 {
                                findings.push((
                                    org_file.clone(),
                                    "Suspicious integrity hash patterns".to_string(),
                                ));
                            }

                            if content.contains("@ctrl") {
                                // check modification time
                                if let Ok(metadata) = fs::metadata(&lock_path) {
                                    if let Ok(mtime) = metadata.modified() {
                                        if let Ok(duration) = mtime.elapsed() {
                                            if duration.as_secs() < 2592000 {
                                                findings.push((org_file.clone(), "Recently modified lockfile contains @ctrl packages (potential worm activity)".to_string()));
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // tmp file will be dropped, no need to remove explicitly
                    }
                }
            }
        }
        Ok(findings)
    }

    pub fn check_typosquatting(&self, scan_dir: &Path) -> Result<Vec<(PathBuf, String)>> {
        let mut findings = Vec::new();
        let popular_packages = vec![
            "react",
            "vue",
            "angular",
            "express",
            "lodash",
            "axios",
            "typescript",
            "webpack",
            "babel",
            "eslint",
            "jest",
            "mocha",
            "chalk",
            "debug",
            "commander",
            "inquirer",
            "yargs",
            "request",
            "moment",
            "underscore",
            "jquery",
            "bootstrap",
            "socket.io",
            "redis",
            "mongoose",
            "passport",
        ];

        for entry in WalkDir::new(scan_dir).into_iter().filter_map(Result::ok) {
            if entry.file_type().is_file() && entry.file_name() == "package.json" {
                let path = entry.into_path();
                if let Ok(content) = fs::read_to_string(&path) {
                    // extract package names from dependencies sections crudely
                    let deps_re = &*RE_DEPS_BLOCK;
                    if let Some(caps) = deps_re.captures(&content) {
                        let block = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                        for line in block.lines() {
                            if let Some(name_caps) = RE_DEP_NAME.captures(line) {
                                let package_name =
                                    name_caps.get(1).map(|m| m.as_str()).unwrap_or("");
                                if package_name.len() < 2 {
                                    continue;
                                }
                                if !package_name.chars().any(|c| c.is_alphabetic()) {
                                    continue;
                                }
                                if !package_name.is_ascii() {
                                    findings.push((
                                        path.clone(),
                                        format!(
                                            "Potential Unicode/homoglyph characters in package: {}",
                                            package_name
                                        ),
                                    ));
                                }
                                // simple confusable checks
                                let confusables =
                                    vec!["rn:m", "vv:w", "cl:d", "ii:i", "nn:n", "oo:o"];
                                for conf in confusables {
                                    let parts: Vec<&str> = conf.split(':').collect();
                                    if package_name.contains(parts[0]) {
                                        findings.push((path.clone(), format!("Potential typosquatting pattern '{}' in package: {}", parts[0], package_name)));
                                    }
                                }
                                for popular in &popular_packages {
                                    if package_name == *popular {
                                        continue;
                                    }
                                    if package_name.len() == popular.len() && package_name.len() > 4
                                    {
                                        let diff = package_name
                                            .chars()
                                            .zip(popular.chars())
                                            .filter(|(a, b)| a != b)
                                            .count();
                                        if diff == 1
                                            && !package_name.contains('-')
                                            && !popular.contains('-')
                                        {
                                            findings.push((path.clone(), format!("Potential typosquatting of '{}': {} (1 character difference)", popular, package_name)));
                                        }
                                    }
                                    if package_name.len() == popular.len() - 1 {
                                        for i in 0..=popular.len() {
                                            let test_name =
                                                format!("{}{}", &popular[..i], &popular[i + 1..]);
                                            if package_name == test_name {
                                                findings.push((path.clone(), format!("Potential typosquatting of '{}': {} (missing character)", popular, package_name)));
                                            }
                                        }
                                    }
                                    if package_name.len() == popular.len() + 1 {
                                        for i in 0..=package_name.len() {
                                            let test_name = format!(
                                                "{}{}",
                                                &package_name[..i],
                                                &package_name[i + 1..]
                                            );
                                            if test_name == *popular {
                                                findings.push((path.clone(), format!("Potential typosquatting of '{}': {} (extra character)", popular, package_name)));
                                            }
                                        }
                                    }
                                }
                                if package_name.starts_with('@') {
                                    let namespace = package_name.split('/').next().unwrap_or("");
                                    let suspicious_namespaces = vec![
                                        "@types",
                                        "@angular",
                                        "@typescript",
                                        "@react",
                                        "@vue",
                                        "@babel",
                                    ];
                                    for suspicious in suspicious_namespaces {
                                        if namespace != suspicious
                                            && namespace.contains(&suspicious[1..])
                                        {
                                            let ns_clean = &namespace[1..];
                                            let sus_clean = &suspicious[1..];
                                            if ns_clean.len() == sus_clean.len() {
                                                let ns_diff = ns_clean
                                                    .chars()
                                                    .zip(sus_clean.chars())
                                                    .filter(|(a, b)| a != b)
                                                    .count();
                                                if (1..=2).contains(&ns_diff) {
                                                    findings.push((path.clone(), format!("Suspicious namespace variation: {} (similar to {})", namespace, suspicious)));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    pub fn check_network_exfiltration(&self, scan_dir: &Path) -> Result<Vec<(PathBuf, String)>> {
        let mut findings = Vec::new();
        let suspicious_domains = vec![
            "pastebin.com",
            "hastebin.com",
            "ix.io",
            "0x0.st",
            "transfer.sh",
            "file.io",
            "anonfiles.com",
            "mega.nz",
            "dropbox.com/s/",
            "discord.com/api/webhooks",
            "telegram.org",
            "t.me",
            "ngrok.io",
            "localtunnel.me",
            "serveo.net",
            "requestbin.com",
            "webhook.site",
            "beeceptor.com",
            "pipedream.com",
            "zapier.com/hooks",
        ];

        for entry in WalkDir::new(scan_dir).into_iter().filter_map(Result::ok) {
            if entry.file_type().is_file() {
                if let Some(ext) = entry.path().extension().and_then(|s| s.to_str()) {
                    if ["js", "ts", "json", "mjs"].contains(&ext) {
                        if let Ok(content) = fs::read_to_string(entry.path()) {
                            if !entry.path().to_string_lossy().contains("/vendor/")
                                && !entry.path().to_string_lossy().contains("/node_modules/")
                                && RE_IP.is_match(&content)
                                && !content.contains("127.0.0.1")
                                && !content.contains("0.0.0.0")
                            {
                                findings.push((
                                    entry.path().to_path_buf(),
                                    "Hardcoded IP addresses found".to_string(),
                                ));
                            }
                            if !entry.path().to_string_lossy().contains("package-lock.json")
                                && !entry.path().to_string_lossy().contains("yarn.lock")
                                && !entry.path().to_string_lossy().contains("/vendor/")
                                && !entry.path().to_string_lossy().contains("/node_modules/")
                            {
                                for domain in &suspicious_domains {
                                    if content.contains(domain) {
                                        let snippet = content.lines().next().unwrap_or("");
                                        findings.push((
                                            entry.path().to_path_buf(),
                                            format!(
                                                "Suspicious domain found: {}: {}",
                                                domain,
                                                snippet.chars().take(80).collect::<String>()
                                            ),
                                        ));
                                    }
                                }
                            }

                            if !entry.path().to_string_lossy().contains("/vendor/")
                                && !entry.path().to_string_lossy().contains("/node_modules/")
                                && (content.contains("atob(") || content.contains("base64"))
                            {
                                findings.push((
                                    entry.path().to_path_buf(),
                                    "Base64 decoding detected".to_string(),
                                ));
                            }

                            if content.contains("dns-query")
                                || content.contains("application/dns-message")
                            {
                                findings.push((
                                    entry.path().to_path_buf(),
                                    "DNS-over-HTTPS pattern detected".to_string(),
                                ));
                            }

                            if content.contains("wss://") || content.contains("ws://") {
                                for cap in RE_WSS.find_iter(&content) {
                                    let endpoint = cap.as_str();
                                    if !endpoint.contains("localhost")
                                        && !endpoint.contains("127.0.0.1")
                                    {
                                        findings.push((
                                            entry.path().to_path_buf(),
                                            format!(
                                                "WebSocket connection to external endpoint: {}",
                                                endpoint
                                            ),
                                        ));
                                    }
                                }
                            }

                            if content.contains("X-Exfiltrate")
                                || content.contains("X-Data-Export")
                                || content.contains("X-Credential")
                            {
                                findings.push((
                                    entry.path().to_path_buf(),
                                    "Suspicious HTTP headers detected".to_string(),
                                ));
                            }

                            if !entry.path().to_string_lossy().contains("/vendor/")
                                && !entry.path().to_string_lossy().contains("/node_modules/")
                                && !entry.path().to_string_lossy().contains(".min.js")
                                && content.contains("btoa(")
                                && RE_NETWORK_CALLS.is_match(&content)
                                && !RE_AUTH_HEADER.is_match(&content)
                            {
                                findings.push((
                                    entry.path().to_path_buf(),
                                    "Suspicious base64 encoding near network operation".to_string(),
                                ));
                            }
                        }
                    }
                }
            }
        }
        Ok(findings)
    }

    pub fn generate_summary_counts(
        &self,
        scan_dir: &Path,
        paranoid: bool,
    ) -> Result<(usize, usize, usize)> {
        // high, medium, low
        let mut high = 0usize;
        let mut medium = 0usize;
        let mut low = 0usize;

        // workflow files -> HIGH
        let wf = self.check_workflow_files(scan_dir);
        high += wf.len();

        // file hashes -> HIGH
        if let Ok(hashes) = self.check_file_hashes(scan_dir) {
            high += hashes.len();
        }

        // packages -> compromised (HIGH), suspicious (MEDIUM), namespaces (LOW - informational)
        if let Ok((compromised, suspicious, namespaces)) = self.check_packages(scan_dir) {
            high += compromised.len();
            medium += suspicious.len();
            low += namespaces.len(); // Bash counts these as LOW RISK
        }

        // postinstall hooks -> HIGH
        if let Ok(posts) = self.check_postinstall_hooks(scan_dir) {
            high += posts.len();
        }

        // suspicious content -> MEDIUM
        if let Ok(susp) = self.check_content(scan_dir) {
            medium += susp.len();
        }

        // crypto patterns -> split high/medium/low according to message
        if let Ok(cryptos) = self.check_crypto_theft_patterns(scan_dir) {
            for (_p, info) in cryptos {
                if info.contains("HIGH RISK") {
                    high += 1;
                } else if info.contains("LOW RISK") {
                    low += 1;
                } else {
                    medium += 1;
                }
            }
        }

        // trufflehog -> based on provided risk levels
        if let Ok(truffs) = self.check_trufflehog_activity(scan_dir) {
            for (_p, risk, _info) in truffs {
                match risk.as_str() {
                    "HIGH" => high += 1,
                    "MEDIUM" => medium += 1,
                    "LOW" => low += 1,
                    _ => medium += 1,
                }
            }
        }

        // git branches -> MEDIUM
        if let Ok(branches) = self.check_git_branches(scan_dir) {
            medium += branches.len();
        }

        // shai-hulud repos -> HIGH
        if let Ok(repos) = self.check_shai_hulud_repos(scan_dir) {
            high += repos.len();
        }

        // package integrity -> MEDIUM
        if let Ok(integ) = self.check_package_integrity(scan_dir) {
            medium += integ.len();
        }

        // typosquatting and network exfiltration are checked in paranoid mode
        // but NOT counted in summary (informational only, like bash)
        // They are still included in detailed_report
        if paranoid {
            // Just run the checks for detailed report, don't count
            let _ = self.check_typosquatting(scan_dir);
            let _ = self.check_network_exfiltration(scan_dir);
        }

        Ok((high, medium, low))
    }

    pub fn generate_detailed_report(
        &self,
        scan_dir: &Path,
        paranoid: bool,
    ) -> Result<serde_json::Value> {
        use serde_json::json;
        let mut report = serde_json::Map::new();

        let wf = self.check_workflow_files(scan_dir);
        report.insert(
            "workflow_files".to_string(),
            json!(wf.iter().map(|p| p.to_string_lossy()).collect::<Vec<_>>()),
        );

        let hashes = self.check_file_hashes(scan_dir)?;
        report.insert(
            "malicious_hashes".to_string(),
            json!(hashes
                .iter()
                .map(|(p, h)| json!({"path": p.to_string_lossy().to_string(), "hash": h}))
                .collect::<Vec<_>>()),
        );

        let (compromised, suspicious, namespaces) = self.check_packages(scan_dir)?;

        // Combine all package findings for detailed report
        let mut all_packages = Vec::new();
        for (p, i) in compromised.iter() {
            all_packages
                .push(json!({"path": p.to_string_lossy().to_string(), "info": i, "risk": "HIGH"}));
        }
        for (p, i) in suspicious.iter() {
            all_packages.push(
                json!({"path": p.to_string_lossy().to_string(), "info": i, "risk": "MEDIUM"}),
            );
        }
        for (p, i) in namespaces.iter() {
            all_packages.push(
                json!({"path": p.to_string_lossy().to_string(), "info": i, "risk": "MEDIUM"}),
            );
        }

        report.insert("compromised_packages".to_string(), json!(all_packages));

        let posts = self.check_postinstall_hooks(scan_dir)?;
        report.insert(
            "postinstall_hooks".to_string(),
            json!(posts
                .iter()
                .map(|(p, i)| json!({"path": p.to_string_lossy().to_string(), "info": i}))
                .collect::<Vec<_>>()),
        );

        let content = self.check_content(scan_dir)?;
        report.insert(
            "suspicious_content".to_string(),
            json!(content
                .iter()
                .map(|(p, i)| json!({"path": p.to_string_lossy().to_string(), "info": i}))
                .collect::<Vec<_>>()),
        );

        let cryptos = self.check_crypto_theft_patterns(scan_dir)?;
        report.insert(
            "crypto_patterns".to_string(),
            json!(cryptos
                .iter()
                .map(|(p, i)| json!({"path": p.to_string_lossy().to_string(), "info": i}))
                .collect::<Vec<_>>()),
        );

        let truffs = self.check_trufflehog_activity(scan_dir)?;
        report.insert("trufflehog_activity".to_string(), json!(truffs.iter().map(|(p,r,i)| json!({"path": p.to_string_lossy().to_string(), "risk": r, "info": i})).collect::<Vec<_>>()));

        let branches = self.check_git_branches(scan_dir)?;
        report.insert(
            "git_branches".to_string(),
            json!(branches
                .iter()
                .map(|(p, i)| json!({"path": p.to_string_lossy().to_string(), "info": i}))
                .collect::<Vec<_>>()),
        );

        let repos = self.check_shai_hulud_repos(scan_dir)?;
        report.insert(
            "shai_hulud_repos".to_string(),
            json!(repos
                .iter()
                .map(|(p, i)| json!({"path": p.to_string_lossy().to_string(), "info": i}))
                .collect::<Vec<_>>()),
        );

        let integ = self.check_package_integrity(scan_dir)?;
        report.insert(
            "package_integrity".to_string(),
            json!(integ
                .iter()
                .map(|(p, i)| json!({"path": p.to_string_lossy().to_string(), "info": i}))
                .collect::<Vec<_>>()),
        );

        if paranoid {
            let typo = self.check_typosquatting(scan_dir)?;
            report.insert(
                "typosquatting".to_string(),
                json!(typo
                    .iter()
                    .map(|(p, i)| json!({"path": p.to_string_lossy().to_string(), "info": i}))
                    .collect::<Vec<_>>()),
            );
            let net = self.check_network_exfiltration(scan_dir)?;
            report.insert(
                "network_exfiltration".to_string(),
                json!(net
                    .iter()
                    .map(|(p, i)| json!({"path": p.to_string_lossy().to_string(), "info": i}))
                    .collect::<Vec<_>>()),
            );
        }

        Ok(serde_json::Value::Object(report))
    }

    // Helper functions
    pub fn get_file_context(path: &Path) -> String {
        let s = path.to_string_lossy();
        if s.contains("/node_modules/") {
            return "node_modules".to_string();
        }
        if s.ends_with(".md") || s.ends_with(".txt") || s.ends_with(".rst") {
            return "documentation".to_string();
        }
        if s.ends_with(".d.ts") {
            return "type_definitions".to_string();
        }
        if s.contains("/dist/") || s.contains("/build/") || s.contains("/public/") {
            return "build_output".to_string();
        }
        if path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|n| n.contains("config") || n.contains(".config."))
            .unwrap_or(false)
        {
            return "configuration".to_string();
        }
        "source_code".to_string()
    }

    pub fn is_legitimate_pattern(_path: &Path, content_sample: &str) -> bool {
        if content_sample.contains("process.env.NODE_ENV") && content_sample.contains("production")
        {
            return true;
        }
        if content_sample.contains("createApp") || content_sample.contains("Vue") {
            return true;
        }
        if content_sample.contains("webpack")
            || content_sample.contains("vite")
            || content_sample.contains("rollup")
        {
            return true;
        }
        false
    }

    pub fn check_git_branches(&self, scan_dir: &Path) -> Result<Vec<(PathBuf, String)>> {
        let mut findings = Vec::new();
        for entry in WalkDir::new(scan_dir).into_iter().filter_map(Result::ok) {
            if entry.file_type().is_dir() && entry.file_name() == ".git" {
                let repo_dir = entry.path().parent().unwrap().to_path_buf();
                if let Ok(cfg) = std::fs::read_to_string(entry.path().join("config")) {
                    if cfg.contains("shai-hulud") || cfg.contains("Shai-Hulud") {
                        findings.push((
                            repo_dir.clone(),
                            "Git remote contains 'Shai-Hulud'".to_string(),
                        ));
                    }
                }
                // search refs/heads for '*shai-hulud*' files
                let heads = entry.path().join("refs").join("heads");
                if heads.exists() {
                    for bf in WalkDir::new(&heads)
                        .into_iter()
                        .filter_map(Result::ok)
                        .filter(|e| e.file_type().is_file())
                    {
                        if bf.file_name().to_string_lossy().contains("shai-hulud") {
                            if let Ok(commit_hash) = std::fs::read_to_string(bf.path()) {
                                findings.push((
                                    repo_dir.clone(),
                                    format!(
                                        "Branch '{}' (commit: {}...)",
                                        bf.file_name().to_string_lossy(),
                                        commit_hash.chars().take(8).collect::<String>()
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
        }
        Ok(findings)
    }
}
