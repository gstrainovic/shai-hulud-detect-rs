# Bash vs Rust Function Comparison

## Overview
This document compares each function in the bash script with its Rust counterpart to ensure 1:1 functionality.

## Function Comparison Table

### 1. check_workflow_files
**Bash Function:**
- Input: `scan_dir` (directory path)
- Output: Populates `WORKFLOW_FILES` array with paths to `shai-hulud-workflow.yml` files
- Implementation: Uses `find` to search for files named "shai-hulud-workflow.yml"
```bash
find "$scan_dir" -name "shai-hulud-workflow.yml" 2>/dev/null
```

**Rust Function:**
- Input: `&Path` (scan_dir)
- Output: `Vec<PathBuf>` with matching files
- Implementation: Uses `WalkDir` to search recursively
```rust
pub fn check_workflow_files(&self, scan_dir: &Path) -> Vec<PathBuf>
```

**Status:** ✅ IDENTICAL - Both find files named "shai-hulud-workflow.yml"

---

### 2. check_file_hashes
**Bash Function:**
- Input: `scan_dir`
- Output: Populates `MALICIOUS_HASHES` array with "file:hash" entries
- Implementation: 
  - Finds `*.js`, `*.ts`, `*.json` files
  - Computes SHA-256 hash using `shasum -a 256`
  - Parallelizes with `xargs -P ${PARALLELISM}`
  - Shows progress indicator
  - Matches against `MALICIOUS_HASHLIST` array (9 hashes)

**Rust Function:**
- Input: `&Path` (scan_dir)
- Output: `Result<Vec<(PathBuf, String)>>` with matching files and hashes
- Implementation:
  - Finds files with extensions: js, ts, json
  - Computes SHA-256 with `sha2` crate
  - Parallelizes with rayon
  - No progress indicator

**Status:** ⚠️ PARTIAL MATCH
- **Missing:** Progress indicator
- **Missing:** Same hash list (needs verification)

---

### 3. check_packages
**Bash Function:**
- Input: `scan_dir`
- Output: Populates `COMPROMISED_FOUND`, `SUSPICIOUS_FOUND`, `NAMESPACE_WARNINGS` arrays
- Implementation:
  - Finds all `package.json` files
  - Parses dependencies using `awk`
  - Exact match → `COMPROMISED_FOUND`
  - Semver pattern match → `SUSPICIOUS_FOUND`
  - Uses `semver_match` function for version comparison
  - Checks compromised namespaces
  - Shows progress indicator

**Rust Function:**
- Input: `&Path`
- Output: `Result<Vec<(PathBuf, String)>>` - single array for all findings
- Implementation:
  - Finds `package.json` files
  - Parses JSON with `serde_json`
  - Simple version matching (strips `^`, `~`, `>`)
  - Checks namespaces

**Status:** ❌ MAJOR DIFFERENCES
- **Missing:** Separate arrays for COMPROMISED vs SUSPICIOUS vs NAMESPACE warnings
- **Missing:** Full semver matching with `^`, `~` operators
- **Missing:** Progress indicator
- **Issue:** All findings go into one array instead of three

---

### 4. check_postinstall_hooks
**Bash Function:**
- Input: `scan_dir`
- Output: Populates `POSTINSTALL_HOOKS` array
- Implementation:
  - Finds all `package.json` files
  - Searches for `"postinstall"` key
  - Extracts command using `grep -A1`
  - Flags suspicious patterns: `curl`, `wget`, `node -e`, `eval`

**Rust Function:**
- Input: `&Path`
- Output: `Result<Vec<(PathBuf, String)>>`
- Implementation:
  - Finds files starting with "package" and ending in ".json"
  - Uses regex to extract postinstall command
  - Checks same patterns

**Status:** ⚠️ MINOR DIFFERENCES
- **Issue:** Rust accepts `package*.json`, bash only `package.json`
- Both check same suspicious patterns

---

### 5. check_content
**Bash Function:**
- Input: `scan_dir`
- Output: Populates `SUSPICIOUS_CONTENT` array
- Implementation:
  - Searches `*.js`, `*.ts`, `*.json`, `*.yml`, `*.yaml` files
  - Looks for:
    - `webhook\.site` pattern
    - UUID `bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`

**Rust Function:**
- Input: `&Path`
- Output: `Result<Vec<(PathBuf, String)>>`
- Implementation: Same patterns and file types

**Status:** ✅ IDENTICAL

---

### 6. check_crypto_theft_patterns
**Bash Function:**
- Input: `scan_dir`
- Output: Populates `CRYPTO_PATTERNS` array with risk levels
- Implementation:
  - Searches `*.js`, `*.ts`, `*.json`
  - Multiple patterns:
    - Ethereum addresses with context keywords
    - XMLHttpRequest.prototype.send
    - Known function names: checkethereumw, runmask, etc.
    - Attacker wallets
    - npmjs.help domain
    - javascript-obfuscator
    - Crypto regex patterns
  - Context-aware risk assessment (framework paths = LOW RISK)
  - Separates findings into HIGH/MEDIUM/LOW based on file location

**Rust Function:**
- Input: `&Path`
- Output: `Result<Vec<(PathBuf, String)>>`
- Implementation: 
  - Checks same patterns
  - No context-aware risk assessment
  - No separation by risk level

**Status:** ❌ MAJOR DIFFERENCES
- **Missing:** Context-aware detection (framework vs application code)
- **Missing:** Risk level separation
- **Missing:** XMLHttpRequest + crypto pattern combination logic

---

### 7. check_trufflehog_activity
**Bash Function:**
- Input: `scan_dir`
- Output: Populates `TRUFFLEHOG_ACTIVITY` array with format "file:RISK:info"
- Implementation:
  - Searches for trufflehog binaries
  - Context-aware analysis using `get_file_context()`:
    - documentation → skip
    - node_modules → MEDIUM risk
    - source + subprocess + curl → HIGH risk
  - Credential patterns (AWS_ACCESS_KEY, etc.) with context
  - Environment variable scanning with legitimacy checks
  - Uses `is_legitimate_pattern()` helper

**Rust Function:**
- Input: `&Path`
- Output: `Result<Vec<(PathBuf, String, String)>>` - (path, risk, info)
- Implementation:
  - Similar structure but simplified logic
  - Has context detection
  - Has legitimacy pattern checking

**Status:** ⚠️ PARTIAL MATCH
- Similar structure but needs verification of all edge cases

---

### 8. check_git_branches
**Bash Function:**
- Input: `scan_dir`
- Output: Populates `GIT_BRANCHES` array
- Implementation:
  - Finds `.git` directories
  - Searches `refs/heads` for files containing "shai-hulud"
  - Reads commit hash from branch files
  - Format: "repo:Branch 'name' (commit: hash...)"

**Rust Function:**
- Input: `&Path`
- Output: `Result<Vec<(PathBuf, String)>>`
- Implementation:
  - Finds `.git` directories
  - Searches config for "shai-hulud"
  - Searches refs/heads for branch files with "shai-hulud"
  - Reads commit hash

**Status:** ✅ IDENTICAL

---

### 9. check_shai_hulud_repos
**Bash Function:**
- Input: `scan_dir`
- Output: Populates `SHAI_HULUD_REPOS` array
- Implementation:
  - Checks repo name for "shai-hulud" or "Shai-Hulud"
  - Checks for "-migration" pattern
  - Checks git config for "shai-hulud"
  - Checks data.json for base64 patterns (eyJ...==)

**Rust Function:**
- Input: `&Path`
- Output: `Result<Vec<(PathBuf, String)>>`
- Implementation: Same checks

**Status:** ✅ IDENTICAL

---

### 10. check_package_integrity
**Bash Function:**
- Input: `scan_dir`
- Output: Populates `INTEGRITY_ISSUES` array
- Implementation:
  - Finds package-lock.json, yarn.lock, pnpm-lock.yaml
  - For pnpm: transforms to pseudo-package-lock using `transform_pnpm_yaml`
  - Searches for compromised packages in lockfiles
  - Uses complex awk script to extract versions from node_modules structure
  - Checks integrity hash patterns
  - Checks @ctrl packages in recently modified lockfiles (< 30 days)
  - Cleans up temp files

**Rust Function:**
- Input: `&Path`
- Output: `Result<Vec<(PathBuf, String)>>`
- Implementation:
  - Finds same lockfile types
  - For pnpm: uses serde_yaml to parse
  - Uses regex to find packages
  - Checks integrity patterns
  - Checks recent modifications with @ctrl

**Status:** ⚠️ PARTIAL MATCH
- Different pnpm transformation approach
- Different package extraction logic (regex vs awk)

---

### 11. check_typosquatting (Paranoid mode only)
**Bash Function:**
- Input: `scan_dir`
- Output: Populates `TYPOSQUATTING_WARNINGS` array
- Implementation:
  - List of 26 popular packages
  - Unicode character detection using `LC_ALL=C`
  - Confusable character patterns (rn:m, vv:w, etc.)
  - Single character difference detection
  - Missing/extra character detection
  - Namespace confusion detection

**Rust Function:**
- Input: `&Path`
- Output: `Result<Vec<(PathBuf, String)>>`
- Implementation: Same logic with Rust string handling

**Status:** ✅ IDENTICAL

---

### 12. check_network_exfiltration (Paranoid mode only)
**Bash Function:**
- Input: `scan_dir`
- Output: Populates `NETWORK_EXFILTRATION_WARNINGS` array
- Implementation:
  - List of 19 suspicious domains
  - IP address detection (excluding 127.0.0.1, 0.0.0.0)
  - Base64 encoding detection (atob, base64)
  - DNS-over-HTTPS patterns
  - WebSocket connections
  - Suspicious HTTP headers
  - btoa() + network call combinations
  - Extensive filtering to avoid false positives

**Rust Function:**
- Input: `&Path`
- Output: `Result<Vec<(PathBuf, String)>>`
- Implementation: Similar logic, simplified in some areas

**Status:** ⚠️ PARTIAL MATCH
- Needs verification of all filtering logic

---

## Helper Functions

### get_file_context
**Bash:**
```bash
# Returns: node_modules, documentation, type_definitions, 
#          build_output, configuration, source_code
```
**Rust:**
```rust
pub fn get_file_context(path: &Path) -> String
```
**Status:** ✅ IDENTICAL

---

### is_legitimate_pattern
**Bash:**
```bash
# Checks for Vue.js, webpack, vite, rollup patterns
# Returns 0 (legitimate) or 1 (suspicious)
```
**Rust:**
```rust
pub fn is_legitimate_pattern(_path: &Path, content_sample: &str) -> bool
```
**Status:** ✅ IDENTICAL

---

### semverParseInto & semver_match
**Bash:**
```bash
# Full semver support: ^, ~, ||, exact match
# semverParseInto: parses version into major.minor.patch.special
# semver_match: matches test_subject against test_pattern
```
**Rust:**
```rust
# ❌ MISSING - No semver matching implementation
# Current: Only strips ^~> and does string comparison
```
**Status:** ❌ MISSING CRITICAL FUNCTIONALITY

---

### transform_pnpm_yaml
**Bash:**
```bash
# Converts pnpm-lock.yaml to pseudo JSON format
# Complex bash parsing with depth tracking
```
**Rust:**
```rust
# Uses serde_yaml to parse, then converts to JSON-like structure
```
**Status:** ⚠️ DIFFERENT APPROACH - Needs verification

---

## Output Formatting

### Bash Report Generation
**generate_report function:**
- Color codes (RED, YELLOW, GREEN, BLUE)
- File preview boxes for HIGH RISK items
- Risk stratification (HIGH/MEDIUM/LOW)
- Progress indicators during scans
- Detailed summary with issue counts
- Recommendations and notes
- Investigation commands for git branches

### Rust Output
**Current Implementation:**
- Simple list output in main.rs
- No colors
- No risk stratification in output
- No file preview boxes
- No progress indicators
- Minimal formatting

**Status:** ❌ COMPLETELY DIFFERENT
- Rust was designed as a library, bash as end-user tool
- Missing all visual formatting

---

## Critical Issues to Fix

### Priority 1: Core Detection Logic
1. ❌ **Semver matching** - Missing complete implementation
2. ❌ **Package check separation** - Need 3 separate result types (compromised/suspicious/namespace)
3. ❌ **Crypto pattern context-awareness** - Risk levels based on file location
4. ❌ **XMLHttpRequest detection** - Should be separate from other crypto patterns

### Priority 2: Data Structures
5. ❌ **Return types** - Should match bash array structure (separate findings by type)
6. ❌ **Risk levels** - Need consistent HIGH/MEDIUM/LOW tagging across all functions

### Priority 3: Output & UX
7. ❌ **Progress indicators** - Missing from all long-running operations
8. ❌ **Report formatting** - Need colored, formatted report output
9. ❌ **File preview boxes** - Missing for HIGH RISK items
10. ❌ **Summary generation** - Need detailed report like bash

---

## Test Coverage Needed

### Unit Tests (per function)
Each function should have tests for:
1. Empty directory
2. Single match
3. Multiple matches
4. False positives
5. Edge cases (unicode, special characters, etc.)

### Integration Tests
1. Test each test-case directory individually
2. Compare counts: HIGH/MEDIUM/LOW
3. Verify specific findings match bash output
4. Test paranoid vs normal mode differences

### Test Cases from Bash
All directories in `test-cases/`:
- chalk-debug-attack/
- clean-project/
- common-crypto-libs/
- comprehensive-test/
- debug-js/
- edge-case-project/
- false-positive-project/
- git-branch-test/
- infected-lockfile/
- infected-lockfile-pnpm/
- infected-project/
- legitimate-crypto/
- legitimate-security-project/
- lockfile-compromised/
- lockfile-false-positive/
- mixed-project/
- multi-hash-detection/
- namespace-warning/
- network-exfiltration-project/
- semver-matching/
- typosquatting-project/
- xmlhttp-legitimate/
- xmlhttp-malicious/

---

## Action Plan

### Phase 1: Fix Core Detection (Priority 1)
1. Implement full semver matching
2. Refactor check_packages to return 3 separate result types
3. Add context-aware risk assessment to crypto patterns
4. Fix XMLHttpRequest detection logic

### Phase 2: Add Test Coverage
1. Write unit tests for each detection function
2. Create integration test for each test-case directory
3. Add test helper to compare with bash output

### Phase 3: Output Formatting
1. Add progress indicators
2. Implement colored report generation
3. Add file preview boxes
4. Create detailed summary

### Phase 4: Validation
1. Run all tests
2. Compare output with bash for each test-case
3. Fix any remaining discrepancies
