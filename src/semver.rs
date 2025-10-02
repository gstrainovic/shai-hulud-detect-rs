//! Semantic versioning support for package version matching
//! Port of semver_bash from the original shell script

use std::cmp::Ordering;

/// Parsed semantic version components
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemVer {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub special: String,
}

impl SemVer {
    /// Parse a version string into components
    /// Follows the bash semverParseInto logic
    pub fn parse(version: &str) -> Option<Self> {
        // Remove any leading non-numeric chars
        let version = version.trim();

        // Try to extract major.minor.patch with optional special
        let re = regex::Regex::new(r"[^0-9]*([0-9]+)\.([0-9]+)\.([0-9]+)([0-9A-Za-z\-]*)").ok()?;
        let caps = re.captures(version)?;

        let major = caps.get(1)?.as_str().parse().ok()?;
        let minor = caps.get(2)?.as_str().parse().ok()?;
        let patch = caps.get(3)?.as_str().parse().ok()?;
        let special = caps.get(4).map(|m| m.as_str()).unwrap_or("").to_string();

        Some(SemVer {
            major,
            minor,
            patch,
            special,
        })
    }
}

/// Check if a version matches a semver pattern
/// Supports: ^, ~, ||, *, and exact matches
/// Returns true if test_subject matches test_pattern
pub fn semver_match(test_subject: &str, test_pattern: &str) -> bool {
    // Always matches
    if test_pattern == "*" {
        return true;
    }

    let subject = match SemVer::parse(test_subject) {
        Some(v) => v,
        None => return false,
    };

    // Handle multi-variant patterns with ||
    for pattern in test_pattern.split("||") {
        let pattern = pattern.trim();

        // Always matches
        if pattern == "*" {
            return true;
        }

        if pattern.starts_with('^') {
            // Caret: Major must match, minor.patch >= pattern
            let pattern_ver = match SemVer::parse(&pattern[1..]) {
                Some(v) => v,
                None => continue,
            };

            if subject.major != pattern_ver.major {
                continue;
            }

            match subject.minor.cmp(&pattern_ver.minor) {
                Ordering::Greater => return true,
                Ordering::Less => continue,
                Ordering::Equal => {
                    if subject.patch >= pattern_ver.patch {
                        return true;
                    }
                }
            }
        } else if pattern.starts_with('~') {
            // Tilde: Major and minor must match, patch >= pattern
            let pattern_ver = match SemVer::parse(&pattern[1..]) {
                Some(v) => v,
                None => continue,
            };

            if subject.major == pattern_ver.major
                && subject.minor == pattern_ver.minor
                && subject.patch >= pattern_ver.patch
            {
                return true;
            }
        } else {
            // Exact match
            let pattern_ver = match SemVer::parse(pattern) {
                Some(v) => v,
                None => continue,
            };

            if subject.major == pattern_ver.major
                && subject.minor == pattern_ver.minor
                && subject.patch == pattern_ver.patch
                && subject.special == pattern_ver.special
            {
                return true;
            }
        }
    }

    // No match found
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semver_parse() {
        let v = SemVer::parse("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
        assert_eq!(v.special, "");

        let v = SemVer::parse("1.2.3-beta").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
        assert_eq!(v.special, "-beta");

        let v = SemVer::parse("v2.0.0").unwrap();
        assert_eq!(v.major, 2);
        assert_eq!(v.minor, 0);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn test_caret_matching() {
        // ^1.0.0 should match 1.0.0, 1.0.1, 1.1.0, 1.9.9 but not 2.0.0
        assert!(semver_match("1.0.0", "^1.0.0"));
        assert!(semver_match("1.0.1", "^1.0.0"));
        assert!(semver_match("1.1.0", "^1.0.0"));
        assert!(semver_match("1.9.9", "^1.0.0"));
        assert!(!semver_match("2.0.0", "^1.0.0"));
        assert!(!semver_match("0.9.9", "^1.0.0"));
    }

    #[test]
    fn test_tilde_matching() {
        // ~1.2.0 should match 1.2.0, 1.2.1, 1.2.9 but not 1.3.0
        assert!(semver_match("1.2.0", "~1.2.0"));
        assert!(semver_match("1.2.1", "~1.2.0"));
        assert!(semver_match("1.2.9", "~1.2.0"));
        assert!(!semver_match("1.3.0", "~1.2.0"));
        assert!(!semver_match("1.1.9", "~1.2.0"));
    }

    #[test]
    fn test_exact_matching() {
        assert!(semver_match("1.2.3", "1.2.3"));
        assert!(!semver_match("1.2.4", "1.2.3"));
        assert!(!semver_match("1.3.3", "1.2.3"));
    }

    #[test]
    fn test_wildcard() {
        assert!(semver_match("1.2.3", "*"));
        assert!(semver_match("99.99.99", "*"));
    }

    #[test]
    fn test_or_operator() {
        assert!(semver_match("1.0.0", "^1.0.0 || ^2.0.0"));
        assert!(semver_match("2.0.0", "^1.0.0 || ^2.0.0"));
        assert!(!semver_match("3.0.0", "^1.0.0 || ^2.0.0"));
    }
}
