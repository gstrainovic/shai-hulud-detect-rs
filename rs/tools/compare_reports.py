#!/usr/bin/env python3
import json
import re
from pathlib import Path

# Simple comparator: compares bash text outputs with rust detailed JSON per test-case and per-check

# Use the crate (rs/) tests/gold directory as canonical storage for gold files
CRATE_ROOT = Path(__file__).resolve().parent.parent
CRATE_GOLD_DIR = CRATE_ROOT / 'tests' / 'gold'

def resolve_candidate_path(filename: str) -> Path:
    """Resolve filename relative to the crate tests/gold, crate root, or cwd.
    This ensures the comparator always operates on rs/tests/gold when present.
    """
    candidates = [
        CRATE_GOLD_DIR / filename,
        CRATE_ROOT / filename,
        Path(filename),
    ]
    for c in candidates:
        if c.exists():
            return c
    # Default to crate gold dir (may not exist yet) so writes go there
    return CRATE_GOLD_DIR / filename

# Use resolved candidate paths for inputs (also allow tests/gold locations)
BASH_NORMAL = resolve_candidate_path('bash_scan_normal.txt')
BASH_PARANOID = resolve_candidate_path('bash_scan_paranoid.txt')
RUST_NORMAL = resolve_candidate_path('rust_detailed_normal.json')
RUST_PARANOID = resolve_candidate_path('rust_detailed_paranoid.json')

# Sections in rust JSON we will compare
CHECK_KEYS = [
    'workflow_files', 'malicious_hashes', 'compromised_packages', 'postinstall_hooks',
    'suspicious_content', 'crypto_patterns', 'trufflehog_activity', 'git_branches',
    'shai_hulud_repos', 'package_integrity', 'typosquatting', 'network_exfiltration'
]

POSIX_PATH_RE = re.compile(r'(test-cases[\\/.][^\\s]*?\.(?:js|json|sh|yml|yaml|py|lock|txt|md))')
ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')


def extract_bash_findings(bash_path: Path):
    # If bash output is missing, return empty findings and warn instead of crashing
    if not bash_path.exists():
        print(f"Warning: bash output {bash_path} not found — returning empty findings")
        return {k: {} for k in CHECK_KEYS}
    # Read and pre-clean the bash output: remove ANSI escapes so paths/messages are consistent
    raw_text = bash_path.read_text(encoding='utf-8', errors='ignore')
    text = ANSI_RE.sub('', raw_text)
    findings = {k: {} for k in CHECK_KEYS}

    # Map some bash headings to CHECK_KEYS
    section_map = {
        'Malicious workflow files detected': 'workflow_files',
        'Files with known malicious hashes': 'malicious_hashes',
        'Compromised package versions detected': 'compromised_packages',
        'Suspicious postinstall hooks detected': 'postinstall_hooks',
        'Suspicious content patterns': 'suspicious_content',
        'Cryptocurrency theft patterns detected': 'crypto_patterns',
        'Trufflehog/secret scanning activity detected': 'trufflehog_activity',
        "Suspicious git branches": 'git_branches',
        'Shai-Hulud repositories detected': 'shai_hulud_repos',
        'Package integrity issues detected': 'package_integrity',
        'Potential typosquatting/homoglyph attacks detected': 'typosquatting',
        'Network exfiltration patterns detected': 'network_exfiltration'
    }

    # Find all lines that contain a test-cases path and try to assign them to a section by proximity
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = POSIX_PATH_RE.search(line)
        if m:
            raw = m.group(1)
            # already cleaned globally; normalize windows backslashes
            norm = raw.replace('\\', '/').lstrip('./')
            # Find section by scanning previous 8 lines for a header
            sect = None
            for j in range(max(0, i-8), i+1):
                l = lines[j]
                for header, key in section_map.items():
                    if header in l:
                        sect = key
                        break
                if sect:
                    break
            if not sect:
                # fallback: try detect keyword in same line
                if 'postinstall' in line or 'postinstall' in ''.join(lines[max(0, i-2):i+3]).lower():
                    sect = 'postinstall_hooks'
            if not sect:
                sect = 'suspicious_content'
            # avoid duplicate identical messages for same path; strip ANSI from message
            findings.setdefault(sect, {}).setdefault(norm, [])
            msg = ANSI_RE.sub('', line).strip()
            if msg not in findings[sect][norm]:
                findings[sect][norm].append(msg)
    # Merge keys that normalize to the same path (strip ANSI/backslashes) to avoid duplicates
    merged = {}
    for sect, mapping in findings.items():
        merged[sect] = {}
        for raw_path, msgs in mapping.items():
            clean_path = ANSI_RE.sub('', raw_path).replace('\\', '/').lstrip('./')
            merged.setdefault(sect, {}).setdefault(clean_path, [])
            for m in msgs:
                msg_clean = ANSI_RE.sub('', m).strip()
                if msg_clean not in merged[sect][clean_path]:
                    merged[sect][clean_path].append(msg_clean)
    return merged


def load_rust_json(path: Path):
    if not path.exists():
        print(f"Warning: rust JSON {path} not found — returning empty normalized map")
        return {k: {} for k in CHECK_KEYS}
    data = json.loads(path.read_text(encoding='utf-8'))
    # Normalize paths in values
    normalized = {}
    for key in CHECK_KEYS:
        normalized[key] = {}
        val = data.get(key)
        if not val:
            continue
        for item in val:
            p = item.get('path') if isinstance(item, dict) else None
            info = item.get('info') if isinstance(item, dict) else None
            if not p:
                # for workflow_files array of strings
                if isinstance(item, str):
                    p = item
                else:
                    continue
            norm = p.replace('\\', '/').lstrip('./')
            normalized[key].setdefault(norm, []).append(info if info else '')
    return normalized


def compare(bash_findings, rust_findings):
    report = {}
    for key in CHECK_KEYS:
        bash_map = bash_findings.get(key, {})
        rust_map = rust_findings.get(key, {})
        all_paths = set(bash_map.keys()) | set(rust_map.keys())
        diffs = []
        for p in sorted(all_paths):
            b = bash_map.get(p, [])
            r = rust_map.get(p, [])
            if b != r:
                diffs.append({'path': p, 'bash': b, 'rust': r})
        report[key] = {'bash_count': sum(len(v) for v in bash_map.values()), 'rust_count': sum(len(v) for v in rust_map.values()), 'diffs': diffs}
    return report


def build_gold_from_bash(bash_path: Path):
    # If bash output missing, return an empty gold structure
    if not bash_path.exists():
        print(f"Warning: bash output {bash_path} not found — writing empty gold")
        return {'findings': [], 'summary': {'high': 0, 'medium': 0, 'low': 0}}
    raw_text = bash_path.read_text(encoding='utf-8', errors='ignore')
    text = ANSI_RE.sub('', raw_text)
    lines = text.splitlines()
    gold = {'findings': [], 'summary': {'high': 0, 'medium': 0, 'low': 0}}

    # Identify blocks by severity headers
    severity_headers = []
    for i,l in enumerate(lines):
        if 'HIGH RISK' in l or 'HIGH RISK:' in l:
            severity_headers.append((i, 'HIGH'))
        elif 'MEDIUM RISK' in l or 'MEDIUM RISK:' in l:
            severity_headers.append((i, 'MEDIUM'))
        elif 'LOW RISK' in l or 'LOW RISK:' in l:
            severity_headers.append((i, 'LOW'))

    # For each appearance of test-cases paths, find closest preceding severity header
    for i, line in enumerate(lines):
        for m in POSIX_PATH_RE.finditer(line):
            raw = m.group(1)
            p = raw.replace('\\', '/').lstrip('./')
             # find nearest header before i
            sev = 'MEDIUM'
            for idx, s in reversed(severity_headers):
                if idx <= i:
                    sev = s
                    break
            # capture the message context (rest of line)
            msg = line.strip()
            gold['findings'].append({'path': p, 'severity': sev, 'message': msg})
            gold['summary'][sev.lower()] += 1

    # Also parse summary numbers if present
    for l in lines:
        if 'High Risk Issues:' in l:
            try:
                gold['summary']['high'] = int(l.split(':')[-1].strip())
            except:
                pass
        if 'Medium Risk Issues:' in l:
            try:
                gold['summary']['medium'] = int(l.split(':')[-1].strip())
            except:
                pass
        if 'Low Risk (informational):' in l or 'Low Risk Issues:' in l:
            try:
                gold['summary']['low'] = int(l.split(':')[-1].strip())
            except:
                pass

    return gold


# write comparison JSONs as before

if __name__ == '__main__':
    bn = extract_bash_findings(BASH_NORMAL)
    rn = load_rust_json(RUST_NORMAL) if RUST_NORMAL.exists() else {}
    report_n = compare(bn, rn)
    print('=== NORMAL MODE COMPARISON ===')
    print(json.dumps(report_n, indent=2, ensure_ascii=False))

    # write gold JSON
    gold_n = build_gold_from_bash(BASH_NORMAL)
    # Ensure we always write gold outputs into the crate-local tests/gold folder (rs/tests/gold)
    gold_dir = CRATE_GOLD_DIR
    gold_dir.mkdir(parents=True, exist_ok=True)
    Path(gold_dir / 'bash_gold_normal.json').write_text(json.dumps(gold_n, indent=2, ensure_ascii=False), encoding='utf-8')

    # write parsed bash findings for adapter
    Path(gold_dir / 'bash_parsed_normal.json').write_text(json.dumps(bn, indent=2, ensure_ascii=False), encoding='utf-8')

    bp = extract_bash_findings(BASH_PARANOID)
    rp = load_rust_json(RUST_PARANOID) if RUST_PARANOID.exists() else {}
    report_p = compare(bp, rp)
    print('\n=== PARANOID MODE COMPARISON ===')
    print(json.dumps(report_p, indent=2, ensure_ascii=False))

    gold_p = build_gold_from_bash(BASH_PARANOID)
    Path(gold_dir / 'bash_gold_paranoid.json').write_text(json.dumps(gold_p, indent=2, ensure_ascii=False), encoding='utf-8')

    # write parsed bash findings for adapter
    Path(gold_dir / 'bash_parsed_paranoid.json').write_text(json.dumps(bp, indent=2, ensure_ascii=False), encoding='utf-8')

    # Also write the compare reports for programmatic consumption
    Path(gold_dir / 'compare_normal.json').write_text(json.dumps(report_n, indent=2, ensure_ascii=False), encoding='utf-8')
    Path(gold_dir / 'compare_paranoid.json').write_text(json.dumps(report_p, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f"\nWrote gold & compare outputs to {gold_dir}")
