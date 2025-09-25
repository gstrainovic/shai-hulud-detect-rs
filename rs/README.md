Kurzüberblick
=============

Dieses kleine Rust‑Projekt ist eine Portierung des ursprünglichen Bash‑Scan‑Tools „Shai‑Hulud“.
Es stellt Scannerfunktionen bereit, die die Testfälle unter `test-cases/` durchsuchen und Ergebnisse
als strukturierte JSON‑Reports erzeugen. Zusätzlich gibt es einen Comparator, der die Rust‑Ausgaben
gegen die originalen Bash‑Outputs abgleicht (Parity‑Tests).

Features
--------
- Rekursion durch Projekte (WalkDir) und Erkennung von verdächtigen Mustern
- Erkennung von kompromittierten Packages, postinstall‑Hooks, Crypto‑Diebstahlmustern
- Trufflehog‑/Secret‑Scan Indikatoren und Package‑Integritätsprüfungen
- Detaillierte JSON‑Reports für Normal- und Paranoid‑Modi
- Integrationstest, der Bash‑Output vs. Rust‑Output per Kategorie vergleicht

Schnelleinstieg — Voraussetzungen
---------------------------------
- Rust + Cargo (aktuelle Toolchain)
- Bash (für das original Bash‑Scanner‑Skript, falls Parity prüfungen benötigt werden)
- Python3 (für `tools/compare_reports.py` Comparator)

Wichtige Pfade
--------------
- Crate‑Root: `rs/`
- Scanner Binary: `cargo run --bin shai-hulud-detector -- <directory>`
- Gold/Comparator Dateien: `rs/tests/gold/`
- Test‑Cases: Top‑Level `test-cases/` (Repository‑Root)

Nützliche Befehle
-----------------
- Kompilieren & Tests ausführen (ganzer Crate):

  ```bash
  cd rs
  cargo test
  ```

- Nur der Parity‑Integrationstest (Bash vs Rust):

  ```bash
  cd rs
  cargo test --test integration_gold_parity -- --nocapture
  ```

- Nur die API‑Integrationstests:

  ```bash
  cd rs
  cargo test --test integration_test -- --nocapture
  ```

- Scanner lokal ausführen (scannt `test-cases`):

  ```bash
  cd rs
  cargo run -- test-cases
  ```

- Formatter & Linter:

  ```bash
  cd rs
  cargo fmt
  cargo clippy -- -D warnings
  ```

- Comparator (wenn Python3 installiert ist) — erzeugt/aktualisiert Gold‑Outputs unter `rs/tests/gold`:

  ```bash
  cd rs
  python3 tools/compare_reports.py
  ```

Anmerkungen zu Gold‑Files
------------------------
- Die vertrauenswürdigen Referenz‑Outputs (Gold) liegen unter `rs/tests/gold/`.
- Wenn du Gold‑Dateien regenerierst (z. B. nach Änderung der Erkennungslogik), überprüfe und committe
  nur die beabsichtigten Änderungen in `rs/tests/gold/`.

CI / Empfehlungen
-----------------
- Empfohlen: GitHub Actions Job, der bei PRs:
  - `cargo test` ausführt
  - optional: Bash‑Scanner + Comparator laufen lässt, um Parität sicherzustellen
- Sensible Testdaten (echte Webhooks / Keys) bitte niemals in Git einchecken — scrubbe oder anonymisiere sie.

Automatische Fixes
------------------
Während der Entwicklung wurden automatische Lint/Fix‑Werkzeuge eingesetzt, um Code‑Qualität und
Konsistenz zu verbessern. Falls du die gleichen Schritte lokal reproduzieren möchtest:

- `cargo fix` angewendet (lokal im `rs/` Crate).
- `cargo fmt` ausgeführt, um Codeformatierung zu vereinheitlichen.
- Nightly Clippy mit `--fix -Z unstable-options` verwendet, um einfache Änderungen automatisch zu übernehmen.

Wenn du möchtest
-----------------
- Ich kann eine GitHub Actions Datei anlegen, die die Parity‑Checks automatisch ausführt.
- Alternativ kann ich den Python‑Comparator nach Rust portieren, damit keine Python‑Runtime nötig ist.

