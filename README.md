# SentinelAV v3.7 — EDR & MITRE ATT&CK Threat Engine

[![Build and Test](https://github.com/jaspalthakur/SentinelAV/actions/workflows/build.yml/badge.svg)](https://github.com/jaspalthakur/SentinelAV/actions/workflows/build.yml)

**SentinelAV** is an open-source inspired Cyber Security / EDR (Endpoint Detection and Response) suite written in Java 21. It combines a pluggable detection-engine architecture, MITRE ATT&CK technique mapping, ransomware canary honeypots, safe archive inspection, an AES-256-GCM encrypted quarantine vault, and STIX 2.1 report generation behind a dark FlatLaf desktop UI and a scriptable headless CLI.

---

## What's new in v3.7 (UI & UX polish)

- **Unified dark theme** — every screen now draws from the single `CyberPalette` (navy surfaces, consistent borders and text tones) instead of mixing two card styles.
- **Real scan progress** — the progress bar now shows the true `N / M files (P%)` based on the planned scan size instead of a fake modulo percentage.
- **Threat drill-down** — double-click any detection in the scanner to open the threat analysis dialog with its explainable risk signals, MITRE ATT&CK techniques, and matched SHA-256.
- **Sortable tables** — detections, quarantine vault, processes, and signature tables are sortable; bulk actions honor the current sort order.
- **Live status bar** — a footer shows shield state, tripwire state, vault item count, and JVM memory, refreshed continuously.
- **Keyboard navigation** — `Ctrl+1`…`Ctrl+8` jump directly to each section.
- **App icon** — a rendered shield icon on the window and taskbar.
- **Safer destructive actions** — permanent delete and terminate confirmations now default to *Cancel*, so Enter can never destroy data.
- **Clean exit** — closing the window (with a confirmation when the shield is active) stops monitoring, disarms the canary tripwire, flushes the activity log, and removes deployed decoys.

### What's new in v3.6

- **Headless CLI** ([CliRunner.java](src/com/sentinel/av/cli/CliRunner.java)) — scan files or folders from scripts and CI, with text or JSON output, optional quarantine, and stable exit codes.
- **Parallel scanning** ([ScannerEngine.java](src/com/sentinel/av/core/ScannerEngine.java)) — a bounded worker pool scans large trees concurrently while preserving discovery order.
- **Single-read hashing** ([FileContext.java](src/com/sentinel/av/core/engine/FileContext.java)) — MD5 + SHA-256 come from one pass and are computed lazily, so clean files no longer pay for unnecessary hashes.
- **Streaming, crash-safe quarantine** ([QuarantineManager.java](src/com/sentinel/av/core/QuarantineManager.java)) — files are encrypted and promoted atomically; restores are authenticated by GCM before touching the destination.
- **Shared content probe** ([TextProbe.java](src/com/sentinel/av/core/TextProbe.java)) — bounded 1 MiB read reused by YARA, pattern signatures, and behavior rules.
- **Portable data directory** ([AppPaths.java](src/com/sentinel/av/core/AppPaths.java)) — relocate all state with `-Dsentinelav.data.dir=<path>`.
- **Real self-test suite** ([TestRunner.java](src/com/sentinel/av/TestRunner.java)) — 14 test groups / 48 assertions covering hashing, magic bytes, engines, archives, quarantine, scanning, and the canary tripwire.
- **GitHub Actions CI** — every push builds the sources, runs the self-test, packages the fat JAR, and verifies the packaged artifact.

---

## Detection & EDR architecture

| Layer | Implementation |
| --- | --- |
| Hash signatures | MD5 / SHA-256 exact-match lookup against the local signature database |
| Magic bytes | Real file-type detection, including 2-byte `MZ` executables and masquerading documents (`T1036.005`) |
| YARA-style rules | Content rules with MITRE technique tags |
| Pattern signatures | EICAR-style and ransomware header patterns (`T1486`) |
| Block entropy | Packed / encrypted executable detection (`T1027.002`) |
| Behavior engine | Encoded PowerShell and script execution (`T1059.001`) |
| Archive engine | Safe ZIP/JAR/DOCX inspection with zip-bomb (`T1499.001`), zip-slip, depth, and size guards |
| Ransomware canary | Hidden decoy files plus a `WatchService` tripwire (`T1486`) |
| Risk scoring | Weighted, explainable 0–100 score with per-file reasons and ATT&CK tags |

### Trust tiers

- `TRUSTED_AUTO_QUARANTINE` — high-confidence signature matches can be isolated automatically.
- `SUSPICION_USER_PROMPT` — single heuristic hits surface transparent explanations before action.

---

## Requirements

- **JDK 21** (`javac`, `jar`, and `java` on `PATH`)
- **PowerShell** on Windows 10/11 (the app targets Windows endpoint APIs)
- `lib/flatlaf-3.4.1.jar` is committed, so no download step is needed

---

## Quick start

### 1. Build the sources

```powershell
.\build.ps1
```

### 2. Launch the desktop GUI

```powershell
.\run.ps1
```

`run.ps1` builds the fat JAR if it is missing and launches the UI with `javaw`.

### 3. Build a standalone runnable JAR

```powershell
.\build_jar.ps1
java -jar SentinelAV.jar
```

### 4. Run the automated self-test

```powershell
.\run.ps1 --selftest
# or, without the wrapper:
java -cp "bin;lib/flatlaf-3.4.1.jar" com.sentinel.av.TestRunner
```

---

## Headless CLI

Any argument switches `java -jar SentinelAV.jar` into CLI mode; no arguments launches the GUI.

```text
java -jar SentinelAV.jar --scan <path>            Scan a file or directory
java -jar SentinelAV.jar --scan <path> --json     Machine-readable JSON output
java -jar SentinelAV.jar --scan <path> --quarantine   Encrypt detections into the vault
java -jar SentinelAV.jar --selftest               Run the built-in test suite
java -jar SentinelAV.jar --version                Print the version
java -jar SentinelAV.jar --help                   Show usage
```

Exit codes: `0` clean, `1` threats found or self-test failed, `2` usage error.

Example CI-friendly scan:

```powershell
.\run.ps1 --scan .\Downloads --json
if ($LASTEXITCODE -eq 1) { Write-Host "Threats detected" }
```

---

## Desktop features

- **Dashboard** — protection status, security gauge, scan statistics, and activity timeline.
- **Scanner** — quick, full-system, and custom-path modes with live progress, threat details, and one-click quarantine.
- **Real-time monitor** — watches Downloads, Desktop, and Documents, including subdirectories created after startup.
- **Quarantine vault** — AES-256-GCM encrypted storage with restore and permanent-delete actions.
- **Signatures** — built-in signatures plus custom hash/pattern import and export.
- **Processes** — running-process inspection and persistence/autostart review.
- **ATT&CK coverage** — technique matrix and STIX 2.1 export.
- **Activity logs** — structured, bounded security event log with a background writer.

---

## Test suite results

```text
=== SentinelAV 3.6.0 - EDR & MITRE ATT&CK Threat Engine - Headless Test Suite ===
[PASS] Hash utilities (MD5 + SHA-256, single pass)
[PASS] Magic-byte detection (including 2-byte MZ)
[PASS] FileContext lazy hashing
[PASS] Behavior engine maps T1059.001
[PASS] Disguised executable scores T1036.005
[PASS] Pattern signature database detection
[PASS] Archive engine flags executable payload
[PASS] Archive zip-bomb guard (entry count)
[PASS] Archive zip-slip guard
[PASS] Archive nested-archive inspection
[PASS] Quarantine encrypt / restore round-trip
[PASS] Parallel scanner detects exactly one threat
[PASS] Ransomware canary tripwire fires
[PASS] Signature database stays duplicate-free
----------------------------------------------
RESULT: 48 passed, 0 failed
ALL SENTINELAV TESTS PASSED
```

---

## Runtime data

All state lives under `%USERPROFILE%\.sentinel_av` by default:

| Path | Purpose |
| --- | --- |
| `quarantine/` | AES-256-GCM vault files and metadata |
| `signatures.db` | Local signature database |
| `sentinel_activity.log` | Activity log |

Relocate everything for portable or isolated runs:

```powershell
java -Dsentinelav.data.dir=D:\SentinelData -jar SentinelAV.jar
```

The real-time monitor and scanner automatically exclude their own data directory and vault files.

---

## Project layout

```text
src/com/sentinel/av/
├── Main.java                 GUI / CLI entry point
├── Version.java              Single source of version truth
├── TestRunner.java           Headless self-test suite
├── cli/CliRunner.java        Scriptable command line interface
├── core/                     Scanner, hashing, entropy, signatures, quarantine
│   ├── canary/               Ransomware decoy tripwire
│   └── engine/               Pluggable detection engines + FileContext
├── model/                    ScanResult, VirusSignature, QuarantineItem
└── ui/                       FlatLaf desktop panels and components
```

---

## Safety notes

- Heuristic engines can produce false positives; review detections before permanent deletion.
- Quarantine encrypts files in place and removes the original. Use `--quarantine` only on data you can restore.
- The archive engine inspects metadata and bounded entry streams; it never extracts to disk.
- This project is educational and not a replacement for a commercial endpoint security product.

---

## License

No license file is included in this repository. Add one before redistributing.
