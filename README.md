# 🛡️ SentinelAV v3.5 — EDR & MITRE ATT&CK Threat Engine

**SentinelAV v3.5** is an enterprise-grade open-source inspired Cyber Security & EDR (Endpoint Detection and Response) suite written in Java (JDK 21) with a pluggable detection engine architecture, MITRE ATT&CK technique mapping, ransomware canary honeypots, safe archive inspection, AES-256-GCM encrypted quarantine vault, and STIX 2.1 report generation.

---

## ✨ Enterprise & EDR Architectural Upgrades (v3.5)

### 🔌 1. Pluggable `DetectionEngine` Architecture & Trust Tiers
- **Modular Plugin System** ([DetectionEngine.java](src/com/sentinel/av/core/engine/DetectionEngine.java)): Modular interface supporting pluggable detection plugins (`HashEngine`, `MagicByteEngine`, `YaraEngine`, `BlockEntropyEngine`, `BehaviorDetectionEngine`, `ArchiveDetectionEngine`).
- **Trust Tiers**:
  - `TRUSTED_AUTO_QUARANTINE`: High-confidence hash DB matches automatically isolate threats.
  - `SUSPICION_USER_PROMPT`: Single heuristic/entropy hits prompt the user with transparent explanations.

### 📦 2. Safe Archive Inspection Engine (`ArchiveDetectionEngine.java`)
- **Safe ZIP / JAR / DOCX Extraction**: Unpacks and inspects nested archive contents.
- **Zip-Bomb & Resource Guards**: Enforces limits (max 100 extracted files, max 100MB uncompressed size, max depth 3) to prevent denial-of-service (ATT&CK `T1499.001`).

### 🎯 3. MITRE ATT&CK® Mapping & Coverage Matrix (`AttackCoveragePanel.java`)
- **Technique Tagging**: Every detection is tagged with official MITRE ATT&CK technique IDs:
  - `T1055`: Process Memory Injection
  - `T1059.001`: Encoded PowerShell Script Execution
  - `T1486`: Data Encrypted for Impact (Ransomware)
  - `T1036.005`: Masquerading (Disguised PE Header)
  - `T1547.001`: Boot or Logon Autostart Persistence
  - `T1204.002`: Archive Executable Payload
- **STIX 2.1 Exporter**: One-click export of threat indicators to standardized STIX 2.1 JSON bundles.

### 🦆 4. Ransomware Canary Honeypot Guard (`RansomwareCanaryGuard.java`)
- **Decoy File Deployment**: Deploys hidden decoy files (`.docx`, `.xlsx`, `.pdf`) in Desktop, Downloads, and Documents.
- **Real-Time Encryption Alert**: Monitors canary files using `WatchService`. If a suspect process modifies or encrypts a canary file, SentinelAV flags `T1486`, triggers a critical alert, and isolates the threat.

---

## 🚀 Quick Launch & Testing Guide

### 0. Requirements
- **JDK 21** (`javac`, `jar` and `java` on `PATH`)
- **PowerShell** (Windows 10/11) — the app targets Windows endpoint APIs
- `lib/flatlaf-3.4.1.jar` is bundled in this repository, no download step needed

### 1. Build Standalone Runnable Fat JAR
```powershell
.\build_jar.ps1
```

### 2. Launch SentinelAV Application
```powershell
.\run.ps1
```

### 3. Run Automated EDR Test Suite
```powershell
java -cp SentinelAV.jar com.sentinel.av.TestRunner
```

---

## 🧪 Test Suite Results
```
=== SentinelAV v3.5 Pluggable EDR & MITRE ATT&CK Test Suite ===
[TEST 1] Pluggable Behavior Engine & MITRE ATT&CK T1059.001 Mapping (PASSED)
[TEST 2] Archive Inspection Engine Unpacked & Flagged ZIP Payload (PASSED)
[TEST 3] Decoy Canary Files Deployed & Ransomware Watcher Active (PASSED)

✅ ALL SENTINEL AV V3.5 EDR & ATT&CK TESTS PASSED!
```
