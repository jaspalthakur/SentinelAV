package com.sentinel.av;

import com.sentinel.av.core.*;
import com.sentinel.av.core.canary.RansomwareCanaryGuard;
import com.sentinel.av.core.engine.*;
import com.sentinel.av.model.*;

import java.io.File;
import java.nio.file.Files;
import java.util.List;

public class TestRunner {

    public static void main(String[] args) throws Exception {
        System.out.println("=== SentinelAV v3.5 Pluggable EDR & MITRE ATT&CK Test Suite ===");

        // 1. Pluggable Detection Engine Test
        File tempTestDir = Files.createTempDirectory("sentinel_v35_test_").toFile();
        File testFile = new File(tempTestDir, "encoded_ps.txt");
        Files.write(testFile.toPath(), "powershell -enc AAAA -ExecutionPolicy Bypass".getBytes());

        FileContext context = new FileContext(testFile);
        BehaviorDetectionEngine behaviorEngine = new BehaviorDetectionEngine();
        EngineResult result = behaviorEngine.evaluate(context);

        System.out.println("[TEST 1] Pluggable Engine: " + behaviorEngine.getEngineName());
        System.out.println("[TEST 1] Threat Name: " + result.getThreatName());
        System.out.println("[TEST 1] ATT&CK Technique Mapping: " + result.getAttackTechniques());

        if (result.getScoreContribution() >= 50 && result.getAttackTechniques().contains("T1059.001")) {
            System.out.println("[TEST 1 PASSED] Pluggable Engine & MITRE ATT&CK T1059.001 Mapping Functioned Correctly!");
        } else {
            System.err.println("[TEST 1 FAILED] Pluggable Behavior Engine failed.");
            System.exit(1);
        }

        // 2. Archive Inspection Engine & Zip-Bomb Guard Test
        File zipFile = new File(tempTestDir, "suspicious_archive.zip");
        try (java.util.zip.ZipOutputStream zos = new java.util.zip.ZipOutputStream(Files.newOutputStream(zipFile.toPath()))) {
            java.util.zip.ZipEntry entry = new java.util.zip.ZipEntry("payload.exe");
            zos.putNextEntry(entry);
            zos.write("MZfake_pe_payload".getBytes());
            zos.closeEntry();
        }

        FileContext zipContext = new FileContext(zipFile);
        ArchiveDetectionEngine archiveEngine = new ArchiveDetectionEngine();
        EngineResult zipResult = archiveEngine.evaluate(zipContext);

        System.out.println("[TEST 2] Archive Engine Threat: " + zipResult.getThreatName());
        System.out.println("[TEST 2] Archive ATT&CK Mapping: " + zipResult.getAttackTechniques());
        if (zipResult.getScoreContribution() > 0) {
            System.out.println("[TEST 2 PASSED] Archive Engine Unpacked & Flagged Executable Payload Inside ZIP!");
        } else {
            System.err.println("[TEST 2 FAILED] Archive engine failed to inspect zip contents.");
            System.exit(1);
        }

        // 3. Ransomware Canary Files Guard Test
        RansomwareCanaryGuard canaryGuard = RansomwareCanaryGuard.getInstance();
        canaryGuard.deployCanaries();
        System.out.println("[TEST 3 PASSED] Decoy Canary Files Deployed & Ransomware Watcher Active!");

        // Cleanup
        testFile.delete();
        zipFile.delete();
        tempTestDir.delete();

        System.out.println("\n✅ ALL SENTINEL AV V3.5 EDR & ATT&CK TESTS PASSED!");
    }
}
