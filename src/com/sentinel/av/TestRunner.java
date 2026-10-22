package com.sentinel.av;

import com.sentinel.av.core.ActivityLogger;
import com.sentinel.av.core.AppPaths;
import com.sentinel.av.core.HashUtils;
import com.sentinel.av.core.MagicByteUtils;
import com.sentinel.av.core.QuarantineManager;
import com.sentinel.av.core.RiskScoreEngine;
import com.sentinel.av.core.ScannerEngine;
import com.sentinel.av.core.SignatureDatabase;
import com.sentinel.av.core.canary.RansomwareCanaryGuard;
import com.sentinel.av.core.engine.ArchiveDetectionEngine;
import com.sentinel.av.core.engine.BehaviorDetectionEngine;
import com.sentinel.av.core.engine.EngineResult;
import com.sentinel.av.core.engine.FileContext;
import com.sentinel.av.model.QuarantineItem;
import com.sentinel.av.model.ScanResult;
import com.sentinel.av.model.VirusSignature;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Headless self-test suite. Runs every detection and storage subsystem against throwaway
 * files in a temporary directory ({@code -Dsentinelav.data.dir} is redirected there), so
 * it never touches the real Desktop, Downloads or quarantine vault.
 *
 * <p>Exit code 0 = all tests passed, 1 = at least one failure.</p>
 */
public class TestRunner {

    private static int passed;
    private static int failed;
    private static final List<String> failures = new ArrayList<>();

    @FunctionalInterface
    private interface TestBody {
        void run(Path root) throws Exception;
    }

    public static void main(String[] args) {
        System.exit(run());
    }

    public static int run() {
        passed = 0;
        failed = 0;
        failures.clear();

        Path root;
        try {
            root = Files.createTempDirectory("sentinelav-selftest-");
        } catch (IOException e) {
            System.err.println("Could not create the test workspace: " + e.getMessage());
            return 1;
        }
        System.setProperty(AppPaths.DATA_DIR_PROPERTY, root.resolve("data").toString());

        System.out.println("=== " + Version.display() + " - Headless Test Suite ===");
        System.out.println("Workspace: " + root);
        System.out.println();

        runTest("Hash utilities (MD5 + SHA-256, single pass)", TestRunner::testHashes, root);
        runTest("Magic-byte detection (including 2-byte MZ)", TestRunner::testMagicBytes, root);
        runTest("FileContext lazy hashing", TestRunner::testFileContext, root);
        runTest("Behavior engine maps T1059.001", TestRunner::testBehaviorEngine, root);
        runTest("Disguised executable scores T1036.005", TestRunner::testDisguisedExecutable, root);
        runTest("Pattern signature database detection", TestRunner::testPatternSignature, root);
        runTest("Archive engine flags executable payload", TestRunner::testArchivePayload, root);
        runTest("Archive zip-bomb guard (entry count)", TestRunner::testZipBomb, root);
        runTest("Archive zip-slip guard", TestRunner::testZipSlip, root);
        runTest("Archive nested-archive inspection", TestRunner::testNestedArchive, root);
        runTest("Quarantine encrypt / restore round-trip", TestRunner::testQuarantineRoundTrip, root);
        runTest("Parallel scanner detects exactly one threat", TestRunner::testScanner, root);
        runTest("Ransomware canary tripwire fires", TestRunner::testCanary, root);
        runTest("Signature database stays duplicate-free", TestRunner::testSignatureIntegrity, root);

        ActivityLogger.getInstance().flush();

        System.out.println();
        System.out.println("----------------------------------------------");
        System.out.printf("RESULT: %d passed, %d failed%n", passed, failed);
        if (failed > 0) {
            System.out.println("Failures:");
            for (String failure : failures) {
                System.out.println("  - " + failure);
            }
            System.out.println("Workspace kept for inspection: " + root);
            return 1;
        }

        System.out.println("ALL SENTINELAV TESTS PASSED");
        deleteRecursively(root);
        return 0;
    }

    // ---------------------------------------------------------------- tests

    private static void testHashes(Path root) throws Exception {
        Path dir = Files.createDirectory(root.resolve("hash"));
        File abc = writeText(dir, "abc.txt", "abc");

        check("SHA-256 of 'abc'",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                        .equals(HashUtils.calculateSHA256(abc)));
        check("MD5 of 'abc'",
                "900150983cd24fb0d6963f7d28e17f72".equals(HashUtils.calculateMD5(abc)));

        String[] pair = HashUtils.calculateMD5AndSha256(abc);
        check("Single-pass hashes agree with individual calls",
                pair[0].equals(HashUtils.calculateMD5(abc)) && pair[1].equals(HashUtils.calculateSHA256(abc)));

        File empty = writeText(dir, "empty.txt", "");
        check("MD5 of empty file", "d41d8cd98f00b204e9800998ecf8427e".equals(HashUtils.calculateMD5(empty)));
    }

    private static void testMagicBytes(Path root) throws Exception {
        Path dir = Files.createDirectory(root.resolve("magic"));

        File tinyMz = writeText(dir, "tiny.bin", "MZ");
        check("Two-byte MZ header is detected as executable",
                MagicByteUtils.detectFileType(tinyMz) == MagicByteUtils.FileType.WINDOWS_EXECUTABLE);

        File pdf = writeText(dir, "doc.pdf", "%PDF-1.7\nrest");
        check("PDF header is detected",
                MagicByteUtils.detectFileType(pdf) == MagicByteUtils.FileType.PDF_DOCUMENT);

        File unknown = writeText(dir, "blob.bin", "hello");
        check("Unknown content stays UNKNOWN",
                MagicByteUtils.detectFileType(unknown) == MagicByteUtils.FileType.UNKNOWN);
    }

    private static void testFileContext(Path root) throws Exception {
        Path dir = Files.createDirectory(root.resolve("context"));
        File abc = writeText(dir, "abc.txt", "abc");

        FileContext context = new FileContext(abc);
        check("File size is captured", context.getFileSize() == 3);
        check("SHA-256 matches the standalone helper",
                HashUtils.calculateSHA256(abc).equals(context.getSha256()));
        check("MD5 matches the standalone helper",
                HashUtils.calculateMD5(abc).equals(context.getMd5()));
        check("Same hash array is reused on repeated access", context.getSha256() == context.getSha256());
    }

    private static void testBehaviorEngine(Path root) throws Exception {
        Path dir = Files.createDirectory(root.resolve("behavior"));
        File sample = writeText(dir, "encoded_ps.txt",
                "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAApAA==");

        EngineResult result = new BehaviorDetectionEngine().evaluate(new FileContext(sample));
        check("Behavior score is high enough to act on", result.getScoreContribution() >= 70);
        check("MITRE technique T1059.001 is mapped", result.getAttackTechniques().contains("T1059.001"));
        check("Threat name is reported", !"None".equals(result.getThreatName()));
    }

    private static void testDisguisedExecutable(Path root) throws Exception {
        Path dir = Files.createDirectory(root.resolve("disguise"));
        File fake = writeText(dir, "invoice.pdf", "MZ" + "A".repeat(2048));

        RiskScoreEngine.RiskScoreBreakdown breakdown =
                RiskScoreEngine.evaluateFile(fake, SignatureDatabase.getInstance());
        check("Disguised PE is infected", breakdown.isInfected());
        check("Disguised PE scores at least 80", breakdown.getScore() >= 80);
        check("Masquerading technique T1036.005 is mapped",
                breakdown.getAttackTechniques().contains("T1036.005"));
    }

    private static void testPatternSignature(Path root) throws Exception {
        Path dir = Files.createDirectory(root.resolve("pattern"));
        File note = writeText(dir, "note.txt",
                "hello __LOCKED_BY_SENTINEL_RANSOMTEST__ world");

        RiskScoreEngine.RiskScoreBreakdown breakdown =
                RiskScoreEngine.evaluateFile(note, SignatureDatabase.getInstance());
        check("Pattern signature triggers a detection", breakdown.isInfected());
        check("Ransomware signature name is reported",
                breakdown.getPrimaryThreatName() != null
                        && breakdown.getPrimaryThreatName().toLowerCase().contains("locky"));
        check("Ransomware technique T1486 is mapped",
                breakdown.getAttackTechniques().contains("T1486"));
    }

    private static void testArchivePayload(Path root) throws Exception {
        Path dir = Files.createDirectory(root.resolve("archive"));
        File zip = makeZip(dir, "payload.zip", Map.of("payload.exe", "MZfake_pe_payload".getBytes()));

        EngineResult result = new ArchiveDetectionEngine().evaluate(new FileContext(zip));
        check("Archive payload is flagged", result.getScoreContribution() > 0);
        check("Archive payload maps T1204.002", result.getAttackTechniques().contains("T1204.002"));
    }

    private static void testZipBomb(Path root) throws Exception {
        Path dir = Files.createDirectory(root.resolve("bomb"));
        Map<String, byte[]> entries = new java.util.LinkedHashMap<>();
        for (int i = 0; i < 150; i++) {
            entries.put("file" + i + ".txt", new byte[16]);
        }
        File zip = makeZip(dir, "bomb.zip", entries);

        EngineResult result = new ArchiveDetectionEngine().evaluate(new FileContext(zip));
        check("Archive with 150 entries trips the bomb guard", result.getScoreContribution() > 0);
        check("Zip-bomb threat name is reported",
                result.getThreatName() != null && result.getThreatName().contains("ZipBomb"));
        check("Zip-bomb maps T1499.001", result.getAttackTechniques().contains("T1499.001"));
    }

    private static void testZipSlip(Path root) throws Exception {
        Path dir = Files.createDirectory(root.resolve("slip"));
        File zip = makeZip(dir, "slip.zip", Map.of("../escaped.txt", "payload".getBytes()));

        EngineResult result = new ArchiveDetectionEngine().evaluate(new FileContext(zip));
        check("Path-traversal entry is flagged", result.getScoreContribution() > 0);
        check("Traversal threat name is reported",
                result.getThreatName() != null && result.getThreatName().contains("PathTraversal"));
    }

    private static void testNestedArchive(Path root) throws Exception {
        Path dir = Files.createDirectory(root.resolve("nested"));
        ByteArrayOutputStream innerBytes = new ByteArrayOutputStream();
        try (ZipOutputStream inner = new ZipOutputStream(innerBytes)) {
            inner.putNextEntry(new ZipEntry("dropper.ps1"));
            inner.write("powershell -enc AAAA".getBytes());
            inner.closeEntry();
        }
        File outer = makeZip(dir, "outer.zip", Map.of("inner.zip", innerBytes.toByteArray()));

        EngineResult result = new ArchiveDetectionEngine().evaluate(new FileContext(outer));
        check("Nested archive contents are inspected", result.getScoreContribution() > 0);
    }

    private static void testQuarantineRoundTrip(Path root) throws Exception {
        Path dir = Files.createDirectory(root.resolve("vault"));
        String payload = "sentinel quarantine round trip payload";
        File victim = writeText(dir, "victim.dll", payload);

        ScanResult result = new ScanResult(victim, victim.length(),
                new RiskScoreEngine.RiskScoreBreakdown(95, RiskScoreEngine.Verdict.CRITICAL_MALWARE,
                        List.of("Self-test synthetic detection"), "Test.Synthetic.Malware"),
                "deadbeef", "Self-test");

        QuarantineManager manager = QuarantineManager.getInstance();
        int before = manager.getQuarantineCount();

        check("Quarantine succeeds", manager.quarantineFile(result));
        check("Original file is removed", !victim.exists());
        check("Vault entry is recorded", manager.getQuarantineCount() == before + 1);

        QuarantineItem item = manager.getItems().get(manager.getQuarantineCount() - 1);
        check("Vault file exists", Files.isRegularFile(Path.of(item.getQuarantinedPath())));

        check("Restore succeeds", manager.restoreFile(item));
        check("Restored bytes match the original",
                Files.readString(victim.toPath(), StandardCharsets.UTF_8).equals(payload));
        check("Vault file is removed after restore",
                !Files.exists(Path.of(item.getQuarantinedPath())));
    }

    private static void testScanner(Path root) throws Exception {
        Path dir = Files.createDirectory(root.resolve("scan"));
        writeText(dir, "clean.txt", "nothing to see here");
        writeText(dir, "threat.txt", "hello __LOCKED_BY_SENTINEL_RANSOMTEST__ world");
        writeText(dir, "also-clean.md", "# notes");

        List<ScanResult> seen = new ArrayList<>();
        ScannerEngine engine = new ScannerEngine();
        List<ScanResult> threats = engine.scanPathWithMode(dir.toFile(),
                ScannerEngine.ScanMode.CUSTOM_PATH_SCAN,
                new ScannerEngine.ScanProgressListener() {
                    @Override
                    public void onProgress(File currentFile, int scannedCount, long totalBytes, String currentPath) {
                    }

                    @Override
                    public void onThreatDetected(ScanResult result) {
                    }

                    @Override
                    public void onScanComplete(List<ScanResult> allResults, List<ScanResult> threats, long durationMs) {
                        seen.addAll(allResults);
                    }
                });

        check("All three files were scanned", seen.size() == 3);
        check("Exactly one threat detected", threats.size() == 1);
        check("Detected threat is the seeded signature file",
                threats.get(0).getFileName().equals("threat.txt"));
        check("Engine is idle after the scan", !engine.isScanning());
    }

    private static void testCanary(Path root) throws Exception {
        Path dir = Files.createDirectory(root.resolve("canary"));
        RansomwareCanaryGuard guard = RansomwareCanaryGuard.getInstance();

        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<File> tampered = new AtomicReference<>();
        guard.addListener((canaryFile, threatName) -> {
            tampered.set(canaryFile);
            latch.countDown();
        });

        try {
            guard.deployCanaries(List.of(dir));
            check("Canary watcher is active", guard.isActive());
            check("A decoy file was deployed", !guard.getCanaryPaths().isEmpty());

            Path canary = guard.getCanaryPaths().get(0);
            check("Decoy file exists on disk", Files.isRegularFile(canary));

            Thread.sleep(200); // let the WatchService register before tampering
            Files.writeString(canary, "tampered by self-test");
            check("Tripwire fired within 5 s", latch.await(5, TimeUnit.SECONDS));
            check("Tripwire reported the decoy", tampered.get() != null);
        } finally {
            guard.removeCanaries();
        }
        check("Canary watcher stops cleanly", !guard.isActive());
    }

    private static void testSignatureIntegrity(Path root) {
        SignatureDatabase db = SignatureDatabase.getInstance();
        Set<String> ids = new HashSet<>();
        boolean unique = true;
        for (VirusSignature sig : db.getAllSignatures()) {
            if (!ids.add(sig.getId())) {
                unique = false;
            }
        }
        check("Signature ids are unique", unique);
        check("Built-in pattern signatures are present", db.getPatternSignatures().size() >= 3);
        check("Signature count is positive", db.getSignatureCount() >= 8);
    }

    // -------------------------------------------------------------- helpers

    private static void runTest(String name, TestBody body, Path root) {
        int failuresBefore = failed;
        try {
            body.run(root);
        } catch (Throwable t) {
            failed++;
            failures.add(name + " threw " + t);
            System.out.println("[FAIL] " + name + " - threw " + t);
        }
        if (failed == failuresBefore) {
            System.out.println("[PASS] " + name);
        }
    }

    private static void check(String description, boolean condition) {
        if (condition) {
            passed++;
        } else {
            failed++;
            failures.add(description);
            System.out.println("    [X] " + description);
        }
    }

    private static File writeText(Path dir, String name, String content) throws IOException {
        Path file = dir.resolve(name);
        Files.writeString(file, content, StandardCharsets.UTF_8);
        return file.toFile();
    }

    private static File makeZip(Path dir, String name, Map<String, byte[]> entries) throws IOException {
        File zip = dir.resolve(name).toFile();
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(zip.toPath()))) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                zos.putNextEntry(new ZipEntry(entry.getKey()));
                zos.write(entry.getValue());
                zos.closeEntry();
            }
        }
        return zip;
    }

    private static void deleteRecursively(Path root) {
        try (var stream = Files.walk(root)) {
            stream.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException ignored) {
                    // Best effort cleanup.
                }
            });
        } catch (IOException ignored) {
            // Best effort cleanup.
        }
    }
}
