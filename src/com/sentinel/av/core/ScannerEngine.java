package com.sentinel.av.core;

import com.sentinel.av.core.engine.FileContext;
import com.sentinel.av.model.ScanResult;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class ScannerEngine {

    public interface ScanProgressListener {
        void onProgress(File currentFile, int scannedCount, long totalBytes, String currentPath);
        void onThreatDetected(ScanResult result);
        void onScanComplete(List<ScanResult> allResults, List<ScanResult> threats, long durationMs);
    }

    public enum ScanMode {
        QUICK_SCAN, FULL_SYSTEM_SCAN, CUSTOM_PATH_SCAN, PROCESS_MEMORY_SCAN
    }

    /** Hard ceiling on files fed to a single scan, to bound memory on huge volumes. */
    private static final int MAX_FILES_PER_SCAN = 250_000;
    /** Minimum gap between progress callbacks so the UI is not flooded mid-scan. */
    private static final long PROGRESS_INTERVAL_MS = 100L;
    private static final int MAX_WORKER_THREADS = 8;

    private final SignatureDatabase db;
    private final java.util.concurrent.atomic.AtomicBoolean cancelRequested = new java.util.concurrent.atomic.AtomicBoolean(false);
    private final java.util.concurrent.atomic.AtomicBoolean isScanning = new java.util.concurrent.atomic.AtomicBoolean(false);

    public ScannerEngine() {
        this.db = SignatureDatabase.getInstance();
    }

    public void cancelScan() {
        cancelRequested.set(true);
    }

    public boolean isScanning() {
        return isScanning.get();
    }

    public List<ScanResult> scanPath(File target, ScanProgressListener listener) {
        return scanPathWithMode(target, ScanMode.CUSTOM_PATH_SCAN, listener);
    }

    /**
     * Scans the requested target using a small worker pool. Each worker claims the next
     * file index, so results keep their discovery order while detection runs in parallel.
     */
    public List<ScanResult> scanPathWithMode(File target, ScanMode mode, ScanProgressListener listener) {
        cancelRequested.set(false);
        isScanning.set(true);

        long startTime = System.currentTimeMillis();
        List<File> fileList = collectTargets(target, mode);

        ActivityLogger.getInstance().info("ScannerEngine",
                "Starting " + mode + " on " + describeTarget(target, mode) + " (" + fileList.size() + " files)");

        int fileCount = fileList.size();
        ScanResult[] results = new ScanResult[fileCount];
        AtomicInteger nextIndex = new AtomicInteger(0);
        AtomicInteger scannedCount = new AtomicInteger(0);
        AtomicLong totalBytes = new AtomicLong(0);
        AtomicLong lastProgressAt = new AtomicLong(0);

        if (fileCount > 0) {
            int threads = Math.max(1, Math.min(MAX_WORKER_THREADS,
                    Math.min(fileCount, Runtime.getRuntime().availableProcessors())));
            ExecutorService pool = Executors.newFixedThreadPool(threads, runnable -> {
                Thread thread = new Thread(runnable, "Sentinel-Scan-Worker");
                thread.setDaemon(true);
                return thread;
            });

            Runnable worker = () -> {
                while (!cancelRequested.get()) {
                    int index = nextIndex.getAndIncrement();
                    if (index >= fileCount) {
                        return;
                    }
                    File file = fileList.get(index);
                    long size = file.length();
                    int count = scannedCount.incrementAndGet();
                    long bytes = totalBytes.addAndGet(size);

                    long now = System.currentTimeMillis();
                    long last = lastProgressAt.get();
                    if (listener != null && (now - last >= PROGRESS_INTERVAL_MS || count == fileCount)
                            && lastProgressAt.compareAndSet(last, now)) {
                        safeProgress(listener, file, count, bytes);
                    }

                    ScanResult result;
                    try {
                        result = scanSingleFile(file);
                    } catch (Throwable t) {
                        // One unreadable or vanishing file must not abort the whole scan.
                        result = new ScanResult(file, size);
                    }
                    results[index] = result;

                    if (result.isInfected() && listener != null) {
                        try {
                            listener.onThreatDetected(result);
                        } catch (RuntimeException ignored) {
                            // Keep scanning even if the UI listener fails.
                        }
                    }
                }
            };

            try {
                for (int i = 0; i < threads; i++) {
                    pool.execute(worker);
                }
                pool.shutdown();
                while (!pool.awaitTermination(1, TimeUnit.DAYS)) {
                    // Keep waiting; workers exit promptly once cancel is requested.
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                cancelRequested.set(true);
                pool.shutdownNow();
            } finally {
                pool.shutdownNow();
            }
        }

        boolean cancelled = cancelRequested.get();
        long duration = System.currentTimeMillis() - startTime;

        List<ScanResult> allResults = new ArrayList<>(fileCount);
        List<ScanResult> threats = new ArrayList<>();
        for (int i = 0; i < fileCount; i++) {
            ScanResult result = results[i];
            if (result == null) {
                continue;
            }
            allResults.add(result);
            if (result.isInfected()) {
                threats.add(result);
                ActivityLogger.getInstance().threat("ScannerEngine",
                        "THREAT DETECTED! File: " + result.getFileName()
                                + " | Risk Score: " + result.getRiskScore() + "/100"
                                + " | Threat: " + result.getThreatName());
            }
        }

        isScanning.set(false);

        ActivityLogger.getInstance().info("ScannerEngine",
                (cancelled ? "Scan cancelled after " : "Scan completed in ") + duration
                        + " ms. Total files: " + scannedCount.get() + ", Threats found: " + threats.size());

        if (listener != null) {
            listener.onScanComplete(allResults, threats, duration);
        }
        return threats;
    }

    public ScanResult scanSingleFile(File file) {
        if (file == null || !file.isFile() || !file.canRead()) {
            return new ScanResult(file, 0);
        }

        FileContext context = new FileContext(file);
        RiskScoreEngine.RiskScoreBreakdown breakdown = RiskScoreEngine.evaluateFile(context, db);

        if (breakdown.isInfected()) {
            String hash = context.getSha256();
            String method = !breakdown.getReasons().isEmpty()
                    ? breakdown.getReasons().get(0)
                    : "Multi-Signal Heuristics";
            return new ScanResult(file, context.getFileSize(), breakdown, hash, method);
        }

        return new ScanResult(file, context.getFileSize());
    }

    private List<File> collectTargets(File target, ScanMode mode) {
        List<File> fileList = new ArrayList<>();

        if (mode == ScanMode.QUICK_SCAN) {
            String userHome = System.getProperty("user.home");
            collectFiles(new File(userHome, "Downloads"), fileList);
            collectFiles(new File(userHome, "Desktop"), fileList);
            collectFiles(new File(System.getProperty("java.io.tmpdir")), fileList);
        } else {
            collectFiles(target, fileList);
        }
        return fileList;
    }

    private String describeTarget(File target, ScanMode mode) {
        if (mode == ScanMode.QUICK_SCAN) {
            return "Quick Locations";
        }
        return target != null ? target.getAbsolutePath() : "Quick Locations";
    }

    private void safeProgress(ScanProgressListener listener, File file, int count, long bytes) {
        try {
            listener.onProgress(file, count, bytes, file.getAbsolutePath());
        } catch (RuntimeException ignored) {
            // Progress reporting must never stop a scan.
        }
    }

    private void collectFiles(File target, List<File> fileList) {
        if (target == null || fileList.size() >= MAX_FILES_PER_SCAN || cancelRequested.get()) {
            return;
        }
        if (target.isFile()) {
            if (isScannable(target)) {
                fileList.add(target);
            }
            return;
        }
        if (!target.isDirectory()) {
            return;
        }

        java.nio.file.Path dataDir = AppPaths.dataDir();
        if (target.toPath().toAbsolutePath().normalize().startsWith(dataDir)) {
            return; // never scan our own vault/log/signature store
        }

        File[] files = target.listFiles();
        if (files == null) {
            return;
        }
        java.util.Arrays.sort(files);
        for (File f : files) {
            if (cancelRequested.get() || fileList.size() >= MAX_FILES_PER_SCAN) {
                return;
            }
            if (f.isFile()) {
                if (isScannable(f)) {
                    fileList.add(f);
                }
            } else if (f.isDirectory() && isTraversable(f)) {
                collectFiles(f, fileList);
            }
        }
    }

    private static boolean isTraversable(File dir) {
        String name = dir.getName();
        if (name.startsWith(".") || name.equals("node_modules") || name.equals("$Recycle.Bin")) {
            return false;
        }
        java.nio.file.Path path = dir.toPath().toAbsolutePath().normalize();
        return !path.startsWith(AppPaths.dataDir());
    }

    private static boolean isScannable(File file) {
        String name = file.getName().toLowerCase(java.util.Locale.ROOT);
        if (name.endsWith(".sentinel_locked_vault") || name.endsWith(".sentinel_restore")) {
            return false;
        }
        return !file.toPath().toAbsolutePath().normalize().startsWith(AppPaths.dataDir());
    }
}
