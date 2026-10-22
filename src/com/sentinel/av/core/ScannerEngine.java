package com.sentinel.av.core;

import com.sentinel.av.model.ScanResult;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
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

    private final SignatureDatabase db;
    private final AtomicBoolean cancelRequested = new AtomicBoolean(false);
    private final AtomicBoolean isScanning = new AtomicBoolean(false);

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

    public List<ScanResult> scanPathWithMode(File target, ScanMode mode, ScanProgressListener listener) {
        cancelRequested.set(false);
        isScanning.set(true);

        long startTime = System.currentTimeMillis();
        List<ScanResult> allResults = new ArrayList<>();
        List<ScanResult> threats = new ArrayList<>();
        AtomicInteger scannedCount = new AtomicInteger(0);
        AtomicLong totalBytes = new AtomicLong(0);

        List<File> fileList = new ArrayList<>();

        if (mode == ScanMode.QUICK_SCAN) {
            String userHome = System.getProperty("user.home");
            collectFiles(new File(userHome, "Downloads"), fileList);
            collectFiles(new File(userHome, "Desktop"), fileList);
            collectFiles(new File(System.getProperty("java.io.tmpdir")), fileList);
        } else {
            collectFiles(target, fileList);
        }

        ActivityLogger.getInstance().info("ScannerEngine", 
            "Starting " + mode + " on target: " + (target != null ? target.getAbsolutePath() : "Quick Locations") + 
            " (" + fileList.size() + " files)");

        for (File file : fileList) {
            if (cancelRequested.get()) {
                ActivityLogger.getInstance().warning("ScannerEngine", "Scan cancelled by user.");
                break;
            }

            scannedCount.incrementAndGet();
            long size = file.length();
            totalBytes.addAndGet(size);

            if (listener != null) {
                listener.onProgress(file, scannedCount.get(), totalBytes.get(), file.getAbsolutePath());
            }

            ScanResult result = scanSingleFile(file);
            allResults.add(result);

            if (result.isInfected()) {
                threats.add(result);
                ActivityLogger.getInstance().threat("ScannerEngine", 
                    "THREAT DETECTED! File: " + file.getName() + " | Risk Score: " + result.getRiskScore() + "/100 | Threat: " + result.getThreatName());
                if (listener != null) {
                    listener.onThreatDetected(result);
                }
            }
        }

        long duration = System.currentTimeMillis() - startTime;
        isScanning.set(false);

        ActivityLogger.getInstance().info("ScannerEngine", 
            "Scan completed in " + duration + " ms. Total files: " + scannedCount.get() + ", Threats found: " + threats.size());

        if (listener != null) {
            listener.onScanComplete(allResults, threats, duration);
        }

        return threats;
    }

    public ScanResult scanSingleFile(File file) {
        if (!file.exists() || !file.isFile() || !file.canRead()) {
            return new ScanResult(file, 0);
        }

        long fileSize = file.length();
        RiskScoreEngine.RiskScoreBreakdown breakdown = RiskScoreEngine.evaluateFile(file, db);

        if (breakdown.isInfected()) {
            String hash = HashUtils.calculateSHA256(file);
            String method = !breakdown.getReasons().isEmpty() ? breakdown.getReasons().get(0) : "Multi-Signal Heuristics";
            return new ScanResult(file, fileSize, breakdown, hash, method);
        }

        return new ScanResult(file, fileSize);
    }

    private void collectFiles(File target, List<File> fileList) {
        if (target == null || !target.exists() || cancelRequested.get()) return;

        if (target.isFile()) {
            fileList.add(target);
        } else if (target.isDirectory()) {
            File[] files = target.listFiles();
            if (files != null) {
                for (File f : files) {
                    if (cancelRequested.get()) break;
                    if (f.isFile()) {
                        fileList.add(f);
                    } else if (f.isDirectory()) {
                        if (!f.getName().startsWith(".") && !f.getName().equals("node_modules") && !f.getName().equals("$Recycle.Bin")) {
                            collectFiles(f, fileList);
                        }
                    }
                }
            }
        }
    }
}
