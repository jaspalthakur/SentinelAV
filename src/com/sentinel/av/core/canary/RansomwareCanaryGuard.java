package com.sentinel.av.core.canary;

import com.sentinel.av.core.ActivityLogger;
import com.sentinel.av.core.QuarantineManager;
import com.sentinel.av.model.ScanResult;
import com.sentinel.av.model.VirusSignature;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

public class RansomwareCanaryGuard {
    private static RansomwareCanaryGuard instance;

    public interface CanaryEventListener {
        void onCanaryTampered(File canaryFile, String threatName);
    }

    private final Set<Path> canaryPaths = ConcurrentHashMap.newKeySet();
    private final AtomicBoolean active = new AtomicBoolean(false);
    private WatchService watchService;
    private Thread monitorThread;
    private final List<CanaryEventListener> listeners = new ArrayList<>();

    private RansomwareCanaryGuard() {}

    public static synchronized RansomwareCanaryGuard getInstance() {
        if (instance == null) {
            instance = new RansomwareCanaryGuard();
        }
        return instance;
    }

    public void addListener(CanaryEventListener listener) {
        listeners.add(listener);
    }

    public synchronized void deployCanaries() {
        String userHome = System.getProperty("user.home");
        Path desktop = Paths.get(userHome, "Desktop");
        Path downloads = Paths.get(userHome, "Downloads");
        Path documents = Paths.get(userHome, "Documents");

        deployInDir(desktop, "!_000_Sentinel_Decoy_Document.docx");
        deployInDir(downloads, "!_000_Sentinel_Decoy_Spreadsheet.xlsx");
        deployInDir(documents, "!_000_Sentinel_Decoy_Vault.pdf");

        startCanaryWatcher();
    }

    private void deployInDir(Path dir, String fileName) {
        if (dir != null && Files.exists(dir) && Files.isDirectory(dir)) {
            Path canaryFile = dir.resolve(fileName);
            try {
                if (!Files.exists(canaryFile)) {
                    String canaryHeader = "SENTINEL_CANARY_DECOY_FILE_DO_NOT_MODIFY_" + UUID.randomUUID();
                    Files.write(canaryFile, canaryHeader.getBytes());
                }
                canaryPaths.add(canaryFile);
                ActivityLogger.getInstance().system("CanaryGuard", "Deployed decoy canary at: " + canaryFile);
            } catch (IOException ignored) {}
        }
    }

    private synchronized void startCanaryWatcher() {
        if (active.get() || canaryPaths.isEmpty()) return;

        try {
            watchService = FileSystems.getDefault().newWatchService();
            Set<Path> parentDirs = new HashSet<>();
            for (Path p : canaryPaths) {
                if (p.getParent() != null) parentDirs.add(p.getParent());
            }

            for (Path parent : parentDirs) {
                parent.register(watchService, StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_DELETE);
            }

            active.set(true);
            monitorThread = new Thread(this::watchCanaries, "Sentinel-CanaryWatcher");
            monitorThread.setDaemon(true);
            monitorThread.start();

            ActivityLogger.getInstance().system("CanaryGuard", "Ransomware Canary Guard ACTIVE.");

        } catch (IOException e) {
            ActivityLogger.getInstance().warning("CanaryGuard", "Failed to start Canary Watcher: " + e.getMessage());
        }
    }

    private void watchCanaries() {
        while (active.get()) {
            WatchKey key;
            try {
                key = watchService.take();
            } catch (InterruptedException | ClosedWatchServiceException e) {
                break;
            }

            Path dir = (Path) key.watchable();
            for (WatchEvent<?> event : key.pollEvents()) {
                Path filename = (Path) event.context();
                Path fullPath = dir.resolve(filename);

                if (canaryPaths.contains(fullPath)) {
                    ActivityLogger.getInstance().threat("CanaryGuard", 
                        "🚨 RANSOMWARE ALERT (T1486): Decoy Canary File Tampered/Modified: " + fullPath);

                    ScanResult result = new ScanResult(
                        fullPath.toFile(),
                        fullPath.toFile().length(),
                        new com.sentinel.av.core.RiskScoreEngine.RiskScoreBreakdown(
                            100,
                            com.sentinel.av.core.RiskScoreEngine.Verdict.CRITICAL_MALWARE,
                            Arrays.asList("Ransomware Canary Decoy File Tampered (MITRE ATT&CK T1486)", "Rapid Unauthorized File Encryption Detected"),
                            "Ransomware.CanaryTamper.T1486"
                        ),
                        "CANARY_TAMPER",
                        "Ransomware Canary Honeypot Engine"
                    );

                    QuarantineManager.getInstance().quarantineFile(result);

                    for (CanaryEventListener l : listeners) {
                        l.onCanaryTampered(fullPath.toFile(), "Ransomware.CanaryTamper.T1486");
                    }
                }
            }

            boolean valid = key.reset();
            if (!valid) break;
        }
    }
}
