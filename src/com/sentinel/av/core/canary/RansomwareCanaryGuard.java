package com.sentinel.av.core.canary;

import com.sentinel.av.core.ActivityLogger;

import java.io.File;
import java.io.IOException;
import java.nio.file.ClosedWatchServiceException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.nio.file.StandardWatchEventKinds.ENTRY_DELETE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY;

/**
 * Ransomware canary honeypot: deploys harmless decoy documents and watches them for
 * modification or deletion (T1486).
 *
 * <p>Decoys can be deployed into an explicit set of directories, which keeps automated
 * tests out of the user's real Desktop/Downloads. A tampered decoy is redeployed rather
 * than quarantined — the decoy belongs to us, and removing it would silence the tripwire.</p>
 */
public class RansomwareCanaryGuard {
    private static RansomwareCanaryGuard instance;

    public interface CanaryEventListener {
        void onCanaryTampered(File canaryFile, String threatName);
    }

    public static final String CANARY_PREFIX = "!_000_Sentinel_Decoy_";
    private static final String[] DEFAULT_DECOY_NAMES = {
            "Document.docx", "Spreadsheet.xlsx", "Vault.pdf"
    };

    private final Set<Path> canaryPaths = ConcurrentHashMap.newKeySet();
    /** Suppresses the MODIFY event produced by our own decoy rewrite. */
    private final java.util.Map<Path, Long> suppressUntil = new ConcurrentHashMap<>();
    private final AtomicBoolean active = new AtomicBoolean(false);
    private final List<CanaryEventListener> listeners = new CopyOnWriteArrayList<>();

    private WatchService watchService;
    private Thread monitorThread;

    private RansomwareCanaryGuard() {
    }

    public static synchronized RansomwareCanaryGuard getInstance() {
        if (instance == null) {
            instance = new RansomwareCanaryGuard();
        }
        return instance;
    }

    public void addListener(CanaryEventListener listener) {
        listeners.add(listener);
    }

    public void removeListener(CanaryEventListener listener) {
        listeners.remove(listener);
    }

    /** Deploys decoys into the user's Desktop/Downloads/Documents when those exist. */
    public void deployCanaries() {
        String userHome = System.getProperty("user.home");
        List<Path> dirs = new ArrayList<>();
        dirs.add(Paths.get(userHome, "Desktop"));
        dirs.add(Paths.get(userHome, "Downloads"));
        dirs.add(Paths.get(userHome, "Documents"));
        deployCanaries(dirs);
    }

    /**
     * Deploys one decoy per existing directory in {@code directories} and starts the
     * watcher. Safe to call repeatedly; existing decoys are reused.
     */
    public synchronized void deployCanaries(Collection<Path> directories) {
        int index = 0;
        for (Path dir : directories) {
            if (dir == null || !Files.isDirectory(dir)) {
                continue;
            }
            String decoyName = CANARY_PREFIX
                    + (index < DEFAULT_DECOY_NAMES.length ? DEFAULT_DECOY_NAMES[index] : index + ".dat");
            deployInDir(dir, decoyName);
            index++;
        }
        startCanaryWatcher();
    }

    /** Removes every deployed decoy and stops the watcher; mainly for tests and shutdown. */
    public synchronized void removeCanaries() {
        stopWatcher();
        for (Path canary : canaryPaths) {
            try {
                Files.deleteIfExists(canary);
            } catch (IOException ignored) {
                // Best effort cleanup.
            }
        }
        canaryPaths.clear();
    }

    public List<Path> getCanaryPaths() {
        return List.copyOf(canaryPaths);
    }

    public boolean isActive() {
        return active.get();
    }

    private void deployInDir(Path dir, String fileName) {
        Path canaryFile = dir.resolve(fileName);
        try {
            if (!Files.exists(canaryFile)) {
                writeDecoy(canaryFile);
            }
            canaryPaths.add(canaryFile);
            ActivityLogger.getInstance().system("CanaryGuard", "Deployed decoy canary at: " + canaryFile);
        } catch (IOException ignored) {
            // A read-only directory simply gets no decoy.
        }
    }

    private void writeDecoy(Path canaryFile) throws IOException {
        String header = "SENTINEL_CANARY_DECOY_FILE_DO_NOT_MODIFY_" + UUID.randomUUID();
        Files.write(canaryFile, header.getBytes(), StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
    }

    private synchronized void startCanaryWatcher() {
        if (active.get() || canaryPaths.isEmpty()) {
            return;
        }

        try {
            watchService = FileSystems.getDefault().newWatchService();
            Set<Path> parentDirs = new HashSet<>();
            for (Path p : canaryPaths) {
                if (p.getParent() != null) {
                    parentDirs.add(p.getParent());
                }
            }
            for (Path parent : parentDirs) {
                parent.register(watchService, ENTRY_MODIFY, ENTRY_DELETE);
            }

            active.set(true);
            monitorThread = new Thread(this::watchCanaries, "Sentinel-CanaryWatcher");
            monitorThread.setDaemon(true);
            monitorThread.start();

            ActivityLogger.getInstance().system("CanaryGuard", "Ransomware Canary Guard ACTIVE.");

        } catch (IOException e) {
            ActivityLogger.getInstance().warning("CanaryGuard",
                    "Failed to start Canary Watcher: " + e.getMessage());
        }
    }

    private synchronized void stopWatcher() {
        if (!active.getAndSet(false)) {
            return;
        }
        try {
            if (watchService != null) {
                watchService.close();
            }
        } catch (IOException ignored) {
            // Shutting down anyway.
        }
        if (monitorThread != null) {
            monitorThread.interrupt();
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
                if (event.kind() == java.nio.file.StandardWatchEventKinds.OVERFLOW) {
                    continue;
                }
                Path filename = (Path) event.context();
                Path fullPath = dir.resolve(filename);

                if (canaryPaths.contains(fullPath) && !isSuppressed(fullPath)) {
                    handleTamper(fullPath);
                }
            }

            if (!key.reset()) {
                break;
            }
        }
    }

    private boolean isSuppressed(Path canaryPath) {
        Long until = suppressUntil.get(canaryPath);
        if (until == null) {
            return false;
        }
        if (System.currentTimeMillis() > until) {
            suppressUntil.remove(canaryPath);
            return false;
        }
        return true;
    }

    private void handleTamper(Path canaryPath) {
        // Rewriting the decoy generates another MODIFY event; ignore that echo.
        suppressUntil.put(canaryPath, System.currentTimeMillis() + 2000L);

        ActivityLogger.getInstance().threat("CanaryGuard",
                "🚨 RANSOMWARE ALERT (T1486): decoy canary file tampered with: " + canaryPath);

        // Put the tripwire back so a second attempt is still caught.
        try {
            writeDecoy(canaryPath);
        } catch (IOException e) {
            ActivityLogger.getInstance().warning("CanaryGuard",
                    "Could not redeploy decoy " + canaryPath + ": " + e.getMessage());
        }

        for (CanaryEventListener listener : listeners) {
            try {
                listener.onCanaryTampered(canaryPath.toFile(), "Ransomware.CanaryTamper.T1486");
            } catch (RuntimeException ignored) {
                // One bad listener must not stop the others.
            }
        }
    }
}
