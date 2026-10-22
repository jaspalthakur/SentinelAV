package com.sentinel.av.core;

import com.sentinel.av.model.ScanResult;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class RealTimeMonitor {
    private static RealTimeMonitor instance;

    public interface MonitorEventListener {
        void onFileDetected(Path path, String eventType);
        void onThreatIntercepted(ScanResult result);
        void onMonitorStatusChanged(boolean isActive);
    }

    private final Set<Path> watchedPaths = new HashSet<>();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private WatchService watchService;
    private ExecutorService monitorExecutor;
    private ExecutorService scanThreadPool;
    private final ScannerEngine scannerEngine = new ScannerEngine();
    private final List<MonitorEventListener> listeners = new CopyOnWriteArrayList<>();
    private final Map<Path, Long> lastProcessedMap = new ConcurrentHashMap<>();

    private RealTimeMonitor() {
        String userHome = System.getProperty("user.home");
        Path downloads = Paths.get(userHome, "Downloads");
        Path desktop = Paths.get(userHome, "Desktop");
        Path temp = Paths.get(System.getProperty("java.io.tmpdir"));

        if (Files.exists(downloads)) watchedPaths.add(downloads);
        if (Files.exists(desktop)) watchedPaths.add(desktop);
        if (Files.exists(temp)) watchedPaths.add(temp);
    }

    public static synchronized RealTimeMonitor getInstance() {
        if (instance == null) {
            instance = new RealTimeMonitor();
        }
        return instance;
    }

    public void addListener(MonitorEventListener listener) {
        listeners.add(listener);
    }

    public void removeListener(MonitorEventListener listener) {
        listeners.remove(listener);
    }

    public synchronized void addWatchedDirectory(Path path) {
        if (path != null && Files.isDirectory(path)) {
            watchedPaths.add(path);
            if (running.get() && watchService != null) {
                registerTree(path);
            }
        }
    }

    public Set<Path> getWatchedPaths() {
        return Collections.unmodifiableSet(watchedPaths);
    }

    public boolean isRunning() {
        return running.get();
    }

    public synchronized void startMonitoring() {
        if (running.get()) return;

        try {
            watchService = FileSystems.getDefault().newWatchService();
            for (Path path : watchedPaths) {
                if (Files.exists(path) && Files.isDirectory(path)) {
                    registerTree(path);
                }
            }

            running.set(true);
            scanThreadPool = Executors.newFixedThreadPool(4); // Bounded worker pool
            monitorExecutor = Executors.newSingleThreadExecutor();
            monitorExecutor.submit(this::processEvents);

            ActivityLogger.getInstance().system("RealTimeMonitor", "Real-Time Shield Service STARTED with Debounced ThreadPool.");
            notifyStatus(true);

        } catch (IOException e) {
            ActivityLogger.getInstance().warning("RealTimeMonitor", "Failed to start Real-Time Monitor: " + e.getMessage());
        }
    }

    public synchronized void stopMonitoring() {
        if (!running.get()) return;

        running.set(false);
        try {
            if (watchService != null) {
                watchService.close();
            }
            if (scanThreadPool != null) {
                scanThreadPool.shutdownNow();
            }
            if (monitorExecutor != null) {
                monitorExecutor.shutdownNow();
            }
        } catch (IOException e) {
            // Shutdown silent catch
        }

        ActivityLogger.getInstance().system("RealTimeMonitor", "Real-Time Shield Service STOPPED.");
        notifyStatus(false);
    }

    private void registerTree(Path start) {
        try {
            Files.walkFileTree(start, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                    if (!dir.getFileName().toString().startsWith(".") && !dir.getFileName().toString().equals("node_modules")) {
                        dir.register(watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY);
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException ignored) {}
    }

    private void processEvents() {
        while (running.get()) {
            WatchKey key;
            try {
                key = watchService.take();
            } catch (InterruptedException | ClosedWatchServiceException e) {
                break;
            }

            Path dir = (Path) key.watchable();
            for (WatchEvent<?> event : key.pollEvents()) {
                WatchEvent.Kind<?> kind = event.kind();
                if (kind == StandardWatchEventKinds.OVERFLOW) continue;

                @SuppressWarnings("unchecked")
                WatchEvent<Path> ev = (WatchEvent<Path>) event;
                Path filename = ev.context();
                Path fullPath = dir.resolve(filename);

                notifyFileDetected(fullPath, kind.name());

                if (Files.exists(fullPath) && Files.isRegularFile(fullPath)) {
                    // Debounce: Ignore duplicate file events within 1.5 seconds
                    long now = System.currentTimeMillis();
                    Long lastTime = lastProcessedMap.get(fullPath);
                    if (lastTime != null && (now - lastTime) < 1500) {
                        continue;
                    }
                    lastProcessedMap.put(fullPath, now);

                    // Submit to bounded thread pool
                    scanThreadPool.submit(() -> debounceAndScan(fullPath));
                }
            }

            boolean valid = key.reset();
            if (!valid) {
                // Key invalid
            }
        }
    }

    private void debounceAndScan(Path fullPath) {
        // Wait for file write stabilization
        long prevSize = -1;
        for (int i = 0; i < 5; i++) {
            try {
                if (!Files.exists(fullPath)) return;
                long currSize = Files.size(fullPath);
                if (currSize > 0 && currSize == prevSize) {
                    break;
                }
                prevSize = currSize;
                Thread.sleep(300);
            } catch (Exception ignored) {
                break;
            }
        }

        File fileToScan = fullPath.toFile();
        if (!fileToScan.exists() || !fileToScan.canRead()) return;

        ScanResult result = scannerEngine.scanSingleFile(fileToScan);

        if (result.isInfected()) {
            ActivityLogger.getInstance().threat("RealTimeMonitor", 
                "REAL-TIME SHIELD INTERCEPTED THREAT: " + result.getThreatName() + " in " + fullPath + " (Score: " + result.getRiskScore() + "/100)");

            // Auto Quarantine
            QuarantineManager.getInstance().quarantineFile(result);
            notifyThreatIntercepted(result);
        }
    }

    private void notifyFileDetected(Path path, String eventType) {
        for (MonitorEventListener l : listeners) {
            l.onFileDetected(path, eventType);
        }
    }

    private void notifyThreatIntercepted(ScanResult result) {
        for (MonitorEventListener l : listeners) {
            l.onThreatIntercepted(result);
        }
    }

    private void notifyStatus(boolean isActive) {
        for (MonitorEventListener l : listeners) {
            l.onMonitorStatusChanged(isActive);
        }
    }
}
