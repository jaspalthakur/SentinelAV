package com.sentinel.av.core;

import com.sentinel.av.model.ActivityLog;
import com.sentinel.av.model.ActivityLog.LogLevel;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * In-memory activity log with bounded, asynchronous disk persistence.
 *
 * <p>Logging used to spawn one thread per entry; a 50k-file scan therefore created 50k
 * threads. Entries are now handed to a single daemon writer with a fixed-size queue, and
 * the in-memory ring keeps only the most recent {@value #MAX_IN_MEMORY} entries.</p>
 */
public class ActivityLogger {
    private static ActivityLogger instance;

    public interface LogListener {
        void onLogAdded(ActivityLog log);
    }

    private static final int MAX_IN_MEMORY = 2000;
    private static final int WRITE_QUEUE_CAPACITY = 8192;
    private static final int MAX_MESSAGE_LENGTH = 4000;

    private final Deque<ActivityLog> logs = new ArrayDeque<>();
    private final List<LogListener> listeners = new CopyOnWriteArrayList<>();
    private final Path logFilePath = AppPaths.logFile();
    private final ThreadPoolExecutor writer;

    private ActivityLogger() {
        try {
            Path parent = logFilePath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
        } catch (IOException ignored) {
            // Logging must never prevent the application from starting.
        }

        ThreadFactory factory = runnable -> {
            Thread thread = new Thread(runnable, "Sentinel-LogWriter");
            thread.setDaemon(true);
            return thread;
        };
        writer = new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(WRITE_QUEUE_CAPACITY), factory,
                new ThreadPoolExecutor.DiscardOldestPolicy());
        writer.allowCoreThreadTimeOut(false);
    }

    public static synchronized ActivityLogger getInstance() {
        if (instance == null) {
            instance = new ActivityLogger();
        }
        return instance;
    }

    public void addListener(LogListener listener) {
        listeners.add(listener);
    }

    public void removeListener(LogListener listener) {
        listeners.remove(listener);
    }

    public void info(String category, String message) {
        log(LogLevel.INFO, category, message);
    }

    public void warning(String category, String message) {
        log(LogLevel.WARNING, category, message);
    }

    public void threat(String category, String message) {
        log(LogLevel.THREAT_DETECTED, category, message);
    }

    public void quarantine(String category, String message) {
        log(LogLevel.QUARANTINE, category, message);
    }

    public void system(String category, String message) {
        log(LogLevel.SYSTEM, category, message);
    }

    private void log(LogLevel level, String category, String message) {
        String safeMessage = message != null && message.length() > MAX_MESSAGE_LENGTH
                ? message.substring(0, MAX_MESSAGE_LENGTH) + "…"
                : message;
        ActivityLog entry = new ActivityLog(level, category, safeMessage);

        synchronized (logs) {
            if (logs.size() >= MAX_IN_MEMORY) {
                logs.pollFirst();
            }
            logs.addLast(entry);
        }

        for (LogListener listener : listeners) {
            try {
                listener.onLogAdded(entry);
            } catch (RuntimeException ignored) {
                // A broken UI listener must not break logging.
            }
        }

        if (!writer.isShutdown()) {
            writer.execute(() -> appendToFile(entry));
        }
    }

    private void appendToFile(ActivityLog entry) {
        try (BufferedWriter writerHandle = Files.newBufferedWriter(logFilePath,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
            writerHandle.write(String.format("[%s] [%s] [%s] %s%n",
                    entry.getTimestamp(), entry.getLevel(), entry.getCategory(), entry.getMessage()));
        } catch (IOException ignored) {
            // Best-effort persistence.
        }
    }

    public List<ActivityLog> getLogs() {
        synchronized (logs) {
            return List.copyOf(logs);
        }
    }

    public void clearLogs() {
        synchronized (logs) {
            logs.clear();
        }
    }

    /** Drains queued log writes; used by tests and orderly shutdown. */
    public void flush() {
        writer.shutdown();
        try {
            writer.awaitTermination(2, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
