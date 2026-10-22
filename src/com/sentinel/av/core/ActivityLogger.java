package com.sentinel.av.core;

import com.sentinel.av.model.ActivityLog;
import com.sentinel.av.model.ActivityLog.LogLevel;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class ActivityLogger {
    private static ActivityLogger instance;

    public interface LogListener {
        void onLogAdded(ActivityLog log);
    }

    private final List<ActivityLog> logs = new CopyOnWriteArrayList<>();
    private final List<LogListener> listeners = new CopyOnWriteArrayList<>();
    private final Path logFilePath = Paths.get(System.getProperty("user.home"), ".sentinel_av", "sentinel_activity.log");

    private ActivityLogger() {
        try {
            Files.createDirectories(logFilePath.getParent());
        } catch (IOException ignored) {}
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
        ActivityLog entry = new ActivityLog(level, category, message);
        logs.add(entry);

        // Keep last 1000 logs in memory
        if (logs.size() > 1000) {
            logs.remove(0);
        }

        // Notify UI listeners
        for (LogListener l : listeners) {
            l.onLogAdded(entry);
        }

        // Write to log file asynchronously
        saveToFileAsync(entry);
    }

    private void saveToFileAsync(ActivityLog entry) {
        new Thread(() -> {
            try (BufferedWriter writer = Files.newBufferedWriter(logFilePath, StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
                writer.write(String.format("[%s] [%s] [%s] %s%n", 
                    entry.getTimestamp(), entry.getLevel(), entry.getCategory(), entry.getMessage()));
            } catch (IOException ignored) {}
        }).start();
    }

    public List<ActivityLog> getLogs() {
        return Collections.unmodifiableList(logs);
    }

    public void clearLogs() {
        logs.clear();
    }
}
