package com.sentinel.av.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class ActivityLog {
    public enum LogLevel {
        INFO, WARNING, THREAT_DETECTED, QUARANTINE, SYSTEM
    }

    private String timestamp;
    private LogLevel level;
    private String category;
    private String message;

    public ActivityLog(LogLevel level, String category, String message) {
        this.timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        this.level = level;
        this.category = category;
        this.message = message;
    }

    public String getTimestamp() { return timestamp; }
    public LogLevel getLevel() { return level; }
    public String getCategory() { return category; }
    public String getMessage() { return message; }
}
