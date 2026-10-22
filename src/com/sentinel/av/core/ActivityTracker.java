package com.sentinel.av.core;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.*;

public class ActivityTracker implements Serializable {
    private static final long serialVersionUID = 1L;
    private static ActivityTracker instance;

    private LocalDateTime lastScanTime = null;
    private int totalScansRun = 0;
    private int totalFilesScanned = 0;
    private int totalThreatsBlocked = 0;
    private final Map<String, Integer> dailyScansMap = new LinkedHashMap<>();
    private final Map<String, Integer> dailyThreatsMap = new LinkedHashMap<>();

    private ActivityTracker() {
        // Initialize last 7 days with zero values
        for (int i = 6; i >= 0; i--) {
            String day = LocalDateTime.now().minusDays(i).format(DateTimeFormatter.ofPattern("EEE"));
            dailyScansMap.put(day, 0);
            dailyThreatsMap.put(day, 0);
        }
    }

    public static synchronized ActivityTracker getInstance() {
        if (instance == null) {
            instance = new ActivityTracker();
        }
        return instance;
    }

    public synchronized void recordScan(int filesScanned, int threatsFound) {
        this.lastScanTime = LocalDateTime.now();
        this.totalScansRun++;
        this.totalFilesScanned += filesScanned;
        this.totalThreatsBlocked += threatsFound;

        String todayStr = LocalDateTime.now().format(DateTimeFormatter.ofPattern("EEE"));
        dailyScansMap.put(todayStr, dailyScansMap.getOrDefault(todayStr, 0) + filesScanned);
        dailyThreatsMap.put(todayStr, dailyThreatsMap.getOrDefault(todayStr, 0) + threatsFound);
    }

    public LocalDateTime getLastScanTime() { return lastScanTime; }
    public int getTotalScansRun() { return totalScansRun; }
    public int getTotalFilesScanned() { return totalFilesScanned; }
    public int getTotalThreatsBlocked() { return totalThreatsBlocked; }

    public String getLastScanFormatted() {
        if (lastScanTime == null) return "Never";
        long mins = ChronoUnit.MINUTES.between(lastScanTime, LocalDateTime.now());
        if (mins < 1) return "Just now";
        if (mins < 60) return mins + " mins ago";
        long hours = ChronoUnit.HOURS.between(lastScanTime, LocalDateTime.now());
        if (hours < 24) return hours + " hours ago";
        return lastScanTime.format(DateTimeFormatter.ofPattern("MMM dd, HH:mm"));
    }

    public Map<String, Integer> getDailyScansMap() {
        return Collections.unmodifiableMap(dailyScansMap);
    }

    public Map<String, Integer> getDailyThreatsMap() {
        return Collections.unmodifiableMap(dailyThreatsMap);
    }
}
