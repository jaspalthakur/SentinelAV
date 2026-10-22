package com.sentinel.av.model;

import com.sentinel.av.core.RiskScoreEngine;

import java.io.File;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ScanResult {
    public enum ThreatStatus {
        CLEAN, INFECTED, QUARANTINED, DELETED, ERROR, IGNORED
    }

    private File file;
    private long fileSize;
    private boolean isInfected;
    private String threatName;
    private VirusSignature.Severity severity;
    private String matchedHash;
    private String detectionMethod;
    private int riskScore; // 0 to 100
    private List<String> reasons = new ArrayList<>();
    private ThreatStatus status;
    private LocalDateTime scanTime;

    public ScanResult(File file, long fileSize) {
        this.file = file;
        this.fileSize = fileSize;
        this.isInfected = false;
        this.threatName = "None";
        this.severity = VirusSignature.Severity.LOW;
        this.matchedHash = null;
        this.detectionMethod = "Clean";
        this.riskScore = 0;
        this.reasons = Collections.emptyList();
        this.status = ThreatStatus.CLEAN;
        this.scanTime = LocalDateTime.now();
    }

    public ScanResult(File file, long fileSize, RiskScoreEngine.RiskScoreBreakdown breakdown, String matchedHash, String detectionMethod) {
        this.file = file;
        this.fileSize = fileSize;
        this.isInfected = breakdown.isInfected();
        this.threatName = breakdown.getPrimaryThreatName();
        this.severity = breakdown.getVerdict().getSeverity();
        this.matchedHash = matchedHash;
        this.detectionMethod = detectionMethod;
        this.riskScore = breakdown.getScore();
        this.reasons = new ArrayList<>(breakdown.getReasons());
        this.status = this.isInfected ? ThreatStatus.INFECTED : ThreatStatus.CLEAN;
        this.scanTime = LocalDateTime.now();
    }

    public File getFile() { return file; }
    public String getFilePath() { return file != null ? file.getAbsolutePath() : ""; }
    public String getFileName() { return file != null ? file.getName() : ""; }
    public long getFileSize() { return fileSize; }
    public boolean isInfected() { return isInfected; }
    public String getThreatName() { return threatName; }
    public VirusSignature.Severity getSeverity() { return severity; }
    public String getMatchedHash() { return matchedHash; }
    public String getDetectionMethod() { return detectionMethod; }
    public int getRiskScore() { return riskScore; }
    public List<String> getReasons() { return Collections.unmodifiableList(reasons); }
    public ThreatStatus getStatus() { return status; }
    public void setStatus(ThreatStatus status) { this.status = status; }
    public LocalDateTime getScanTime() { return scanTime; }
}
