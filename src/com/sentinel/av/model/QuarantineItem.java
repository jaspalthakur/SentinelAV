package com.sentinel.av.model;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class QuarantineItem implements Serializable {
    private static final long serialVersionUID = 2L;

    private String id;
    private String originalPath;
    private String quarantinedPath;
    private String fileName;
    private String threatName;
    private VirusSignature.Severity severity;
    private long fileSize;
    private String quarantineTimeFormatted;
    private String aesKeyBase64;
    private String ivBase64;
    private int riskScore;
    private List<String> reasons;

    public QuarantineItem(String id, String originalPath, String quarantinedPath, String fileName, String threatName, 
                          VirusSignature.Severity severity, long fileSize, String aesKeyBase64, String ivBase64, 
                          int riskScore, List<String> reasons) {
        this.id = id;
        this.originalPath = originalPath;
        this.quarantinedPath = quarantinedPath;
        this.fileName = fileName;
        this.threatName = threatName;
        this.severity = severity;
        this.fileSize = fileSize;
        this.quarantineTimeFormatted = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        this.aesKeyBase64 = aesKeyBase64;
        this.ivBase64 = ivBase64;
        this.riskScore = riskScore;
        this.reasons = reasons != null ? new ArrayList<>(reasons) : Collections.emptyList();
    }

    public String getId() { return id; }
    public String getOriginalPath() { return originalPath; }
    public String getQuarantinedPath() { return quarantinedPath; }
    public String getFileName() { return fileName; }
    public String getThreatName() { return threatName; }
    public VirusSignature.Severity getSeverity() { return severity; }
    public long getFileSize() { return fileSize; }
    public String getQuarantineTimeFormatted() { return quarantineTimeFormatted; }
    public String getAesKeyBase64() { return aesKeyBase64; }
    public String getIvBase64() { return ivBase64; }
    public int getRiskScore() { return riskScore; }
    public List<String> getReasons() { return reasons != null ? Collections.unmodifiableList(reasons) : Collections.emptyList(); }
}
