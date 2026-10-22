package com.sentinel.av.model;

import java.io.Serializable;

public class VirusSignature implements Serializable {
    private static final long serialVersionUID = 1L;

    public enum Severity {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    private String id;
    private String name;
    private String hash; // MD5 or SHA-256 hash in lowercase
    private String hashType; // "MD5" or "SHA-256"
    private Severity severity;
    private String description;
    private boolean isPattern; // true if signature is string pattern matching (e.g. EICAR)
    private String pattern;

    public VirusSignature(String id, String name, String hash, String hashType, Severity severity, String description) {
        this.id = id;
        this.name = name;
        this.hash = hash != null ? hash.toLowerCase() : null;
        this.hashType = hashType;
        this.severity = severity;
        this.description = description;
        this.isPattern = false;
        this.pattern = null;
    }

    public VirusSignature(String id, String name, String pattern, Severity severity, String description, boolean isPattern) {
        this.id = id;
        this.name = name;
        this.hash = null;
        this.hashType = "PATTERN";
        this.severity = severity;
        this.description = description;
        this.isPattern = isPattern;
        this.pattern = pattern;
    }

    public String getId() { return id; }
    public String getName() { return name; }
    public String getHash() { return hash; }
    public String getHashType() { return hashType; }
    public Severity getSeverity() { return severity; }
    public String getDescription() { return description; }
    public boolean isPattern() { return isPattern; }
    public String getPattern() { return pattern; }

    @Override
    public String toString() {
        return name + " (" + (isPattern ? "Pattern" : hashType + ": " + hash) + ")";
    }
}
