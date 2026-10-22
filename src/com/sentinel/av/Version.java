package com.sentinel.av;

/** Single source of truth for the application version. */
public final class Version {

    public static final String VERSION = "3.8.0";
    public static final String CODENAME = "EDR & MITRE ATT&CK Threat Engine";

    private Version() {
    }

    public static String display() {
        return "SentinelAV " + VERSION + " - " + CODENAME;
    }
}
