package com.sentinel.av.core;

import com.sentinel.av.model.VirusSignature;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class PersistenceScanner {

    public static class PersistenceItem {
        private final String name;
        private final String location;
        private final String command;
        private final VirusSignature.Severity risk;
        private final String reason;

        public PersistenceItem(String name, String location, String command, VirusSignature.Severity risk, String reason) {
            this.name = name;
            this.location = location;
            this.command = command;
            this.risk = risk;
            this.reason = reason;
        }

        public String getName() { return name; }
        public String getLocation() { return location; }
        public String getCommand() { return command; }
        public VirusSignature.Severity getRisk() { return risk; }
        public String getReason() { return reason; }
    }

    public static List<PersistenceItem> scanPersistence() {
        List<PersistenceItem> list = new ArrayList<>();

        // 1. Scan User Startup Folder
        String userHome = System.getProperty("user.home");
        File startupFolder = new File(userHome, "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");

        if (startupFolder.exists() && startupFolder.isDirectory()) {
            File[] files = startupFolder.listFiles();
            if (files != null) {
                for (File f : files) {
                    String nameLower = f.getName().toLowerCase();
                    VirusSignature.Severity risk = VirusSignature.Severity.LOW;
                    String reason = "Legitimate Startup Shortcut/File";

                    if (nameLower.endsWith(".vbs") || nameLower.endsWith(".bat") || nameLower.endsWith(".ps1") || nameLower.endsWith(".scr")) {
                        risk = VirusSignature.Severity.HIGH;
                        reason = "Script or ScreenSaver payload in Startup Folder";
                    }

                    list.add(new PersistenceItem(f.getName(), "Startup Directory", f.getAbsolutePath(), risk, reason));
                }
            }
        }

        // 2. Query Windows Registry Run Key via reg query
        try {
            Process proc = new ProcessBuilder("cmd.exe", "/c", "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run").start();
            try (java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(proc.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("HKEY_")) continue;

                    String[] parts = line.split("\\s{2,}");
                    if (parts.length >= 3) {
                        String regName = parts[0];
                        String regCmd = parts[2];
                        String cmdLower = regCmd.toLowerCase();

                        VirusSignature.Severity risk = VirusSignature.Severity.LOW;
                        String reason = "Standard Registry Startup Key";

                        if (cmdLower.contains("powershell") && (cmdLower.contains("-enc") || cmdLower.contains("hidden"))) {
                            risk = VirusSignature.Severity.CRITICAL;
                            reason = "Encoded / Hidden PowerShell execution at startup";
                        } else if (cmdLower.contains("wscript") || cmdLower.contains("cscript")) {
                            risk = VirusSignature.Severity.HIGH;
                            reason = "VBScript auto-start launcher";
                        } else if (cmdLower.contains("appdata\\local\\temp")) {
                            risk = VirusSignature.Severity.HIGH;
                            reason = "Registry autostart binary located in Temp folder";
                        }

                        list.add(new PersistenceItem(regName, "Registry (HKCU Run)", regCmd, risk, reason));
                    }
                }
            }
        } catch (Exception ignored) {}

        return list;
    }
}
