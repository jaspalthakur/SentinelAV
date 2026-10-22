package com.sentinel.av.core;

import com.sentinel.av.model.VirusSignature;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class YaraRuleEvaluator {

    public static class RuleMatch {
        private final String ruleName;
        private final VirusSignature.Severity severity;
        private final String description;

        public RuleMatch(String ruleName, VirusSignature.Severity severity, String description) {
            this.ruleName = ruleName;
            this.severity = severity;
            this.description = description;
        }

        public String getRuleName() { return ruleName; }
        public VirusSignature.Severity getSeverity() { return severity; }
        public String getDescription() { return description; }
    }

    public static List<RuleMatch> evaluateRules(File file) {
        List<RuleMatch> matches = new ArrayList<>();
        if (file == null || !file.exists() || !file.isFile() || file.length() == 0) {
            return matches;
        }

        String fileNameLower = file.getName().toLowerCase();

        // 1. Check Disguised PE Executable Header (File starts with 'MZ' but extension is non-exe)
        try (InputStream is = new FileInputStream(file)) {
            byte[] header = new byte[2];
            int read = is.read(header);
            if (read == 2 && header[0] == 'M' && header[1] == 'Z') {
                if (!fileNameLower.endsWith(".exe") && !fileNameLower.endsWith(".dll") && 
                    !fileNameLower.endsWith(".sys") && !fileNameLower.endsWith(".scr")) {
                    matches.add(new RuleMatch(
                        "YARA.Suspicious.DisguisedPEHeader",
                        VirusSignature.Severity.CRITICAL,
                        "Executable PE header 'MZ' detected inside non-executable file (" + file.getName() + ")"
                    ));
                }
            }
        } catch (Exception ignored) {}

        // 2. Text / Binary String Pattern Inspection (inspect up to first 1MB)
        if (file.length() < 10 * 1024 * 1024) {
            try (InputStream is = new FileInputStream(file)) {
                byte[] buffer = new byte[16384];
                int bytesRead;
                StringBuilder sb = new StringBuilder();
                int totalRead = 0;
                while ((bytesRead = is.read(buffer)) != -1 && totalRead < 1024 * 1024) {
                    sb.append(new String(buffer, 0, bytesRead, "ISO-8859-1"));
                    totalRead += bytesRead;
                }

                String content = sb.toString();

                // Process Injection API String Rule
                if (content.contains("VirtualAllocEx") && content.contains("WriteProcessMemory") && content.contains("CreateRemoteThread")) {
                    matches.add(new RuleMatch(
                        "YARA.Trojan.ProcessInjectionStrings",
                        VirusSignature.Severity.HIGH,
                        "Found Windows API function strings associated with remote process memory injection."
                    ));
                }

                // Obfuscated PowerShell Execution Rule
                if (content.contains("powershell -enc") || content.contains("powershell -e ") || 
                    content.contains("-ExecutionPolicy Bypass -WindowStyle Hidden")) {
                    matches.add(new RuleMatch(
                        "YARA.Script.ObfuscatedPowerShellDownloader",
                        VirusSignature.Severity.HIGH,
                        "Suspicious hidden/encoded PowerShell script execution sequence."
                    ));
                }

                // Base64 Encoded PE Executable Rule
                if (content.contains("TVqQAAMAAAAEAAAA") || content.contains("TVpQAA")) {
                    matches.add(new RuleMatch(
                        "YARA.Payload.Base64EncodedExecutable",
                        VirusSignature.Severity.HIGH,
                        "Base64 encoded PE binary payload pattern matched."
                    ));
                }

                // Ransom Note String Rule
                if (content.contains("YOUR_FILES_HAVE_BEEN_ENCRYPTED") || content.contains("DECRYPT_YOUR_FILES") ||
                    content.contains("ALL_YOUR_FILES_ARE_LOCKED")) {
                    matches.add(new RuleMatch(
                        "YARA.Ransomware.RansomNoteText",
                        VirusSignature.Severity.CRITICAL,
                        "Ransomware demand note text pattern matched."
                    ));
                }

            } catch (Exception ignored) {}
        }

        return matches;
    }
}
