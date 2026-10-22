package com.sentinel.av.core;

import com.sentinel.av.model.VirusSignature;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class YaraRuleEvaluator {

    public static class RuleMatch {
        private final String ruleName;
        private final VirusSignature.Severity severity;
        private final String description;
        private final String attackTechnique;

        public RuleMatch(String ruleName, VirusSignature.Severity severity, String description) {
            this(ruleName, severity, description, null);
        }

        public RuleMatch(String ruleName, VirusSignature.Severity severity, String description, String attackTechnique) {
            this.ruleName = ruleName;
            this.severity = severity;
            this.description = description;
            this.attackTechnique = attackTechnique;
        }

        public String getRuleName() { return ruleName; }
        public VirusSignature.Severity getSeverity() { return severity; }
        public String getDescription() { return description; }
        public String getAttackTechnique() { return attackTechnique; }
    }

    private static final Set<String> EXECUTABLE_EXTENSIONS = Set.of(".exe", ".dll", ".sys", ".scr", ".com");

    private YaraRuleEvaluator() {
    }

    public static List<RuleMatch> evaluateRules(File file) {
        if (file == null || !file.isFile() || file.length() == 0) {
            return new ArrayList<>();
        }
        return evaluateRules(TextProbe.readPrefix(file), file.getName().toLowerCase(Locale.ROOT));
    }

    /**
     * Evaluates the built-in rule set against content already read by the caller, so a
     * single file read can feed YARA, pattern signatures and entropy checks.
     *
     * @param content       leading file bytes decoded as ISO-8859-1 (may be empty)
     * @param fileNameLower lowercase file name, used by the masquerading rule
     */
    public static List<RuleMatch> evaluateRules(String content, String fileNameLower) {
        List<RuleMatch> matches = new ArrayList<>();
        if (content == null || content.isEmpty()) {
            return matches;
        }
        String name = fileNameLower != null ? fileNameLower : "";

        // 1. Executable PE header inside a non-executable file (T1036.005)
        if (content.length() >= 2 && content.charAt(0) == 'M' && content.charAt(1) == 'Z'
                && !hasExecutableExtension(name)) {
            matches.add(new RuleMatch(
                    "YARA.Suspicious.DisguisedPEHeader",
                    VirusSignature.Severity.CRITICAL,
                    "Executable PE header 'MZ' detected inside non-executable file",
                    "T1036.005"));
        }

        // 2. PowerShell download / execution cradle (T1059.001)
        if (content.contains("powershell -enc") || content.contains("powershell -e ")
                || content.contains("-ExecutionPolicy Bypass -WindowStyle Hidden")
                || content.contains("IEX (New-Object Net.WebClient)")) {
            matches.add(new RuleMatch(
                    "YARA.Script.ObfuscatedPowerShellDownloader",
                    VirusSignature.Severity.HIGH,
                    "Suspicious hidden/encoded PowerShell script execution sequence.",
                    "T1059.001"));
        }

        // 3. Remote process injection API strings (T1055)
        if (content.contains("VirtualAllocEx") && content.contains("WriteProcessMemory")
                && content.contains("CreateRemoteThread")) {
            matches.add(new RuleMatch(
                    "YARA.Trojan.ProcessInjectionStrings",
                    VirusSignature.Severity.HIGH,
                    "Found Windows API function strings associated with remote process memory injection.",
                    "T1055"));
        }

        // 4. Base64 encoded PE payload (T1027)
        if (content.contains("TVqQAAMAAAAEAAAA") || content.contains("TVpQAA")) {
            matches.add(new RuleMatch(
                    "YARA.Payload.Base64EncodedExecutable",
                    VirusSignature.Severity.HIGH,
                    "Base64 encoded PE binary payload pattern matched.",
                    "T1027"));
        }

        // 5. Ransom note text (T1486)
        if (content.contains("YOUR_FILES_HAVE_BEEN_ENCRYPTED") || content.contains("DECRYPT_YOUR_FILES")
                || content.contains("ALL_YOUR_FILES_ARE_LOCKED")) {
            matches.add(new RuleMatch(
                    "YARA.Ransomware.RansomNoteText",
                    VirusSignature.Severity.CRITICAL,
                    "Ransomware demand note text pattern matched.",
                    "T1486"));
        }

        return matches;
    }

    private static boolean hasExecutableExtension(String name) {
        for (String ext : EXECUTABLE_EXTENSIONS) {
            if (name.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }
}
