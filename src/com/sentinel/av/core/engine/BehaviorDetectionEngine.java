package com.sentinel.av.core.engine;

import com.sentinel.av.core.MagicByteUtils;
import com.sentinel.av.core.TextProbe;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class BehaviorDetectionEngine implements DetectionEngine {

    /** Content window inspected for behavioural markers. */
    private static final int CONTENT_WINDOW = TextProbe.DEFAULT_LIMIT;

    @Override
    public String getEngineId() { return "behavior-sigma-engine"; }

    @Override
    public String getEngineName() { return "Sigma Behavior & MITRE ATT&CK Engine"; }

    @Override
    public EngineResult evaluate(FileContext context) {
        if (context == null) {
            return EngineResult.clean(getEngineId());
        }
        File file = context.getFile();
        if (file == null || !file.isFile()) {
            return EngineResult.clean(getEngineId());
        }

        int score = 0;
        List<String> reasons = new ArrayList<>();
        List<String> attackTechniques = new ArrayList<>();
        String threatName = "None";

        String nameLower = context.getFileNameLower();
        boolean isExe = MagicByteUtils.isExecutableType(context.getMagicFileType());

        // 1. T1036.005 - Disguised PE Header
        if (isExe && isDocumentExtension(nameLower)) {
            score += 80;
            reasons.add("Behavior Rule: Executable PE binary header disguised with an innocent file extension ("
                    + context.getFileName() + ")");
            attackTechniques.add("T1036.005");
            threatName = "Behavior.Masquerading.DisguisedExecutable";
        }

        // Content rules: one bounded read feeds every string check below.
        String content = TextProbe.readPrefix(file, CONTENT_WINDOW);
        if (!content.isEmpty()) {
            String contentLower = content.toLowerCase(java.util.Locale.ROOT);

            // 2. T1059.001 - Encoded / obfuscated PowerShell
            if (contentLower.contains("powershell -enc") || contentLower.contains("powershell -e ")
                    || contentLower.contains("bypass -nop -w hidden")
                    || contentLower.contains("-executionpolicy bypass -windowstyle hidden")) {
                score += 70;
                reasons.add("Behavior Rule: Obfuscated or encoded PowerShell execution sequence.");
                attackTechniques.add("T1059.001");
                if ("None".equals(threatName)) {
                    threatName = "Behavior.Script.ObfuscatedPowerShell";
                }
            }

            // 3. T1055 - Process memory injection APIs
            if (content.contains("VirtualAllocEx") && content.contains("WriteProcessMemory")) {
                score += 85;
                reasons.add("Behavior Rule: process memory injection APIs detected.");
                attackTechniques.add("T1055");
                if ("None".equals(threatName)) {
                    threatName = "Behavior.Injection.ProcessMemoryInjection";
                }
            }

            // 4. T1486 - Ransomware extortion note
            if (content.contains("YOUR_FILES_HAVE_BEEN_ENCRYPTED")
                    || content.contains("DECRYPT_YOUR_FILES")
                    || content.contains("ALL_YOUR_FILES_ARE_LOCKED")) {
                score += 90;
                reasons.add("Behavior Rule: ransomware extortion demand note text matched.");
                attackTechniques.add("T1486");
                if ("None".equals(threatName)) {
                    threatName = "Behavior.Ransomware.NoteText";
                }
            }

            // 5. T1547.001 - autostart persistence written by a script
            if ((contentLower.contains("currentversion\\run") || contentLower.contains("currentversion/run"))
                    && contentLower.contains("reg add")) {
                score += 60;
                reasons.add("Behavior Rule: script registers a Run-key autostart entry.");
                attackTechniques.add("T1547.001");
                if ("None".equals(threatName)) {
                    threatName = "Behavior.Persistence.RegistryRunKey";
                }
            }
        }

        if (score > 0) {
            EngineResult.TrustTier tier = score >= 80
                    ? EngineResult.TrustTier.TRUSTED_AUTO_QUARANTINE
                    : EngineResult.TrustTier.SUSPICION_USER_PROMPT;
            return new EngineResult(getEngineId(), score, tier, threatName, reasons, attackTechniques);
        }

        return EngineResult.clean(getEngineId());
    }

    private static boolean isDocumentExtension(String nameLower) {
        return nameLower.endsWith(".pdf") || nameLower.endsWith(".jpg") || nameLower.endsWith(".jpeg")
                || nameLower.endsWith(".png") || nameLower.endsWith(".txt") || nameLower.endsWith(".docx")
                || nameLower.endsWith(".xlsx") || nameLower.endsWith(".mp3") || nameLower.endsWith(".mp4");
    }
}
