package com.sentinel.av.core.engine;

import com.sentinel.av.core.MagicByteUtils;
import com.sentinel.av.core.YaraRuleEvaluator;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class BehaviorDetectionEngine implements DetectionEngine {

    @Override
    public String getEngineId() { return "behavior-sigma-engine"; }

    @Override
    public String getEngineName() { return "Sigma Behavior & MITRE ATT&CK Engine"; }

    @Override
    public EngineResult evaluate(FileContext context) {
        File file = context.getFile();
        if (file == null || !file.exists() || !file.isFile()) {
            return EngineResult.clean(getEngineId());
        }

        int score = 0;
        List<String> reasons = new ArrayList<>();
        List<String> attackTechniques = new ArrayList<>();
        String threatName = "None";

        String nameLower = context.getFileName().toLowerCase();
        boolean isExe = MagicByteUtils.isExecutableType(context.getMagicFileType());

        // 1. T1036.005 - Disguised PE Header
        if (isExe && (nameLower.endsWith(".pdf") || nameLower.endsWith(".jpg") || nameLower.endsWith(".png") || nameLower.endsWith(".txt"))) {
            score += 80;
            reasons.add("Behavior Rule: Executable PE binary header disguised with innocent file extension (" + context.getFileName() + ")");
            attackTechniques.add("T1036.005"); // Masquerading: Match Legitimate Name or Location
            threatName = "Behavior.Masquerading.DisguisedExecutable";
        }

        // 2. T1059.001 - Encoded / Obfuscated PowerShell Command
        if (file.length() < 5 * 1024 * 1024) {
            try (InputStream is = new FileInputStream(file)) {
                byte[] buf = new byte[16384];
                int read = is.read(buf);
                if (read > 0) {
                    String content = new String(buf, 0, read, "ISO-8859-1");

                    if (content.contains("powershell -enc") || content.contains("powershell -e ") || content.contains("bypass -nop -w hidden")) {
                        score += 70;
                        reasons.add("Behavior Rule: Obfuscated or Encoded PowerShell execution sequence.");
                        attackTechniques.add("T1059.001"); // Command and Scripting Interpreter: PowerShell
                        if ("None".equals(threatName)) threatName = "Behavior.Script.ObfuscatedPowerShell";
                    }

                    // T1055 - Process Memory Injection APIs
                    if (content.contains("VirtualAllocEx") && content.contains("WriteProcessMemory")) {
                        score += 85;
                        reasons.add("Behavior Rule: Process memory injection APIs detected.");
                        attackTechniques.add("T1055"); // Process Injection
                        if ("None".equals(threatName)) threatName = "Behavior.Injection.ProcessMemoryInjection";
                    }

                    // T1486 - Ransomware Note Header
                    if (content.contains("YOUR_FILES_HAVE_BEEN_ENCRYPTED") || content.contains("DECRYPT_YOUR_FILES")) {
                        score += 90;
                        reasons.add("Behavior Rule: Ransomware extortion demand note text matched.");
                        attackTechniques.add("T1486"); // Data Encrypted for Impact
                        if ("None".equals(threatName)) threatName = "Behavior.Ransomware.NoteText";
                    }
                }
            } catch (Exception ignored) {}
        }

        if (score > 0) {
            EngineResult.TrustTier tier = score >= 80 ? EngineResult.TrustTier.TRUSTED_AUTO_QUARANTINE : EngineResult.TrustTier.SUSPICION_USER_PROMPT;
            return new EngineResult(getEngineId(), score, tier, threatName, reasons, attackTechniques);
        }

        return EngineResult.clean(getEngineId());
    }
}
