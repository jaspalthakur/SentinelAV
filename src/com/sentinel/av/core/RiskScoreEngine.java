package com.sentinel.av.core;

import com.sentinel.av.model.VirusSignature;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class RiskScoreEngine {

    public enum Verdict {
        CLEAN(0, VirusSignature.Severity.LOW),
        SUSPICIOUS_LOW(25, VirusSignature.Severity.LOW),
        SUSPICIOUS_MEDIUM(50, VirusSignature.Severity.MEDIUM),
        HIGH_RISK(75, VirusSignature.Severity.HIGH),
        CRITICAL_MALWARE(95, VirusSignature.Severity.CRITICAL);

        private final int minScore;
        private final VirusSignature.Severity severity;

        Verdict(int minScore, VirusSignature.Severity severity) {
            this.minScore = minScore;
            this.severity = severity;
        }

        public int getMinScore() { return minScore; }
        public VirusSignature.Severity getSeverity() { return severity; }
    }

    public static class RiskScoreBreakdown {
        private final int score; // 0 to 100
        private final Verdict verdict;
        private final List<String> reasons;
        private final String primaryThreatName;

        public RiskScoreBreakdown(int score, Verdict verdict, List<String> reasons, String primaryThreatName) {
            this.score = Math.min(100, Math.max(0, score));
            this.verdict = verdict;
            this.reasons = reasons;
            this.primaryThreatName = primaryThreatName;
        }

        public int getScore() { return score; }
        public Verdict getVerdict() { return verdict; }
        public List<String> getReasons() { return Collections.unmodifiableList(reasons); }
        public String getPrimaryThreatName() { return primaryThreatName; }
        public boolean isInfected() { return score >= 50; }
    }

    public static RiskScoreBreakdown evaluateFile(File file, SignatureDatabase db) {
        if (file == null || !file.exists() || !file.isFile()) {
            return new RiskScoreBreakdown(0, Verdict.CLEAN, Collections.emptyList(), "None");
        }

        int score = 0;
        List<String> reasons = new ArrayList<>();
        String threatName = "None";

        // 1. Signature Database Hash Check (+100)
        String md5 = HashUtils.calculateMD5(file);
        if (md5 != null) {
            VirusSignature sig = db.findByMD5(md5);
            if (sig != null) {
                score += 100;
                reasons.add("Exact MD5 Hash match with known malware signature database: " + sig.getName());
                threatName = sig.getName();
            }
        }

        String sha256 = HashUtils.calculateSHA256(file);
        if (sha256 != null && score < 100) {
            VirusSignature sig = db.findBySHA256(sha256);
            if (sig != null) {
                score += 100;
                reasons.add("Exact SHA-256 Hash match with known malware signature database: " + sig.getName());
                threatName = sig.getName();
            }
        }

        // 2. Magic-Byte Discrepancy Check (+80)
        MagicByteUtils.FileType realType = MagicByteUtils.detectFileType(file);
        String nameLower = file.getName().toLowerCase();
        boolean isExe = MagicByteUtils.isExecutableType(realType);

        if (isExe && (nameLower.endsWith(".pdf") || nameLower.endsWith(".jpg") || nameLower.endsWith(".png") || nameLower.endsWith(".txt") || nameLower.endsWith(".docx"))) {
            score += 80;
            reasons.add("Magic-Byte Discrepancy: Windows/Linux Executable header disguised as non-executable (" + file.getName() + ")");
            if ("None".equals(threatName)) threatName = "Heuristic.DisguisedExecutableHeader";
        }

        // 3. YARA Rule Engine Evaluation (+50 to +90)
        List<YaraRuleEvaluator.RuleMatch> yaraMatches = YaraRuleEvaluator.evaluateRules(file);
        for (YaraRuleEvaluator.RuleMatch yara : yaraMatches) {
            score += 60;
            reasons.add("YARA Rule Match: " + yara.getRuleName() + " (" + yara.getDescription() + ")");
            if ("None".equals(threatName)) threatName = yara.getRuleName();
        }

        // 4. Block-Wise Entropy Analysis (+35)
        EntropyCalculator.EntropyAnalysisResult entropyRes = EntropyCalculator.analyzeEntropy(file);
        if (entropyRes.isHighEntropy() && isExe) {
            score += 35;
            reasons.add("High Block Entropy Score (" + entropyRes.getMaxBlockEntropy() + " / 8.0) indicating packed code or encryption payload.");
            if ("None".equals(threatName)) threatName = "Heuristic.HighEntropyPackedExecutable";
        }

        // 5. File Location Penalty (+25)
        String pathLower = file.getAbsolutePath().toLowerCase();
        if (pathLower.contains("appdata\\local\\temp") || pathLower.contains("windows\\temp")) {
            if (isExe || nameLower.endsWith(".vbs") || nameLower.endsWith(".bat") || nameLower.endsWith(".ps1")) {
                score += 25;
                reasons.add("Suspicious File Location: Executable/Script running from Temporary System Directory.");
            }
        }

        // 6. Suspicious Double Extension (+30)
        if (nameLower.endsWith(".pdf.exe") || nameLower.endsWith(".doc.exe") || nameLower.endsWith(".jpg.exe") || nameLower.endsWith(".txt.vbs")) {
            score += 30;
            reasons.add("Suspicious Double Extension disguise pattern.");
            if ("None".equals(threatName)) threatName = "Heuristic.DoubleExtensionDisguise";
        }

        // Determine Final Verdict
        Verdict verdict;
        if (score >= 95) verdict = Verdict.CRITICAL_MALWARE;
        else if (score >= 70) verdict = Verdict.HIGH_RISK;
        else if (score >= 45) verdict = Verdict.SUSPICIOUS_MEDIUM;
        else if (score >= 20) verdict = Verdict.SUSPICIOUS_LOW;
        else verdict = Verdict.CLEAN;

        return new RiskScoreBreakdown(score, verdict, reasons, threatName);
    }
}
