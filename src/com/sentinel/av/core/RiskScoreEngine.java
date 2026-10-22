package com.sentinel.av.core;

import com.sentinel.av.core.engine.FileContext;
import com.sentinel.av.model.VirusSignature;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

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
        private final List<String> attackTechniques;

        public RiskScoreBreakdown(int score, Verdict verdict, List<String> reasons, String primaryThreatName) {
            this(score, verdict, reasons, primaryThreatName, Collections.emptyList());
        }

        public RiskScoreBreakdown(int score, Verdict verdict, List<String> reasons, String primaryThreatName,
                                  List<String> attackTechniques) {
            this.score = Math.min(100, Math.max(0, score));
            this.verdict = verdict;
            this.reasons = reasons != null ? reasons : Collections.emptyList();
            this.primaryThreatName = primaryThreatName;
            this.attackTechniques = attackTechniques != null ? attackTechniques : Collections.emptyList();
        }

        public int getScore() { return score; }
        public Verdict getVerdict() { return verdict; }
        public List<String> getReasons() { return Collections.unmodifiableList(reasons); }
        public String getPrimaryThreatName() { return primaryThreatName; }
        public List<String> getAttackTechniques() { return Collections.unmodifiableList(attackTechniques); }
        public boolean isInfected() { return score >= 50; }
    }

    /** Maximum file size still eligible for content (string) inspection. */
    private static final long MAX_CONTENT_SCAN_BYTES = 10L * 1024 * 1024;

    private RiskScoreEngine() {
    }

    public static RiskScoreBreakdown evaluateFile(File file, SignatureDatabase db) {
        if (file == null) {
            return clean();
        }
        return evaluateFile(new FileContext(file), db);
    }

    public static RiskScoreBreakdown evaluateFile(FileContext ctx, SignatureDatabase db) {
        File file = ctx.getFile();
        if (file == null || !file.isFile()) {
            return clean();
        }

        int score = 0;
        List<String> reasons = new ArrayList<>();
        Set<String> techniques = new LinkedHashSet<>();
        String threatName = "None";

        // 1. Signature database hash lookup (+100). MD5 first, then SHA-256 only if needed.
        String md5 = ctx.getMd5();
        if (md5 != null) {
            VirusSignature sig = db.findByMD5(md5);
            if (sig != null) {
                score += 100;
                reasons.add("Exact MD5 hash match with known malware signature: " + sig.getName());
                threatName = sig.getName();
                addTechnique(techniques, sig);
            }
        }
        if (score < 100) {
            String sha256 = ctx.getSha256();
            if (sha256 != null) {
                VirusSignature sig = db.findBySHA256(sha256);
                if (sig != null) {
                    score += 100;
                    reasons.add("Exact SHA-256 hash match with known malware signature: " + sig.getName());
                    threatName = sig.getName();
                    addTechnique(techniques, sig);
                }
            }
        }

        String nameLower = ctx.getFileNameLower();
        boolean isExe = ctx.isExecutable();

        // 2. Magic-byte discrepancy: executable payload behind a document extension (+80).
        if (isExe && isDisguisedExtension(nameLower)) {
            score += 80;
            reasons.add("Magic-Byte Discrepancy: executable header disguised as a non-executable ("
                    + file.getName() + ")");
            if ("None".equals(threatName)) {
                threatName = "Heuristic.DisguisedExecutableHeader";
            }
            techniques.add("T1036.005");
        }

        // 3. Single content read shared by YARA rules and pattern signatures.
        if (file.length() <= MAX_CONTENT_SCAN_BYTES) {
            String content = TextProbe.readPrefix(file);

            for (YaraRuleEvaluator.RuleMatch yara : YaraRuleEvaluator.evaluateRules(content, nameLower)) {
                score += 60;
                reasons.add("YARA Rule Match: " + yara.getRuleName() + " (" + yara.getDescription() + ")");
                if ("None".equals(threatName)) {
                    threatName = yara.getRuleName();
                }
                if (yara.getAttackTechnique() != null) {
                    techniques.add(yara.getAttackTechnique());
                }
            }

            if (!content.isEmpty()) {
                String contentLower = content.toLowerCase(Locale.ROOT);
                for (VirusSignature sig : db.getPatternSignatures()) {
                    String pattern = sig.getPattern();
                    if (pattern == null || pattern.isBlank()) {
                        continue;
                    }
                    if (contentLower.contains(pattern.toLowerCase(Locale.ROOT))) {
                        score += 70;
                        reasons.add("Signature pattern match: " + sig.getName());
                        if ("None".equals(threatName)) {
                            threatName = sig.getName();
                        }
                        addTechnique(techniques, sig);
                    }
                }
            }
        }

        // 4. Block-wise entropy analysis (+35), only meaningful for executable payloads.
        EntropyCalculator.EntropyAnalysisResult entropyRes = EntropyCalculator.analyzeEntropy(file);
        if (entropyRes.isHighEntropy() && isExe) {
            score += 35;
            reasons.add("High block entropy (" + entropyRes.getMaxBlockEntropy()
                    + " / 8.0) indicating packed code or an encrypted payload.");
            if ("None".equals(threatName)) {
                threatName = "Heuristic.HighEntropyPackedExecutable";
            }
            techniques.add("T1027.002");
        }

        // 5. Executable or script launched from a temporary directory (+25).
        String pathLower = file.getAbsolutePath().toLowerCase(Locale.ROOT);
        if (pathLower.contains("\\temp\\") || pathLower.endsWith("\\temp")) {
            if (isExe || isScript(nameLower)) {
                score += 25;
                reasons.add("Suspicious location: executable/script in a temporary system directory.");
            }
        }

        // 6. Double-extension disguise (+30).
        if (hasDoubleExtension(nameLower)) {
            score += 30;
            reasons.add("Suspicious double-extension disguise pattern.");
            if ("None".equals(threatName)) {
                threatName = "Heuristic.DoubleExtensionDisguise";
            }
            techniques.add("T1036.007");
        }

        return new RiskScoreBreakdown(score, verdictFor(score), reasons, threatName, new ArrayList<>(techniques));
    }

    private static RiskScoreBreakdown clean() {
        return new RiskScoreBreakdown(0, Verdict.CLEAN, Collections.emptyList(), "None", Collections.emptyList());
    }

    private static void addTechnique(Set<String> techniques, VirusSignature sig) {
        if (sig.getAttackTechnique() != null && !sig.getAttackTechnique().isBlank()) {
            techniques.add(sig.getAttackTechnique());
        }
    }

    private static boolean isDisguisedExtension(String nameLower) {
        return nameLower.endsWith(".pdf") || nameLower.endsWith(".jpg") || nameLower.endsWith(".jpeg")
                || nameLower.endsWith(".png") || nameLower.endsWith(".txt") || nameLower.endsWith(".docx")
                || nameLower.endsWith(".xlsx") || nameLower.endsWith(".mp4");
    }

    private static boolean isScript(String nameLower) {
        return nameLower.endsWith(".vbs") || nameLower.endsWith(".bat") || nameLower.endsWith(".cmd")
                || nameLower.endsWith(".ps1") || nameLower.endsWith(".js") || nameLower.endsWith(".hta");
    }

    private static boolean hasDoubleExtension(String nameLower) {
        return nameLower.endsWith(".pdf.exe") || nameLower.endsWith(".doc.exe")
                || nameLower.endsWith(".jpg.exe") || nameLower.endsWith(".txt.vbs")
                || nameLower.endsWith(".pdf.scr") || nameLower.endsWith(".docm.exe");
    }

    private static Verdict verdictFor(int score) {
        if (score >= 95) return Verdict.CRITICAL_MALWARE;
        if (score >= 70) return Verdict.HIGH_RISK;
        if (score >= 45) return Verdict.SUSPICIOUS_MEDIUM;
        if (score >= 20) return Verdict.SUSPICIOUS_LOW;
        return Verdict.CLEAN;
    }
}
