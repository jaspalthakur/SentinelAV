package com.sentinel.av.core.engine;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class EngineResult {

    public enum TrustTier {
        TRUSTED_AUTO_QUARANTINE, // High confidence (Hash DB match) -> Auto isolate
        SUSPICION_USER_PROMPT,   // Single heuristic/entropy hit -> Prompt user for confirmation
        INFORMATIONAL            // Clean or low confidence
    }

    private final String engineId;
    private final int scoreContribution;
    private final TrustTier trustTier;
    private final String threatName;
    private final List<String> reasons;
    private final List<String> attackTechniques; // e.g. ["T1055", "T1059.001"]

    public EngineResult(String engineId, int scoreContribution, TrustTier trustTier, String threatName, List<String> reasons, List<String> attackTechniques) {
        this.engineId = engineId;
        this.scoreContribution = scoreContribution;
        this.trustTier = trustTier;
        this.threatName = threatName;
        this.reasons = reasons != null ? new ArrayList<>(reasons) : Collections.emptyList();
        this.attackTechniques = attackTechniques != null ? new ArrayList<>(attackTechniques) : Collections.emptyList();
    }

    public static EngineResult clean(String engineId) {
        return new EngineResult(engineId, 0, TrustTier.INFORMATIONAL, "None", Collections.emptyList(), Collections.emptyList());
    }

    public String getEngineId() { return engineId; }
    public int getScoreContribution() { return scoreContribution; }
    public TrustTier getTrustTier() { return trustTier; }
    public String getThreatName() { return threatName; }
    public List<String> getReasons() { return Collections.unmodifiableList(reasons); }
    public List<String> getAttackTechniques() { return Collections.unmodifiableList(attackTechniques); }
}
