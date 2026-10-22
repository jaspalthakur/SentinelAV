package com.sentinel.av.core.engine;

import com.sentinel.av.core.MagicByteUtils;

import java.io.InputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class ArchiveDetectionEngine implements DetectionEngine {

    private static final int MAX_FILE_COUNT = 100;
    private static final long MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024; // 100 MB max

    @Override
    public String getEngineId() { return "archive-inspector-engine"; }

    @Override
    public String getEngineName() { return "Archive & Container Inspection Engine"; }

    @Override
    public EngineResult evaluate(FileContext context) {
        if (context.getMagicFileType() != MagicByteUtils.FileType.ZIP_ARCHIVE) {
            return EngineResult.clean(getEngineId());
        }

        List<String> reasons = new ArrayList<>();
        List<String> attackTechniques = new ArrayList<>();
        int fileCount = 0;
        long totalBytes = 0;

        try (InputStream fis = Files.newInputStream(context.getFile().toPath());
             ZipInputStream zis = new ZipInputStream(fis)) {

            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                fileCount++;
                if (fileCount > MAX_FILE_COUNT) {
                    reasons.add("Zip-Bomb Guard: Exceeded maximum file count limit (100 files inside archive)");
                    attackTechniques.add("T1499.001"); // Denial of Service: OS Exhaustion
                    return new EngineResult(getEngineId(), 60, EngineResult.TrustTier.SUSPICION_USER_PROMPT, "Heuristic.ZipBombPattern", reasons, attackTechniques);
                }

                long entrySize = entry.getSize();
                if (entrySize > 0) totalBytes += entrySize;
                if (totalBytes > MAX_UNCOMPRESSED_BYTES) {
                    reasons.add("Zip-Bomb Guard: Uncompressed size exceeds 100MB limit.");
                    attackTechniques.add("T1499.001");
                    return new EngineResult(getEngineId(), 60, EngineResult.TrustTier.SUSPICION_USER_PROMPT, "Heuristic.ZipBombPattern", reasons, attackTechniques);
                }

                String entryName = entry.getName().toLowerCase();
                if (entryName.endsWith(".exe") || entryName.endsWith(".vbs") || entryName.endsWith(".bat") || entryName.endsWith(".ps1") || entryName.endsWith(".scr")) {
                    reasons.add("Archive contains executable or script payload: " + entry.getName());
                    attackTechniques.add("T1204.002"); // User Execution: Malicious File
                    return new EngineResult(getEngineId(), 45, EngineResult.TrustTier.SUSPICION_USER_PROMPT, "Heuristic.ArchiveExecutablePayload", reasons, attackTechniques);
                }
            }
        } catch (Exception ignored) {}

        return EngineResult.clean(getEngineId());
    }
}
