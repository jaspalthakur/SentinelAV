package com.sentinel.av.core.engine;

import com.sentinel.av.core.MagicByteUtils;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Inspects ZIP-based containers (zip, jar, docx/xlsx/pptx, apk) without extracting
 * them to disk.
 *
 * <p>Guards enforced here (all counted over the whole nested tree):</p>
 * <ul>
 *   <li>at most {@value #MAX_FILE_COUNT} entries — zip-bomb / inode exhaustion (T1499.001)</li>
 *   <li>at most {@value #MAX_UNCOMPRESSED_BYTES} uncompressed bytes — counted from the
 *       bytes actually read, because {@link ZipEntry#getSize()} is {@code -1} for
 *       streamed local headers</li>
 *   <li>at most {@value #MAX_DEPTH} levels of nested archives</li>
 *   <li>entries whose name escapes the archive root (zip-slip)</li>
 * </ul>
 */
public class ArchiveDetectionEngine implements DetectionEngine {

    private static final int MAX_FILE_COUNT = 100;
    private static final long MAX_UNCOMPRESSED_BYTES = 100L * 1024 * 1024;
    private static final int MAX_DEPTH = 3;
    /** Cap on how much of a nested archive is buffered for recursive inspection. */
    private static final int MAX_NESTED_BYTES = 32 * 1024 * 1024;

    private static final Set<String> PAYLOAD_EXTENSIONS = Set.of(
            ".exe", ".vbs", ".bat", ".cmd", ".ps1", ".scr", ".js", ".jse",
            ".hta", ".wsf", ".lnk", ".msi", ".jar", ".apk");

    @Override
    public String getEngineId() { return "archive-inspector-engine"; }

    @Override
    public String getEngineName() { return "Archive & Container Inspection Engine"; }

    @Override
    public EngineResult evaluate(FileContext context) {
        if (context == null || context.getMagicFileType() != MagicByteUtils.FileType.ZIP_ARCHIVE) {
            return EngineResult.clean(getEngineId());
        }

        Stats stats = new Stats();
        try (ZipInputStream zis = new ZipInputStream(
                new BufferedInputStream(Files.newInputStream(context.getFile().toPath())))) {
            return inspect(zis, 0, stats);
        } catch (Exception e) {
            // Corrupt or truncated container: nothing further can be proven.
            return EngineResult.clean(getEngineId());
        }
    }

    private EngineResult inspect(ZipInputStream zis, int depth, Stats stats) throws IOException {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            if (++stats.entries > MAX_FILE_COUNT) {
                return finding(60, "Heuristic.ZipBombPattern",
                        "Zip-Bomb Guard: archive contains more than " + MAX_FILE_COUNT + " entries.",
                        "T1499.001");
            }

            String entryName = entry.getName();
            if (isPathTraversal(entryName)) {
                return finding(70, "Heuristic.ArchivePathTraversal",
                        "Archive entry escapes the extraction root (zip-slip): " + entryName,
                        "T1036");
            }
            if (entry.isDirectory()) {
                continue;
            }

            // Declared size, when present, lets us reject a bomb before reading it.
            if (entry.getSize() > MAX_UNCOMPRESSED_BYTES) {
                return finding(60, "Heuristic.ZipBombPattern",
                        "Zip-Bomb Guard: declared uncompressed size exceeds 100 MB ("
                                + entryName + ").",
                        "T1499.001");
            }

            String entryLower = entryName.toLowerCase(Locale.ROOT);
            if (hasPayloadExtension(entryLower)) {
                return finding(45, "Heuristic.ArchiveExecutablePayload",
                        "Archive contains executable or script payload: " + entryName,
                        "T1204.002");
            }

            byte[] header = new byte[8];
            int headerLen = 0;
            ByteArrayOutputStream nested = depth < MAX_DEPTH ? new ByteArrayOutputStream() : null;
            byte[] buffer = new byte[8192];
            int read;
            while ((read = zis.read(buffer)) > 0) {
                if (headerLen < header.length) {
                    int copy = Math.min(read, header.length - headerLen);
                    System.arraycopy(buffer, 0, header, headerLen, copy);
                    headerLen += copy;
                }
                stats.totalBytes += read;
                if (stats.totalBytes > MAX_UNCOMPRESSED_BYTES) {
                    return finding(60, "Heuristic.ZipBombPattern",
                            "Zip-Bomb Guard: uncompressed size exceeds 100 MB limit.",
                            "T1499.001");
                }
                if (nested != null) {
                    if (nested.size() + read > MAX_NESTED_BYTES) {
                        nested = null; // too big to recurse into; keep scanning siblings
                    } else {
                        nested.write(buffer, 0, read);
                    }
                }
            }

            if (nested != null && headerLen >= 4
                    && MagicByteUtils.classify(header, headerLen) == MagicByteUtils.FileType.ZIP_ARCHIVE) {
                byte[] inner = nested.toByteArray();
                try (ZipInputStream innerZip = new ZipInputStream(new ByteArrayInputStream(inner))) {
                    EngineResult recursion = inspect(innerZip, depth + 1, stats);
                    if (recursion.getScoreContribution() > 0) {
                        return recursion;
                    }
                } catch (Exception ignored) {
                    // A nested entry that is not a valid archive is not itself suspicious.
                }
            }
        }
        return EngineResult.clean(getEngineId());
    }

    private EngineResult finding(int score, String threatName, String reason, String technique) {
        return new EngineResult(getEngineId(), score, EngineResult.TrustTier.SUSPICION_USER_PROMPT,
                threatName, List.of(reason), List.of(technique));
    }

    private static boolean hasPayloadExtension(String entryLower) {
        for (String ext : PAYLOAD_EXTENSIONS) {
            if (entryLower.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isPathTraversal(String entryName) {
        String normalized = entryName.replace('\\', '/');
        return normalized.startsWith("/")
                || normalized.startsWith("../")
                || normalized.contains("/../")
                || normalized.matches("^[A-Za-z]:/.*");
    }

    /** Running counters shared across the whole nested inspection. */
    private static final class Stats {
        private int entries;
        private long totalBytes;
    }
}
