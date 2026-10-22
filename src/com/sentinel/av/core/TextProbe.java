package com.sentinel.av.core;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/**
 * Reads a bounded leading slice of a file once so several heuristic checks can
 * share the same bytes instead of re-opening the file per rule.
 */
public final class TextProbe {

    /** Default cap for content inspection: 1 MiB. */
    public static final int DEFAULT_LIMIT = 1024 * 1024;

    private TextProbe() {
    }

    public static String readPrefix(File file) {
        return readPrefix(file, DEFAULT_LIMIT);
    }

    /**
     * @return the first {@code maxBytes} of the file decoded as ISO-8859-1 (a 1:1
     *         byte-to-char mapping, so ASCII pattern matching stays byte exact).
     *         Never {@code null}; unreadable files yield an empty string.
     */
    public static String readPrefix(File file, int maxBytes) {
        if (file == null || maxBytes <= 0 || !file.isFile() || !file.canRead()) {
            return "";
        }
        byte[] chunk = new byte[Math.min(maxBytes, 64 * 1024)];
        StringBuilder sb = new StringBuilder(Math.min(maxBytes, 64 * 1024));
        int total = 0;
        try (InputStream in = Files.newInputStream(file.toPath())) {
            int read;
            while (total < maxBytes
                    && (read = in.read(chunk, 0, Math.min(chunk.length, maxBytes - total))) > 0) {
                sb.append(new String(chunk, 0, read, StandardCharsets.ISO_8859_1));
                total += read;
            }
        } catch (Exception ignored) {
            // Partial or unreadable files simply return what was captured so far.
        }
        return sb.toString();
    }
}
