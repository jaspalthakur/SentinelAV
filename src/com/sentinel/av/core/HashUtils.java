package com.sentinel.av.core;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.HexFormat;

public final class HashUtils {

    /** Buffered read size used for hashing; large blocks cut per-read overhead. */
    private static final int BUFFER_SIZE = 64 * 1024;

    private HashUtils() {
    }

    public static String calculateMD5(File file) {
        return calculateHash(file, "MD5");
    }

    public static String calculateSHA256(File file) {
        return calculateHash(file, "SHA-256");
    }

    /**
     * Streams the file through {@code algorithm} and returns lowercase hex, or
     * {@code null} when the file cannot be read.
     */
    public static String calculateHash(File file, String algorithm) {
        if (file == null || !file.isFile() || !file.canRead()) {
            return null;
        }
        try (InputStream in = Files.newInputStream(file.toPath())) {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] buffer = new byte[BUFFER_SIZE];
            int read;
            while ((read = in.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Computes MD5 and SHA-256 in a single pass over the file.
     *
     * @return {@code [md5, sha256]}, with {@code null} entries when the file is unreadable
     */
    public static String[] calculateMD5AndSha256(File file) {
        if (file == null || !file.isFile() || !file.canRead()) {
            return new String[]{null, null};
        }
        try (InputStream in = Files.newInputStream(file.toPath())) {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[BUFFER_SIZE];
            int read;
            while ((read = in.read(buffer)) != -1) {
                md5.update(buffer, 0, read);
                sha256.update(buffer, 0, read);
            }
            HexFormat hex = HexFormat.of();
            return new String[]{hex.formatHex(md5.digest()), hex.formatHex(sha256.digest())};
        } catch (Exception e) {
            return new String[]{null, null};
        }
    }

    public static String calculateStringMD5(String input) {
        if (input == null) {
            return "";
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            return HexFormat.of().formatHex(digest.digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return "";
        }
    }
}
