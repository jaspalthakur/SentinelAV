package com.sentinel.av.core;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;

public class HashUtils {

    public static String calculateMD5(File file) {
        return calculateHash(file, "MD5");
    }

    public static String calculateSHA256(File file) {
        return calculateHash(file, "SHA-256");
    }

    public static String calculateHash(File file, String algorithm) {
        if (file == null || !file.exists() || !file.isFile() || !file.canRead()) {
            return null;
        }
        // Limit hash calculation for very large files (> 500 MB) if needed, or buffer
        try (InputStream fis = new FileInputStream(file)) {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] byteArray = new byte[8192];
            int bytesCount;
            while ((bytesCount = fis.read(byteArray)) != -1) {
                digest.update(byteArray, 0, bytesCount);
            }
            byte[] bytes = digest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    public static String calculateStringMD5(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] bytes = digest.digest(input.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
