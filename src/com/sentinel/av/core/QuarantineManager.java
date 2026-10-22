package com.sentinel.av.core;

import com.sentinel.av.model.QuarantineItem;
import com.sentinel.av.model.ScanResult;
import com.sentinel.av.model.VirusSignature;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

public class QuarantineManager {
    private static QuarantineManager instance;

    private final Path quarantineDir = Paths.get(System.getProperty("user.home"), ".sentinel_av", "quarantine");
    private final Path metadataPath = quarantineDir.resolve("quarantine_meta.db");
    private final List<QuarantineItem> items = new CopyOnWriteArrayList<>();

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH_BYTES = 12;

    private QuarantineManager() {
        try {
            Files.createDirectories(quarantineDir);
            loadMetadata();
        } catch (IOException e) {
            System.err.println("Failed to create quarantine directory: " + e.getMessage());
        }
    }

    public static synchronized QuarantineManager getInstance() {
        if (instance == null) {
            instance = new QuarantineManager();
        }
        return instance;
    }

    public boolean quarantineFile(ScanResult result) {
        if (result == null || result.getFile() == null || !result.getFile().exists()) {
            return false;
        }

        File sourceFile = result.getFile();
        String id = UUID.randomUUID().toString();
        Path targetPath = quarantineDir.resolve(id + ".sentinel_locked_vault");

        try {
            // Generate AES-256 Secret Key & IV per file
            byte[] aesKey = generateAESKey();
            byte[] iv = generateIV();

            // Encrypt using AES-256-GCM
            encryptAESGCM(sourceFile.toPath(), targetPath, aesKey, iv);

            // Delete original file safely
            Files.delete(sourceFile.toPath());

            String keyBase64 = Base64.getEncoder().encodeToString(aesKey);
            String ivBase64 = Base64.getEncoder().encodeToString(iv);

            QuarantineItem item = new QuarantineItem(
                id,
                sourceFile.getAbsolutePath(),
                targetPath.toAbsolutePath().toString(),
                sourceFile.getName(),
                result.getThreatName(),
                result.getSeverity() != null ? result.getSeverity() : VirusSignature.Severity.HIGH,
                result.getFileSize(),
                keyBase64,
                ivBase64,
                result.getRiskScore(),
                result.getReasons()
            );

            items.add(item);
            saveMetadata();

            ActivityLogger.getInstance().quarantine("QuarantineManager", 
                "AES-256 Quarantined: " + sourceFile.getName() + " -> Vault ID: " + id);

            result.setStatus(ScanResult.ThreatStatus.QUARANTINED);
            return true;

        } catch (Exception e) {
            ActivityLogger.getInstance().warning("QuarantineManager", 
                "Failed to quarantine file " + sourceFile.getName() + ": " + e.getMessage());
            return false;
        }
    }

    public boolean restoreFile(QuarantineItem item) {
        if (item == null) return false;

        Path lockedPath = Paths.get(item.getQuarantinedPath());
        Path originalPath = Paths.get(item.getOriginalPath());

        if (!Files.exists(lockedPath)) {
            ActivityLogger.getInstance().warning("QuarantineManager", "Quarantined vault file not found on disk: " + lockedPath);
            return false;
        }

        try {
            if (originalPath.getParent() != null) {
                Files.createDirectories(originalPath.getParent());
            }

            byte[] aesKey = Base64.getDecoder().decode(item.getAesKeyBase64());
            byte[] iv = Base64.getDecoder().decode(item.getIvBase64());

            // Decrypt AES-256-GCM
            decryptAESGCM(lockedPath, originalPath, aesKey, iv);

            // Delete locked vault file
            Files.delete(lockedPath);

            items.remove(item);
            saveMetadata();

            ActivityLogger.getInstance().info("QuarantineManager", 
                "Restored file: " + item.getFileName() + " back to " + item.getOriginalPath());
            return true;

        } catch (Exception e) {
            ActivityLogger.getInstance().warning("QuarantineManager", 
                "Failed to restore file " + item.getFileName() + ": " + e.getMessage());
            return false;
        }
    }

    public boolean deletePermanently(QuarantineItem item) {
        if (item == null) return false;

        Path lockedPath = Paths.get(item.getQuarantinedPath());
        try {
            if (Files.exists(lockedPath)) {
                Files.delete(lockedPath);
            }
            items.remove(item);
            saveMetadata();

            ActivityLogger.getInstance().info("QuarantineManager", 
                "Permanently deleted quarantined item: " + item.getFileName());
            return true;

        } catch (Exception e) {
            ActivityLogger.getInstance().warning("QuarantineManager", 
                "Failed to delete item " + item.getFileName() + ": " + e.getMessage());
            return false;
        }
    }

    public List<QuarantineItem> getItems() {
        return Collections.unmodifiableList(items);
    }

    public int getQuarantineCount() {
        return items.size();
    }

    private byte[] generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        return secretKey.getEncoded();
    }

    private byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH_BYTES];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private void encryptAESGCM(Path source, Path destination, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

        byte[] inputData = Files.readAllBytes(source);
        byte[] encryptedData = cipher.doFinal(inputData);
        Files.write(destination, encryptedData);
    }

    private void decryptAESGCM(Path source, Path destination, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

        byte[] encryptedData = Files.readAllBytes(source);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        Files.write(destination, decryptedData);
    }

    private synchronized void saveMetadata() {
        try (ObjectOutputStream oos = new ObjectOutputStream(Files.newOutputStream(metadataPath))) {
            oos.writeObject(new ArrayList<>(items));
        } catch (Exception e) {
            System.err.println("Failed to save quarantine metadata: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private synchronized void loadMetadata() {
        if (!Files.exists(metadataPath)) return;
        try (ObjectInputStream ois = new ObjectInputStream(Files.newInputStream(metadataPath))) {
            List<QuarantineItem> loaded = (List<QuarantineItem>) ois.readObject();
            items.clear();
            items.addAll(loaded);
        } catch (Exception e) {
            System.err.println("Failed to load quarantine metadata: " + e.getMessage());
        }
    }
}
