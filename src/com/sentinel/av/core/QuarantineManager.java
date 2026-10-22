package com.sentinel.av.core;

import com.sentinel.av.model.QuarantineItem;
import com.sentinel.av.model.ScanResult;
import com.sentinel.av.model.VirusSignature;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * AES-256-GCM encrypted quarantine vault.
 *
 * <p>Files are encrypted with streaming I/O (never {@code readAllBytes}), written to a
 * temporary vault file and only promoted once complete, so an interrupted quarantine
 * cannot destroy the original. Restores are authenticated by the GCM tag before the
 * plaintext touches the destination path.</p>
 */
public class QuarantineManager {
    private static QuarantineManager instance;

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int IV_LENGTH_BYTES = 12;
    private static final int IO_BUFFER = 64 * 1024;
    private static final String VAULT_SUFFIX = ".sentinel_locked_vault";

    private final Path quarantineDir = AppPaths.quarantineDir();
    private final Path metadataPath = quarantineDir.resolve("quarantine_meta.db");
    private final List<QuarantineItem> items = new CopyOnWriteArrayList<>();
    private final SecureRandom secureRandom = new SecureRandom();

    private QuarantineManager() {
        try {
            Files.createDirectories(quarantineDir);
            loadMetadata();
        } catch (Exception e) {
            System.err.println("Failed to create quarantine directory: " + e.getMessage());
        }
    }

    public static synchronized QuarantineManager getInstance() {
        if (instance == null) {
            instance = new QuarantineManager();
        }
        return instance;
    }

    public Path getQuarantineDir() {
        return quarantineDir;
    }

    public boolean quarantineFile(ScanResult result) {
        if (result == null || result.getFile() == null || !result.getFile().isFile()) {
            return false;
        }

        Path sourceFile = result.getFile().toPath().toAbsolutePath();
        String id = UUID.randomUUID().toString();
        Path vaultPath = quarantineDir.resolve(id + VAULT_SUFFIX);
        Path tempVault = quarantineDir.resolve(id + ".tmp");

        try {
            byte[] aesKey = generateAesKey();
            byte[] iv = generateIv();
            encryptAesGcm(sourceFile, tempVault, aesKey, iv);
            Files.move(tempVault, vaultPath, StandardCopyOption.REPLACE_EXISTING);

            try {
                Files.delete(sourceFile);
            } catch (Exception deleteFailure) {
                // Roll the vault back: leaving both copies would be worse than failing.
                Files.deleteIfExists(vaultPath);
                throw deleteFailure;
            }

            QuarantineItem item = new QuarantineItem(
                    id,
                    sourceFile.toString(),
                    vaultPath.toString(),
                    sourceFile.getFileName().toString(),
                    result.getThreatName(),
                    result.getSeverity() != null ? result.getSeverity() : VirusSignature.Severity.HIGH,
                    result.getFileSize(),
                    Base64.getEncoder().encodeToString(aesKey),
                    Base64.getEncoder().encodeToString(iv),
                    result.getRiskScore(),
                    result.getReasons()
            );

            items.add(item);
            saveMetadata();

            ActivityLogger.getInstance().quarantine("QuarantineManager",
                    "AES-256-GCM quarantined: " + item.getFileName() + " -> Vault ID: " + id);

            result.setStatus(ScanResult.ThreatStatus.QUARANTINED);
            return true;

        } catch (Exception e) {
            deleteQuietly(tempVault);
            ActivityLogger.getInstance().warning("QuarantineManager",
                    "Failed to quarantine " + sourceFile.getFileName() + ": " + e.getMessage());
            return false;
        }
    }

    public boolean restoreFile(QuarantineItem item) {
        if (item == null || item.getQuarantinedPath() == null || item.getOriginalPath() == null) {
            return false;
        }

        Path vaultPath = Path.of(item.getQuarantinedPath());
        Path originalPath = Path.of(item.getOriginalPath());

        if (!Files.isRegularFile(vaultPath)) {
            ActivityLogger.getInstance().warning("QuarantineManager",
                    "Quarantined vault file not found on disk: " + vaultPath);
            return false;
        }

        Path tempRestore = originalPath.resolveSibling(originalPath.getFileName() + ".sentinel_restore");
        try {
            if (originalPath.getParent() != null) {
                Files.createDirectories(originalPath.getParent());
            }

            byte[] aesKey = Base64.getDecoder().decode(item.getAesKeyBase64());
            byte[] iv = Base64.getDecoder().decode(item.getIvBase64());

            // GCM authenticates the payload; a tampered vault throws before any write.
            decryptAesGcm(vaultPath, tempRestore, aesKey, iv);
            Files.move(tempRestore, originalPath,
                    StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);

            Files.deleteIfExists(vaultPath);
            items.remove(item);
            saveMetadata();

            ActivityLogger.getInstance().info("QuarantineManager",
                    "Restored file: " + item.getFileName() + " back to " + item.getOriginalPath());
            return true;

        } catch (Exception e) {
            deleteQuietly(tempRestore);
            ActivityLogger.getInstance().warning("QuarantineManager",
                    "Failed to restore " + item.getFileName() + ": " + e.getMessage());
            return false;
        }
    }

    public boolean deletePermanently(QuarantineItem item) {
        if (item == null) {
            return false;
        }
        try {
            if (item.getQuarantinedPath() != null) {
                Files.deleteIfExists(Path.of(item.getQuarantinedPath()));
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

    private byte[] generateAesKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        return secretKey.getEncoded();
    }

    private byte[] generateIv() {
        byte[] iv = new byte[IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);
        return iv;
    }

    private void encryptAesGcm(Path source, Path destination, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

        try (InputStream in = new BufferedInputStream(Files.newInputStream(source), IO_BUFFER);
             OutputStream out = new BufferedOutputStream(Files.newOutputStream(destination), IO_BUFFER)) {
            byte[] buffer = new byte[IO_BUFFER];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(cipher.update(buffer, 0, read));
            }
            out.write(cipher.doFinal());
        }
    }

    private void decryptAesGcm(Path source, Path destination, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

        try (InputStream in = new BufferedInputStream(Files.newInputStream(source), IO_BUFFER);
             OutputStream out = new BufferedOutputStream(Files.newOutputStream(destination), IO_BUFFER)) {
            byte[] buffer = new byte[IO_BUFFER];
            int read;
            while ((read = in.read(buffer)) != -1) {
                byte[] chunk = cipher.update(buffer, 0, read);
                if (chunk != null) {
                    out.write(chunk);
                }
            }
            out.write(cipher.doFinal());
        }
    }

    private static void deleteQuietly(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (Exception ignored) {
            // Cleanup is best effort.
        }
    }

    private synchronized void saveMetadata() {
        try {
            Path tmp = metadataPath.resolveSibling(metadataPath.getFileName() + ".tmp");
            try (ObjectOutputStream oos = new ObjectOutputStream(Files.newOutputStream(tmp))) {
                oos.writeObject(new ArrayList<>(items));
            }
            Files.move(tmp, metadataPath, StandardCopyOption.REPLACE_EXISTING);
        } catch (Exception e) {
            System.err.println("Failed to save quarantine metadata: " + e.getMessage());
        }
    }

    private synchronized void loadMetadata() {
        if (!Files.exists(metadataPath)) {
            return;
        }
        try (ObjectInputStream ois = new ObjectInputStream(Files.newInputStream(metadataPath))) {
            Object read = ois.readObject();
            if (read instanceof List<?> loaded) {
                items.clear();
                for (Object entry : loaded) {
                    if (entry instanceof QuarantineItem item) {
                        items.add(item);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Failed to load quarantine metadata: " + e.getMessage());
        }
    }
}
