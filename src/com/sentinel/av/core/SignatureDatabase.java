package com.sentinel.av.core;

import com.sentinel.av.model.VirusSignature;
import com.sentinel.av.model.VirusSignature.Severity;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class SignatureDatabase {
    private static SignatureDatabase instance;

    private final Map<String, VirusSignature> md5Signatures = new ConcurrentHashMap<>();
    private final Map<String, VirusSignature> sha256Signatures = new ConcurrentHashMap<>();
    /** Keyed by signature id so re-loading the store cannot accumulate duplicates. */
    private final Map<String, VirusSignature> patternSignatures = new LinkedHashMap<>();
    /** Signatures added at runtime (or restored from disk); the only ones persisted. */
    private final List<VirusSignature> customSignatures = new ArrayList<>();

    private final Path storagePath = AppPaths.signatureFile();

    private SignatureDatabase() {
        loadDefaults();
        loadCustomSignatures();
    }

    public static synchronized SignatureDatabase getInstance() {
        if (instance == null) {
            instance = new SignatureDatabase();
        }
        return instance;
    }

    private void loadDefaults() {
        // EICAR Standard Antivirus Test File
        addSignatureInternal(new VirusSignature(
            "SIG-0001",
            "EICAR-Test-File",
            "131f95c51cc819465fa1797f6ccacad9",
            "MD5",
            Severity.HIGH,
            "Standard EICAR Antivirus Test File used to verify scanner detection logic."
        ));

        addSignatureInternal(new VirusSignature(
            "SIG-0002",
            "EICAR-Test-File-SHA256",
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "SHA-256",
            Severity.HIGH,
            "SHA-256 hash variant for EICAR standard test file."
        ));

        // Pattern signature for EICAR string
        addSignatureInternal(new VirusSignature(
            "SIG-0003",
            "EICAR-Pattern-Match",
            "EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
            Severity.HIGH,
            "Pattern string match for EICAR test header.",
            true
        ));

        // WannaCry Ransomware Sample Hashes
        addSignatureInternal(new VirusSignature(
            "SIG-0004",
            "Win32.WannaCry.Ransomware",
            "84c655a44f217f2fe3270f30e965b3b6",
            "MD5",
            Severity.CRITICAL,
            "WannaCry Ransomware variant payload launcher."
        ));

        addSignatureInternal(new VirusSignature(
            "SIG-0005",
            "Win32.WannaCry.Ransomware.SHA256",
            "24d3af82b8c191223910c4f8229495b54116418738f4e15f4001e0a9d0a60870",
            "SHA-256",
            Severity.CRITICAL,
            "WannaCry SHA256 executable payload signature."
        ));

        // Trojan.Agent / Keylogger Test Signature
        addSignatureInternal(new VirusSignature(
            "SIG-0006",
            "Trojan.GenericKeylogger.Sample",
            "44d88612fea8a8f36de82e1278abb02f",
            "MD5",
            Severity.HIGH,
            "Generic Keylogger & Credential Stealer sample definition."
        ));

        // Ransomware Extension Pattern / Header test
        addSignatureInternal(new VirusSignature(
            "SIG-0007",
            "Ransomware.Locky.HeaderPattern",
            "__LOCKED_BY_SENTINEL_RANSOMTEST__",
            Severity.CRITICAL,
            "Ransomware header pattern simulation.",
            true,
            "T1486"
        ));

        // Suspicious Powershell Dropper Pattern
        addSignatureInternal(new VirusSignature(
            "SIG-0008",
            "Script.Powershell.ObfuscatedDownloader",
            "Invoke-Expression (New-Object System.Net.WebClient).DownloadString",
            Severity.MEDIUM,
            "Suspicious PowerShell remote execution pattern.",
            true,
            "T1059.001"
        ));
    }

    private void addSignatureInternal(VirusSignature sig) {
        if (sig == null) {
            return;
        }
        if (sig.isPattern()) {
            patternSignatures.put(sig.getId(), sig);
        } else if ("MD5".equalsIgnoreCase(sig.getHashType()) && sig.getHash() != null) {
            md5Signatures.put(sig.getHash().toLowerCase(Locale.ROOT), sig);
        } else if ("SHA-256".equalsIgnoreCase(sig.getHashType()) && sig.getHash() != null) {
            sha256Signatures.put(sig.getHash().toLowerCase(Locale.ROOT), sig);
        }
    }

    public synchronized void addCustomSignature(VirusSignature sig) {
        if (sig == null) {
            return;
        }
        if (sig.getId() == null || sig.getId().isBlank()) {
            sig = new VirusSignature("CUSTOM-" + UUID.randomUUID(),
                    sig.getName(), sig.getHash() != null ? sig.getHash() : sig.getPattern(),
                    sig.getHashType(), sig.getSeverity(), sig.getDescription());
        }
        addSignatureInternal(sig);
        customSignatures.add(sig);
        saveCustomSignatures();
    }

    public VirusSignature findByMD5(String md5) {
        if (md5 == null) {
            return null;
        }
        return md5Signatures.get(md5.toLowerCase(Locale.ROOT));
    }

    public VirusSignature findBySHA256(String sha256) {
        if (sha256 == null) {
            return null;
        }
        return sha256Signatures.get(sha256.toLowerCase(Locale.ROOT));
    }

    public List<VirusSignature> getPatternSignatures() {
        synchronized (patternSignatures) {
            return List.copyOf(patternSignatures.values());
        }
    }

    public List<VirusSignature> getAllSignatures() {
        List<VirusSignature> all = new ArrayList<>();
        all.addAll(md5Signatures.values());
        all.addAll(sha256Signatures.values());
        all.addAll(getPatternSignatures());
        return Collections.unmodifiableList(all);
    }

    public int getSignatureCount() {
        return md5Signatures.size() + sha256Signatures.size() + patternSignatures.size();
    }

    private void saveCustomSignatures() {
        try {
            Path parent = storagePath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path tmp = storagePath.resolveSibling(storagePath.getFileName() + ".tmp");
            try (ObjectOutputStream oos = new ObjectOutputStream(Files.newOutputStream(tmp))) {
                oos.writeObject(new ArrayList<>(customSignatures));
            }
            Files.move(tmp, storagePath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } catch (Exception e) {
            // Signature persistence is best-effort; scanning continues regardless.
        }
    }

    @SuppressWarnings("unchecked")
    private void loadCustomSignatures() {
        if (!Files.exists(storagePath)) {
            return;
        }
        try (ObjectInputStream ois = new ObjectInputStream(Files.newInputStream(storagePath))) {
            Object read = ois.readObject();
            if (!(read instanceof List<?> list)) {
                return;
            }
            for (Object entry : list) {
                if (!(entry instanceof VirusSignature sig)) {
                    continue;
                }
                // Older builds persisted every default signature too; only keep custom ones.
                if (sig.getId() != null && sig.getId().startsWith("SIG-")) {
                    continue;
                }
                addSignatureInternal(sig);
                customSignatures.add(sig);
            }
        } catch (Exception e) {
            // Corrupt or incompatible store: fall back to built-in signatures only.
        }
    }
}
