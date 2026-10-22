package com.sentinel.av.core.engine;

import com.sentinel.av.core.HashUtils;
import com.sentinel.av.core.MagicByteUtils;

import java.io.File;
import java.util.Locale;

/**
 * Snapshot of one file handed to every detection engine.
 *
 * <p>Values are computed lazily and memoised, and MD5 plus SHA-256 are produced from a
 * single read of the file. An archive-only scan therefore never pays for a full hash,
 * while hash-based detection no longer reads the payload twice.</p>
 */
public class FileContext {
    private final File file;
    private final long fileSize;
    private final String fileName;
    private final String fileNameLower;

    private volatile String[] hashes;
    private volatile MagicByteUtils.FileType magicFileType;
    private volatile boolean magicResolved;

    public FileContext(File file) {
        this.file = file;
        this.fileSize = file != null && file.isFile() ? file.length() : 0;
        this.fileName = file != null ? file.getName() : "";
        this.fileNameLower = fileName.toLowerCase(Locale.ROOT);
    }

    public File getFile() { return file; }
    public long getFileSize() { return fileSize; }
    public String getFileName() { return fileName; }
    public String getFileNameLower() { return fileNameLower; }

    public String getMd5() {
        return ensureHashes()[0];
    }

    public String getSha256() {
        return ensureHashes()[1];
    }

    private String[] ensureHashes() {
        String[] local = hashes;
        if (local == null) {
            synchronized (this) {
                local = hashes;
                if (local == null) {
                    local = file != null ? HashUtils.calculateMD5AndSha256(file) : new String[]{null, null};
                    hashes = local;
                }
            }
        }
        return local;
    }

    public MagicByteUtils.FileType getMagicFileType() {
        if (!magicResolved) {
            synchronized (this) {
                if (!magicResolved) {
                    magicFileType = file != null
                            ? MagicByteUtils.detectFileType(file)
                            : MagicByteUtils.FileType.UNKNOWN;
                    magicResolved = true;
                }
            }
        }
        return magicFileType;
    }

    public boolean isExecutable() {
        return MagicByteUtils.isExecutableType(getMagicFileType());
    }
}
