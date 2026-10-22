package com.sentinel.av.core.engine;

import com.sentinel.av.core.HashUtils;
import com.sentinel.av.core.MagicByteUtils;

import java.io.File;

public class FileContext {
    private final File file;
    private final long fileSize;
    private final String fileName;
    private final String md5;
    private final String sha256;
    private final MagicByteUtils.FileType magicFileType;

    public FileContext(File file) {
        this.file = file;
        this.fileSize = file != null && file.exists() ? file.length() : 0;
        this.fileName = file != null ? file.getName() : "";
        this.md5 = file != null ? HashUtils.calculateMD5(file) : null;
        this.sha256 = file != null ? HashUtils.calculateSHA256(file) : null;
        this.magicFileType = file != null ? MagicByteUtils.detectFileType(file) : MagicByteUtils.FileType.UNKNOWN;
    }

    public File getFile() { return file; }
    public long getFileSize() { return fileSize; }
    public String getFileName() { return fileName; }
    public String getMd5() { return md5; }
    public String getSha256() { return sha256; }
    public MagicByteUtils.FileType getMagicFileType() { return magicFileType; }
}
