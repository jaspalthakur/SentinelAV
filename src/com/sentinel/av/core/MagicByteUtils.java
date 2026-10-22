package com.sentinel.av.core;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

public final class MagicByteUtils {

    public enum FileType {
        WINDOWS_EXECUTABLE, // MZ
        ELF_EXECUTABLE,     // \x7F ELF
        ZIP_ARCHIVE,        // PK\x03\x04
        JPEG_IMAGE,         // \xFF\xD8\xFF
        PNG_IMAGE,          // \x89 PNG
        PDF_DOCUMENT,       // %PDF
        UNKNOWN
    }

    private static final int HEADER_BYTES = 8;

    private MagicByteUtils() {
    }

    public static FileType detectFileType(java.io.File file) {
        if (file == null || !file.isFile() || !file.canRead()) {
            return FileType.UNKNOWN;
        }
        try {
            return detectFileType(file.toPath());
        } catch (Exception ignored) {
            return FileType.UNKNOWN;
        }
    }

    public static FileType detectFileType(Path path) {
        if (path == null) {
            return FileType.UNKNOWN;
        }
        byte[] header = new byte[HEADER_BYTES];
        int read;
        try (InputStream is = Files.newInputStream(path)) {
            read = is.readNBytes(header, 0, HEADER_BYTES);
        } catch (Exception e) {
            return FileType.UNKNOWN;
        }
        return classify(header, read);
    }

    /**
     * Classifies an already-read header. Exposed so stream-based engines can reuse
     * bytes they have buffered instead of reopening the file.
     */
    public static FileType classify(byte[] header, int read) {
        if (header == null || read < 2) {
            return FileType.UNKNOWN;
        }

        // Windows PE executable: 'MZ'
        if (header[0] == 'M' && header[1] == 'Z') {
            return FileType.WINDOWS_EXECUTABLE;
        }
        if (read >= 4) {
            // Linux ELF: \x7F 'E' 'L' 'F'
            if (header[0] == 0x7F && header[1] == 'E' && header[2] == 'L' && header[3] == 'F') {
                return FileType.ELF_EXECUTABLE;
            }
            // ZIP / Office OpenXML: 'P' 'K' \x03 \x04
            if (header[0] == 0x50 && header[1] == 0x4B && header[2] == 0x03 && header[3] == 0x04) {
                return FileType.ZIP_ARCHIVE;
            }
            // PDF: '%' 'P' 'D' 'F'
            if (header[0] == '%' && header[1] == 'P' && header[2] == 'D' && header[3] == 'F') {
                return FileType.PDF_DOCUMENT;
            }
        }
        if (read >= 3) {
            // JPEG: \xFF \xD8 \xFF
            if ((header[0] & 0xFF) == 0xFF && (header[1] & 0xFF) == 0xD8 && (header[2] & 0xFF) == 0xFF) {
                return FileType.JPEG_IMAGE;
            }
        }
        if (read >= 4) {
            // PNG: \x89 'P' 'N' 'G'
            if ((header[0] & 0xFF) == 0x89 && header[1] == 'P' && header[2] == 'N' && header[3] == 'G') {
                return FileType.PNG_IMAGE;
            }
        }
        return FileType.UNKNOWN;
    }

    public static boolean isExecutableType(FileType type) {
        return type == FileType.WINDOWS_EXECUTABLE || type == FileType.ELF_EXECUTABLE;
    }

    public static boolean isLegitimateCompressedFormat(FileType type) {
        return type == FileType.ZIP_ARCHIVE || type == FileType.JPEG_IMAGE || type == FileType.PNG_IMAGE;
    }
}
