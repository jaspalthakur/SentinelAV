package com.sentinel.av.core;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

public class MagicByteUtils {

    public enum FileType {
        WINDOWS_EXECUTABLE, // MZ
        ELF_EXECUTABLE,     // \x7F ELF
        ZIP_ARCHIVE,        // PK\x03\x04
        JPEG_IMAGE,         // \xFF\xD8\xFF
        PNG_IMAGE,          // \x89 PNG
        PDF_DOCUMENT,       // %PDF
        UNKNOWN
    }

    public static FileType detectFileType(File file) {
        if (file == null || !file.exists() || !file.isFile() || file.length() < 4) {
            return FileType.UNKNOWN;
        }

        byte[] header = new byte[8];
        try (InputStream is = new FileInputStream(file)) {
            int read = is.read(header);
            if (read < 4) return FileType.UNKNOWN;

            // Windows PE Executable (MZ)
            if (header[0] == 'M' && header[1] == 'Z') {
                return FileType.WINDOWS_EXECUTABLE;
            }

            // Linux ELF Executable (\x7F ELF)
            if (header[0] == 0x7F && header[1] == 'E' && header[2] == 'L' && header[3] == 'F') {
                return FileType.ELF_EXECUTABLE;
            }

            // ZIP / Office OpenXML (PK\x03\x04)
            if (header[0] == 0x50 && header[1] == 0x4B && header[2] == 0x03 && header[3] == 0x04) {
                return FileType.ZIP_ARCHIVE;
            }

            // PDF Document (%PDF)
            if (header[0] == '%' && header[1] == 'P' && header[2] == 'D' && header[3] == 'F') {
                return FileType.PDF_DOCUMENT;
            }

            // JPEG Image (\xFF\xD8\xFF)
            if ((header[0] & 0xFF) == 0xFF && (header[1] & 0xFF) == 0xD8 && (header[2] & 0xFF) == 0xFF) {
                return FileType.JPEG_IMAGE;
            }

            // PNG Image (\x89 PNG)
            if ((header[0] & 0xFF) == 0x89 && header[1] == 'P' && header[2] == 'N' && header[3] == 'G') {
                return FileType.PNG_IMAGE;
            }

        } catch (Exception ignored) {}

        return FileType.UNKNOWN;
    }

    public static boolean isExecutableType(FileType type) {
        return type == FileType.WINDOWS_EXECUTABLE || type == FileType.ELF_EXECUTABLE;
    }

    public static boolean isLegitimateCompressedFormat(FileType type) {
        return type == FileType.ZIP_ARCHIVE || type == FileType.JPEG_IMAGE || type == FileType.PNG_IMAGE;
    }
}
