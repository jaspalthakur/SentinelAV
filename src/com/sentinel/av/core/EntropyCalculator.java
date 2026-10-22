package com.sentinel.av.core;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;

public final class EntropyCalculator {

    public static class EntropyAnalysisResult {
        private final double overallEntropy;
        private final double maxBlockEntropy;
        private final boolean isHighEntropy;

        public EntropyAnalysisResult(double overallEntropy, double maxBlockEntropy, boolean isHighEntropy) {
            this.overallEntropy = overallEntropy;
            this.maxBlockEntropy = maxBlockEntropy;
            this.isHighEntropy = isHighEntropy;
        }

        public double getOverallEntropy() { return overallEntropy; }
        public double getMaxBlockEntropy() { return maxBlockEntropy; }
        public boolean isHighEntropy() { return isHighEntropy; }
    }

    private static final int BLOCK_SIZE = 8192;
    private static final int MAX_SAMPLED_BLOCKS = 32;

    private EntropyCalculator() {
    }

    /**
     * Calculates block-wise Shannon entropy (8 KiB blocks) and flags packed or encrypted
     * payloads. Legitimate compressed media (ZIP/JPEG/PNG) is never flagged.
     */
    public static EntropyAnalysisResult analyzeEntropy(File file) {
        if (file == null || !file.isFile() || file.length() < 1024) {
            return new EntropyAnalysisResult(0.0, 0.0, false);
        }
        return analyzeEntropy(file, MagicByteUtils.detectFileType(file));
    }

    /** Variant that reuses a magic-byte type already detected by the caller. */
    public static EntropyAnalysisResult analyzeEntropy(File file, MagicByteUtils.FileType fileType) {
        if (file == null || !file.isFile() || file.length() < 1024) {
            return new EntropyAnalysisResult(0.0, 0.0, false);
        }

        if (MagicByteUtils.isLegitimateCompressedFormat(fileType)) {
            double overall = calculateBlockEntropy(file, BLOCK_SIZE, 1)[0];
            return new EntropyAnalysisResult(overall, overall, false);
        }

        double[] blockEntropies = calculateBlockEntropy(file, BLOCK_SIZE, MAX_SAMPLED_BLOCKS);
        double overall = blockEntropies[0];
        double maxBlock = 0.0;
        for (double b : blockEntropies) {
            if (b > maxBlock) {
                maxBlock = b;
            }
        }

        boolean isHigh = maxBlock >= 7.80 || overall >= 7.65;
        return new EntropyAnalysisResult(overall, maxBlock, isHigh);
    }

    private static double[] calculateBlockEntropy(File file, int blockSize, int maxBlocksToSample) {
        double[] results = new double[maxBlocksToSample + 1];
        int[] totalFrequency = new int[256];
        long totalBytesRead = 0;

        java.io.InputStream in = null;
        try {
            in = new java.io.BufferedInputStream(Files.newInputStream(file.toPath()));
            byte[] buffer = new byte[blockSize];
            int blockIndex = 1;
            int bytesRead;

            while (blockIndex <= maxBlocksToSample && (bytesRead = in.read(buffer)) != -1) {
                int[] blockFrequency = new int[256];
                for (int i = 0; i < bytesRead; i++) {
                    int b = buffer[i] & 0xFF;
                    blockFrequency[b]++;
                    totalFrequency[b]++;
                }
                totalBytesRead += bytesRead;
                results[blockIndex] = calculateShannon(blockFrequency, bytesRead);
                blockIndex++;
            }
            results[0] = calculateShannon(totalFrequency, totalBytesRead);
        } catch (Exception e) {
            return new double[]{0.0};
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Exception ignored) {
                    // closing a read-only stream cannot fail in a recoverable way
                }
            }
        }
        return results;
    }

    private static double calculateShannon(int[] frequency, long totalBytes) {
        if (totalBytes == 0) {
            return 0.0;
        }
        double entropy = 0.0;
        for (int count : frequency) {
            if (count > 0) {
                double prob = (double) count / totalBytes;
                entropy -= prob * (Math.log(prob) / Math.log(2));
            }
        }
        return Math.round(entropy * 100.0) / 100.0;
    }
}
