package com.sentinel.av.core;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

public class EntropyCalculator {

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

    /**
     * Calculates Block-Wise Shannon Entropy (8KB block size).
     * Prevents false positives on compressed media (ZIP, JPEG, MP4).
     */
    public static EntropyAnalysisResult analyzeEntropy(File file) {
        if (file == null || !file.exists() || !file.isFile() || file.length() < 1024) {
            return new EntropyAnalysisResult(0.0, 0.0, false);
        }

        MagicByteUtils.FileType fileType = MagicByteUtils.detectFileType(file);

        // Do not flag high entropy for legitimate compressed media formats (ZIP, JPEG, PNG)
        if (MagicByteUtils.isLegitimateCompressedFormat(fileType)) {
            double overall = calculateBlockEntropy(file, 8192, 1)[0];
            return new EntropyAnalysisResult(overall, overall, false);
        }

        double[] blockEntropies = calculateBlockEntropy(file, 8192, 32); // Sample up to 32 blocks
        double overall = blockEntropies[0];
        double maxBlock = 0.0;

        for (double b : blockEntropies) {
            if (b > maxBlock) maxBlock = b;
        }

        // Only flag high entropy for executables or uncompressed scripts/docs
        boolean isHigh = (maxBlock >= 7.80 || overall >= 7.65);
        return new EntropyAnalysisResult(overall, maxBlock, isHigh);
    }

    private static double[] calculateBlockEntropy(File file, int blockSize, int maxBlocksToSample) {
        double[] results = new double[maxBlocksToSample + 1];
        long fileSize = file.length();

        int[] totalFrequency = new int[256];
        long totalBytesRead = 0;

        try (InputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[blockSize];
            int blockIndex = 1;
            int bytesRead;

            while ((bytesRead = fis.read(buffer)) != -1 && blockIndex <= maxBlocksToSample) {
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
        }

        return results;
    }

    private static double calculateShannon(int[] frequency, long totalBytes) {
        if (totalBytes == 0) return 0.0;
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
