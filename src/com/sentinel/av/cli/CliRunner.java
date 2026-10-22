package com.sentinel.av.cli;

import com.sentinel.av.TestRunner;
import com.sentinel.av.Version;
import com.sentinel.av.core.QuarantineManager;
import com.sentinel.av.core.ScannerEngine;
import com.sentinel.av.model.ScanResult;

import java.io.File;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Headless command line interface, so SentinelAV can be scripted and run in CI where no
 * display is available.
 *
 * <pre>
 *   java -jar SentinelAV.jar --scan &lt;path&gt; [--json] [--quarantine]
 *   java -jar SentinelAV.jar --selftest
 *   java -jar SentinelAV.jar --version | --help
 * </pre>
 *
 * Exit codes: {@code 0} clean, {@code 1} threats found or self-test failed,
 * {@code 2} usage error.
 */
public final class CliRunner {

    public static final int EXIT_CLEAN = 0;
    public static final int EXIT_THREATS_FOUND = 1;
    public static final int EXIT_USAGE = 2;

    private static final PrintStream OUT = System.out;
    private static final PrintStream ERR = System.err;

    private CliRunner() {
    }

    public static int run(String[] args) {
        if (args == null || args.length == 0) {
            printUsage(ERR);
            return EXIT_USAGE;
        }

        String target = null;
        boolean json = false;
        boolean quarantine = false;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg.toLowerCase(Locale.ROOT)) {
                case "--help", "-h", "/?" -> {
                    printUsage(OUT);
                    return EXIT_CLEAN;
                }
                case "--version", "-v" -> {
                    OUT.println(Version.display());
                    return EXIT_CLEAN;
                }
                case "--selftest", "--self-test" -> {
                    return TestRunner.run();
                }
                case "--json" -> json = true;
                case "--quarantine", "-q" -> quarantine = true;
                case "--scan", "-s" -> {
                    if (i + 1 >= args.length) {
                        ERR.println("error: --scan requires a path argument");
                        return EXIT_USAGE;
                    }
                    target = args[++i];
                }
                default -> {
                    if (arg.startsWith("-")) {
                        ERR.println("error: unknown option '" + arg + "'");
                        printUsage(ERR);
                        return EXIT_USAGE;
                    }
                    if (target == null) {
                        target = arg;
                    } else {
                        ERR.println("error: more than one scan target supplied");
                        return EXIT_USAGE;
                    }
                }
            }
        }

        if (target == null) {
            ERR.println("error: nothing to scan (use --scan <path>)");
            printUsage(ERR);
            return EXIT_USAGE;
        }

        File file = new File(target);
        if (!file.exists()) {
            ERR.println("error: path does not exist: " + target);
            return EXIT_USAGE;
        }

        return scan(file, json, quarantine);
    }

    private static int scan(File target, boolean json, boolean quarantine) {
        ScannerEngine engine = new ScannerEngine();
        List<ScanResult> allResults = new ArrayList<>();

        ScannerEngine.ScanProgressListener listener = new ScannerEngine.ScanProgressListener() {
            @Override
            public void onProgress(File currentFile, int scannedCount, long totalBytes, String currentPath) {
                if (!json && scannedCount % 250 == 0) {
                    ERR.println("  ... scanned " + scannedCount + " files");
                }
            }

            @Override
            public void onThreatDetected(ScanResult result) {
                // Reported once the scan finishes, in discovery order.
            }

            @Override
            public void onScanComplete(List<ScanResult> results, List<ScanResult> threats, long durationMs) {
                allResults.addAll(results);
            }
        };

        long started = System.currentTimeMillis();
        List<ScanResult> threats = engine.scanPathWithMode(target,
                ScannerEngine.ScanMode.CUSTOM_PATH_SCAN, listener);
        long duration = System.currentTimeMillis() - started;

        int quarantined = 0;
        if (quarantine && !threats.isEmpty()) {
            QuarantineManager manager = QuarantineManager.getInstance();
            for (ScanResult result : threats) {
                if (manager.quarantineFile(result)) {
                    quarantined++;
                }
            }
        }

        if (json) {
            printJson(target, allResults, threats, duration, quarantined);
        } else {
            printText(target, allResults, threats, duration, quarantined);
        }
        return threats.isEmpty() ? EXIT_CLEAN : EXIT_THREATS_FOUND;
    }

    private static void printText(File target, List<ScanResult> results, List<ScanResult> threats,
                                  long durationMs, int quarantined) {
        OUT.println(Version.display());
        OUT.println("Target : " + target.getAbsolutePath());
        OUT.println("Scanned: " + results.size() + " files in " + formatDuration(durationMs));
        OUT.println();

        if (threats.isEmpty()) {
            OUT.println("No threats detected.");
            return;
        }

        for (ScanResult threat : threats) {
            OUT.printf("[%-8s %3d/100] %s%n", threat.getSeverity(), threat.getRiskScore(), threat.getFilePath());
            OUT.println("                  threat : " + threat.getThreatName());
            OUT.println("                  method : " + threat.getDetectionMethod());
            if (!threat.getAttackTechniques().isEmpty()) {
                OUT.println("                  ATT&CK : " + String.join(", ", threat.getAttackTechniques()));
            }
            if (threat.getMatchedHash() != null) {
                OUT.println("                  sha256 : " + threat.getMatchedHash());
            }
        }

        OUT.println();
        OUT.println("Threats found: " + threats.size()
                + (quarantined > 0 ? " (" + quarantined + " quarantined)" : ""));
    }

    private static void printJson(File target, List<ScanResult> results, List<ScanResult> threats,
                                  long durationMs, int quarantined) {
        StringBuilder sb = new StringBuilder(256 + threats.size() * 256);
        sb.append('{');
        sb.append("\"version\":").append(quote(Version.VERSION)).append(',');
        sb.append("\"target\":").append(quote(target.getAbsolutePath())).append(',');
        sb.append("\"scannedFiles\":").append(results.size()).append(',');
        sb.append("\"durationMs\":").append(durationMs).append(',');
        sb.append("\"quarantined\":").append(quarantined).append(',');
        sb.append("\"threats\":[");
        for (int i = 0; i < threats.size(); i++) {
            ScanResult threat = threats.get(i);
            if (i > 0) {
                sb.append(',');
            }
            sb.append('{')
                    .append("\"path\":").append(quote(threat.getFilePath())).append(',')
                    .append("\"threat\":").append(quote(threat.getThreatName())).append(',')
                    .append("\"severity\":").append(quote(threat.getSeverity().name())).append(',')
                    .append("\"score\":").append(threat.getRiskScore()).append(',')
                    .append("\"method\":").append(quote(threat.getDetectionMethod())).append(',')
                    .append("\"sha256\":").append(threat.getMatchedHash() != null
                            ? quote(threat.getMatchedHash()) : "null").append(',')
                    .append("\"status\":").append(quote(threat.getStatus().name())).append(',')
                    .append("\"attackTechniques\":[");
            List<String> techniques = threat.getAttackTechniques();
            for (int t = 0; t < techniques.size(); t++) {
                if (t > 0) {
                    sb.append(',');
                }
                sb.append(quote(techniques.get(t)));
            }
            sb.append("],\"reasons\":[");
            List<String> reasons = threat.getReasons();
            for (int r = 0; r < reasons.size(); r++) {
                if (r > 0) {
                    sb.append(',');
                }
                sb.append(quote(reasons.get(r)));
            }
            sb.append("]}");
        }
        sb.append("]}");
        OUT.println(sb);
    }

    private static String formatDuration(long millis) {
        if (millis < 1000) {
            return millis + " ms";
        }
        return String.format(Locale.ROOT, "%.2f s", millis / 1000.0);
    }

    private static String quote(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(value.length() + 16).append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.append('"').toString();
    }

    private static void printUsage(PrintStream stream) {
        stream.println(Version.display());
        stream.println();
        stream.println("Usage:");
        stream.println("  java -jar SentinelAV.jar                     Launch the desktop GUI");
        stream.println("  java -jar SentinelAV.jar --scan <path>       Scan a file or directory");
        stream.println("  java -jar SentinelAV.jar --scan <path> --json         Machine-readable output");
        stream.println("  java -jar SentinelAV.jar --scan <path> --quarantine   Encrypt detections into the vault");
        stream.println("  java -jar SentinelAV.jar --selftest          Run the built-in detection test suite");
        stream.println("  java -jar SentinelAV.jar --version           Print the version");
        stream.println();
        stream.println("Exit codes: 0 clean, 1 threats found, 2 usage error.");
    }
}
