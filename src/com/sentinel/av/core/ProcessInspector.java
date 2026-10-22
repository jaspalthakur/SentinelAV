package com.sentinel.av.core;

import com.sentinel.av.model.VirusSignature;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class ProcessInspector {

    public static class ProcessInfo {
        private final long pid;
        private final String name;
        private final String commandLine;
        private final String executablePath;
        private final VirusSignature.Severity riskLevel;
        private final String riskReason;

        public ProcessInfo(long pid, String name, String commandLine, String executablePath, VirusSignature.Severity riskLevel, String riskReason) {
            this.pid = pid;
            this.name = name;
            this.commandLine = commandLine != null ? commandLine : "N/A";
            this.executablePath = executablePath != null ? executablePath : "N/A";
            this.riskLevel = riskLevel;
            this.riskReason = riskReason;
        }

        public long getPid() { return pid; }
        public String getName() { return name; }
        public String getCommandLine() { return commandLine; }
        public String getExecutablePath() { return executablePath; }
        public VirusSignature.Severity getRiskLevel() { return riskLevel; }
        public String getRiskReason() { return riskReason; }
    }

    public static List<ProcessInfo> getRunningProcesses() {
        List<ProcessInfo> list = new ArrayList<>();

        ProcessHandle.allProcesses().forEach(ph -> {
            long pid = ph.pid();
            ProcessHandle.Info info = ph.info();
            Optional<String> commandOpt = info.command();
            Optional<String> commandLineOpt = info.commandLine();

            String exePath = commandOpt.orElse("System / Undisclosed");
            String cmdLine = commandLineOpt.orElse(exePath);
            String name = extractProcessName(exePath);

            // Risk Assessment
            VirusSignature.Severity risk = VirusSignature.Severity.LOW;
            String reason = "Normal process execution";

            String cmdLower = cmdLine.toLowerCase();
            String pathLower = exePath.toLowerCase();

            if (pathLower.contains("temp") || pathLower.contains("appdata\\local\\temp")) {
                risk = VirusSignature.Severity.HIGH;
                reason = "Process running from Temporary Directory";
            } else if (cmdLower.contains("powershell") && (cmdLower.contains("-enc") || cmdLower.contains("hidden"))) {
                risk = VirusSignature.Severity.CRITICAL;
                reason = "Hidden / Encoded PowerShell execution";
            } else if (cmdLower.contains("cmd.exe /c") && cmdLower.contains("bitsadmin")) {
                risk = VirusSignature.Severity.HIGH;
                reason = "BITSAdmin background transfer script";
            } else if (name.endsWith(".vbs") || name.endsWith(".scr")) {
                risk = VirusSignature.Severity.MEDIUM;
                reason = "Script or ScreenSaver executable process";
            }

            list.add(new ProcessInfo(pid, name, cmdLine, exePath, risk, reason));
        });

        return list;
    }

    public static boolean terminateProcess(long pid) {
        Optional<ProcessHandle> phOpt = ProcessHandle.of(pid);
        if (phOpt.isPresent()) {
            ProcessHandle ph = phOpt.get();
            return ph.destroyForcibly();
        }
        return false;
    }

    private static String extractProcessName(String path) {
        if (path == null || path.isEmpty() || path.equals("System / Undisclosed")) return "SystemProcess";
        int lastSlash = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
        if (lastSlash >= 0 && lastSlash < path.length() - 1) {
            return path.substring(lastSlash + 1);
        }
        return path;
    }
}
