package com.sentinel.av.ui;

import com.sentinel.av.core.QuarantineManager;
import com.sentinel.av.core.ScannerEngine;
import com.sentinel.av.model.ScanResult;
import com.sentinel.av.ui.components.CyberCard;
import com.sentinel.av.ui.components.StatusBadge;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

public class ScannerPanel extends JPanel implements ScannerEngine.ScanProgressListener {

    private final MainFrame mainFrame;
    private final ScannerEngine scannerEngine = new ScannerEngine();

    private JRadioButton quickScanRadio;
    private JRadioButton fullScanRadio;
    private JRadioButton customScanRadio;
    private JRadioButton processScanRadio;
    private JTextField customPathField;
    private JButton browseBtn;

    private JButton startScanBtn;
    private JButton cancelScanBtn;
    private JButton quarantineAllBtn;
    private JButton deleteAllBtn;

    private JProgressBar progressBar;
    private JLabel progressStatusLabel;
    private JLabel countLabel;
    private JLabel timerLabel;

    private DefaultTableModel threatsTableModel;
    private JTable threatsTable;
    private final List<ScanResult> currentThreats = new ArrayList<>();

    private SwingWorker<Void, Void> currentScanWorker;
    private long startTime;
    private Timer elapsedTimer;

    public ScannerPanel(MainFrame mainFrame) {
        this.mainFrame = mainFrame;
        setLayout(new BorderLayout(15, 15));
        setBackground(new Color(20, 23, 29));
        setBorder(new EmptyBorder(25, 25, 25, 25));

        initComponents();
    }

    private void initComponents() {
        // --- Top Selection Card ---
        CyberCard topCard = new CyberCard(new Color(50, 58, 72));

        JLabel titleLabel = new JLabel("🔍 Multi-Engine Malware Scanner");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        titleLabel.setForeground(Color.WHITE);

        JPanel scanTypePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 8));
        scanTypePanel.setOpaque(false);

        ButtonGroup scanGroup = new ButtonGroup();
        quickScanRadio = new JRadioButton("⚡ Quick Scan", true);
        fullScanRadio = new JRadioButton("🖥️ Deep Full Disk Scan");
        customScanRadio = new JRadioButton("📁 Custom Target");
        processScanRadio = new JRadioButton("⚙️ Process & Memory Scan");

        for (JRadioButton rb : new JRadioButton[]{quickScanRadio, fullScanRadio, customScanRadio, processScanRadio}) {
            rb.setOpaque(false);
            rb.setFont(new Font("Segoe UI", Font.BOLD, 12));
            rb.setForeground(new Color(210, 225, 245));
            scanGroup.add(rb);
            scanTypePanel.add(rb);
        }

        JPanel pathSelectionPanel = new JPanel(new BorderLayout(10, 0));
        pathSelectionPanel.setOpaque(false);

        customPathField = new JTextField(System.getProperty("user.home"));
        customPathField.setFont(new Font("Consolas", Font.PLAIN, 12));
        customPathField.setBackground(new Color(25, 28, 35));
        customPathField.setForeground(Color.WHITE);
        customPathField.setCaretColor(Color.WHITE);
        customPathField.setEnabled(false);

        browseBtn = new JButton("Browse...");
        browseBtn.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        browseBtn.setBackground(new Color(45, 52, 65));
        browseBtn.setForeground(Color.WHITE);
        browseBtn.setEnabled(false);
        browseBtn.addActionListener(e -> browsePath());

        pathSelectionPanel.add(customPathField, BorderLayout.CENTER);
        pathSelectionPanel.add(browseBtn, BorderLayout.EAST);

        quickScanRadio.addActionListener(e -> togglePathInput(false));
        fullScanRadio.addActionListener(e -> togglePathInput(false));
        processScanRadio.addActionListener(e -> togglePathInput(false));
        customScanRadio.addActionListener(e -> togglePathInput(true));

        JPanel configContainer = new JPanel(new BorderLayout(5, 5));
        configContainer.setOpaque(false);
        configContainer.add(scanTypePanel, BorderLayout.NORTH);
        configContainer.add(pathSelectionPanel, BorderLayout.CENTER);

        topCard.add(titleLabel, BorderLayout.NORTH);
        topCard.add(configContainer, BorderLayout.CENTER);

        // --- Progress Section Card ---
        CyberCard progressCard = new CyberCard(new Color(50, 58, 72));

        progressBar = new JProgressBar(0, 100);
        progressBar.setFont(new Font("Segoe UI", Font.BOLD, 12));
        progressBar.setStringPainted(true);
        progressBar.setPreferredSize(new Dimension(100, 24));
        progressBar.setForeground(new Color(16, 185, 129));

        progressStatusLabel = new JLabel("Engine Status: Ready to start malware scan.");
        progressStatusLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        progressStatusLabel.setForeground(new Color(170, 185, 205));

        countLabel = new JLabel("Files Scanned: 0");
        countLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        countLabel.setForeground(new Color(140, 200, 255));

        timerLabel = new JLabel("Elapsed Time: 00:00");
        timerLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        timerLabel.setForeground(new Color(170, 185, 205));

        JPanel statusBottom = new JPanel(new BorderLayout());
        statusBottom.setOpaque(false);
        statusBottom.add(progressStatusLabel, BorderLayout.CENTER);

        JPanel rightStats = new JPanel(new FlowLayout(FlowLayout.RIGHT, 15, 0));
        rightStats.setOpaque(false);
        rightStats.add(countLabel);
        rightStats.add(timerLabel);
        statusBottom.add(rightStats, BorderLayout.EAST);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 10));
        btnRow.setOpaque(false);

        startScanBtn = new JButton("▶ Start Malware Scan");
        startScanBtn.setFont(new Font("Segoe UI", Font.BOLD, 13));
        startScanBtn.setBackground(new Color(59, 130, 246));
        startScanBtn.setForeground(Color.WHITE);
        startScanBtn.setFocusPainted(false);
        startScanBtn.addActionListener(e -> startScan());

        cancelScanBtn = new JButton("⏹ Cancel Scan");
        cancelScanBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        cancelScanBtn.setBackground(new Color(239, 68, 68));
        cancelScanBtn.setForeground(Color.WHITE);
        cancelScanBtn.setEnabled(false);
        cancelScanBtn.addActionListener(e -> cancelScan());

        quarantineAllBtn = new JButton("🔒 Quarantine All Threats");
        quarantineAllBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        quarantineAllBtn.setBackground(new Color(168, 85, 247));
        quarantineAllBtn.setForeground(Color.WHITE);
        quarantineAllBtn.setEnabled(false);
        quarantineAllBtn.addActionListener(e -> quarantineAllThreats());

        deleteAllBtn = new JButton("🗑 Delete All Threats");
        deleteAllBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        deleteAllBtn.setBackground(new Color(185, 28, 28));
        deleteAllBtn.setForeground(Color.WHITE);
        deleteAllBtn.setEnabled(false);
        deleteAllBtn.addActionListener(e -> deleteAllThreats());

        btnRow.add(startScanBtn);
        btnRow.add(cancelScanBtn);
        btnRow.add(quarantineAllBtn);
        btnRow.add(deleteAllBtn);

        progressCard.add(progressBar, BorderLayout.NORTH);
        progressCard.add(statusBottom, BorderLayout.CENTER);
        progressCard.add(btnRow, BorderLayout.SOUTH);

        // --- Center Results Table Card ---
        CyberCard tableCard = new CyberCard(new Color(50, 58, 72));

        JLabel tableTitle = new JLabel("🚨 Intercepted Malware Detections");
        tableTitle.setFont(new Font("Segoe UI", Font.BOLD, 15));
        tableTitle.setForeground(Color.WHITE);

        String[] cols = {"File Name", "Threat Name", "Severity", "Detection Engine", "Status", "Full Path"};
        threatsTableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };

        threatsTable = new JTable(threatsTableModel);
        threatsTable.setBackground(new Color(25, 29, 36));
        threatsTable.setForeground(Color.WHITE);
        threatsTable.setGridColor(new Color(45, 52, 65));
        threatsTable.setRowHeight(28);
        threatsTable.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        threatsTable.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 12));
        threatsTable.getTableHeader().setBackground(new Color(38, 44, 54));
        threatsTable.getTableHeader().setForeground(new Color(200, 215, 235));

        // Severity renderer
        threatsTable.getColumnModel().getColumn(2).setCellRenderer((table, value, isSelected, hasFocus, row, column) -> {
            if (value != null) {
                return StatusBadge.createSeverityBadge(value.toString());
            }
            return new JLabel("");
        });

        // Status renderer
        threatsTable.getColumnModel().getColumn(4).setCellRenderer((table, value, isSelected, hasFocus, row, column) -> {
            if (value != null) {
                return StatusBadge.createStatusBadge(value.toString());
            }
            return new JLabel("");
        });

        JScrollPane scrollPane = new JScrollPane(threatsTable);
        scrollPane.setBorder(BorderFactory.createLineBorder(new Color(45, 52, 65)));

        tableCard.add(tableTitle, BorderLayout.NORTH);
        tableCard.add(scrollPane, BorderLayout.CENTER);

        // Layout Top Container
        JPanel topContainer = new JPanel(new BorderLayout(10, 10));
        topContainer.setOpaque(false);
        topContainer.add(topCard, BorderLayout.NORTH);
        topContainer.add(progressCard, BorderLayout.SOUTH);

        add(topContainer, BorderLayout.NORTH);
        add(tableCard, BorderLayout.CENTER);
    }

    private void togglePathInput(boolean enable) {
        customPathField.setEnabled(enable);
        browseBtn.setEnabled(enable);
    }

    private void browsePath() {
        JFileChooser chooser = new JFileChooser(customPathField.getText());
        chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
        int res = chooser.showOpenDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            customPathField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    public void setScanTargetAndStart(File target) {
        customScanRadio.setSelected(true);
        togglePathInput(true);
        customPathField.setText(target.getAbsolutePath());
        startScan();
    }

    public void startScan() {
        ScannerEngine.ScanMode mode;
        File target = null;

        if (quickScanRadio.isSelected()) {
            mode = ScannerEngine.ScanMode.QUICK_SCAN;
        } else if (fullScanRadio.isSelected()) {
            mode = ScannerEngine.ScanMode.FULL_SYSTEM_SCAN;
            target = new File(System.getProperty("user.home"));
        } else if (processScanRadio.isSelected()) {
            mode = ScannerEngine.ScanMode.PROCESS_MEMORY_SCAN;
            target = new File(System.getProperty("java.io.tmpdir"));
        } else {
            mode = ScannerEngine.ScanMode.CUSTOM_PATH_SCAN;
            String path = customPathField.getText().trim();
            if (path.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Please select a valid path to scan.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            target = new File(path);
        }

        // Reset UI
        threatsTableModel.setRowCount(0);
        currentThreats.clear();
        progressBar.setIndeterminate(true);
        progressStatusLabel.setText("Initializing scanner engine & YARA definitions...");
        countLabel.setText("Files Scanned: 0");
        startScanBtn.setEnabled(false);
        cancelScanBtn.setEnabled(true);
        quarantineAllBtn.setEnabled(false);
        deleteAllBtn.setEnabled(false);

        startTime = System.currentTimeMillis();
        elapsedTimer = new Timer(1000, e -> {
            long elapsedSeconds = (System.currentTimeMillis() - startTime) / 1000;
            long mins = elapsedSeconds / 60;
            long secs = elapsedSeconds % 60;
            timerLabel.setText(String.format("Elapsed Time: %02d:%02d", mins, secs));
        });
        elapsedTimer.start();

        final File scanTarget = target;
        currentScanWorker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                scannerEngine.scanPathWithMode(scanTarget, mode, ScannerPanel.this);
                return null;
            }
        };
        currentScanWorker.execute();
    }

    private void cancelScan() {
        if (scannerEngine.isScanning()) {
            scannerEngine.cancelScan();
            progressStatusLabel.setText("Cancelling active scan...");
        }
    }

    @Override
    public void onProgress(File currentFile, int scannedCount, long totalBytes, String currentPath) {
        SwingUtilities.invokeLater(() -> {
            progressBar.setIndeterminate(false);
            progressBar.setValue(scannedCount % 100);
            progressStatusLabel.setText("Scanning: " + currentFile.getName());
            countLabel.setText("Files Scanned: " + scannedCount);
        });
    }

    @Override
    public void onThreatDetected(ScanResult result) {
        SwingUtilities.invokeLater(() -> {
            currentThreats.add(result);
            threatsTableModel.addRow(new Object[]{
                result.getFileName(),
                result.getThreatName(),
                result.getSeverity() != null ? result.getSeverity().name() : "HIGH",
                result.getDetectionMethod(),
                result.getStatus().name(),
                result.getFilePath()
            });
            quarantineAllBtn.setEnabled(true);
            deleteAllBtn.setEnabled(true);
        });
    }

    @Override
    public void onScanComplete(List<ScanResult> allResults, List<ScanResult> threats, long durationMs) {
        SwingUtilities.invokeLater(() -> {
            if (elapsedTimer != null) elapsedTimer.stop();
            progressBar.setIndeterminate(false);
            progressBar.setValue(100);

            startScanBtn.setEnabled(true);
            cancelScanBtn.setEnabled(false);

            if (threats.isEmpty()) {
                progressStatusLabel.setText("Scan Finished. No threats found! System is clean.");
                JOptionPane.showMessageDialog(this, 
                    "Scan completed successfully!\nFiles scanned: " + allResults.size() + "\nNo threats detected.",
                    "Scan Complete", JOptionPane.INFORMATION_MESSAGE);
            } else {
                progressStatusLabel.setText("Scan Finished. ⚠️ THREATS DETECTED: " + threats.size());
                JOptionPane.showMessageDialog(this,
                    "⚠️ Scan completed with warnings!\nThreats detected: " + threats.size() + 
                    "\n\nPlease click 'Quarantine All' to safely isolate infected files.",
                    "Threats Detected!", JOptionPane.WARNING_MESSAGE);
            }

            mainFrame.updateDashboardStats();
        });
    }

    private void quarantineAllThreats() {
        int count = 0;
        for (ScanResult res : new ArrayList<>(currentThreats)) {
            if (res.getStatus() == ScanResult.ThreatStatus.INFECTED) {
                if (QuarantineManager.getInstance().quarantineFile(res)) {
                    count++;
                }
            }
        }

        for (int i = 0; i < threatsTableModel.getRowCount(); i++) {
            threatsTableModel.setValueAt("QUARANTINED", i, 4);
        }

        JOptionPane.showMessageDialog(this, count + " threat files isolated into Quarantine Vault.", "Quarantine Success", JOptionPane.INFORMATION_MESSAGE);
        quarantineAllBtn.setEnabled(false);
        deleteAllBtn.setEnabled(false);
        mainFrame.updateDashboardStats();
    }

    private void deleteAllThreats() {
        int confirm = JOptionPane.showConfirmDialog(this,
            "Are you sure you want to PERMANENTLY DELETE all detected threat files?",
            "Confirm Delete", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);

        if (confirm == JOptionPane.YES_OPTION) {
            int count = 0;
            for (ScanResult res : new ArrayList<>(currentThreats)) {
                if (res.getFile() != null && res.getFile().exists()) {
                    try {
                        Files.delete(res.getFile().toPath());
                        res.setStatus(ScanResult.ThreatStatus.DELETED);
                        count++;
                    } catch (Exception ignored) {}
                }
            }

            for (int i = 0; i < threatsTableModel.getRowCount(); i++) {
                threatsTableModel.setValueAt("DELETED", i, 4);
            }

            JOptionPane.showMessageDialog(this, count + " threat files permanently deleted.", "Delete Success", JOptionPane.INFORMATION_MESSAGE);
            quarantineAllBtn.setEnabled(false);
            deleteAllBtn.setEnabled(false);
            mainFrame.updateDashboardStats();
        }
    }
}
