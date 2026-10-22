package com.sentinel.av.ui;

import com.sentinel.av.core.ActivityLogger;
import com.sentinel.av.core.QuarantineManager;
import com.sentinel.av.core.RealTimeMonitor;
import com.sentinel.av.core.SignatureDatabase;
import com.sentinel.av.model.ActivityLog;
import com.sentinel.av.ui.components.AnalyticsChartPanel;
import com.sentinel.av.ui.components.CyberCard;
import com.sentinel.av.ui.components.SecurityGaugePanel;
import com.sentinel.av.ui.components.StatCard;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

public class DashboardPanel extends JPanel implements RealTimeMonitor.MonitorEventListener, ActivityLogger.LogListener {

    private final MainFrame mainFrame;
    private JLabel statusTitle;
    private JLabel statusSubtext;
    private JPanel heroBanner;
    private JButton shieldToggleBtn;
    
    private SecurityGaugePanel gaugePanel;
    private StatCard signaturesCard;
    private StatCard realTimeCard;
    private StatCard quarantineCard;
    private StatCard threatsCard;

    private DefaultListModel<String> recentActivityModel;
    private int threatCount = 0;

    public DashboardPanel(MainFrame mainFrame) {
        this.mainFrame = mainFrame;
        setLayout(new BorderLayout(20, 20));
        setBackground(new Color(20, 23, 29));
        setBorder(new EmptyBorder(25, 25, 25, 25));

        initComponents();

        RealTimeMonitor.getInstance().addListener(this);
        ActivityLogger.getInstance().addListener(this);

        updateDashboardStats();
    }

    private void initComponents() {
        // --- Top Hero Banner & Health Gauge ---
        heroBanner = new JPanel(new BorderLayout(20, 15));
        heroBanner.setBackground(new Color(28, 42, 35));
        heroBanner.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(45, 140, 80), 1),
            new EmptyBorder(20, 25, 20, 25)
        ));

        // Left Score Gauge
        gaugePanel = new SecurityGaugePanel();
        gaugePanel.setSecurityScore(100, "FULLY SECURED");

        // Middle Banner Text
        JPanel heroTextGroup = new JPanel(new GridLayout(2, 1, 4, 4));
        heroTextGroup.setOpaque(false);

        statusTitle = new JLabel("🛡️ SYSTEM IS FULLY PROTECTED");
        statusTitle.setFont(new Font("Segoe UI", Font.BOLD, 22));
        statusTitle.setForeground(new Color(110, 230, 150));

        statusSubtext = new JLabel("Real-Time Sentinel Guard Active • YARA Heuristic Engine Enabled • Database Up to Date");
        statusSubtext.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        statusSubtext.setForeground(new Color(180, 210, 190));

        heroTextGroup.add(statusTitle);
        heroTextGroup.add(statusSubtext);

        // Right Hero Buttons
        JPanel heroRight = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 10));
        heroRight.setOpaque(false);

        JButton quickScanBtn = new JButton("⚡ Quick Scan");
        quickScanBtn.setFont(new Font("Segoe UI", Font.BOLD, 13));
        quickScanBtn.setBackground(new Color(16, 185, 129));
        quickScanBtn.setForeground(Color.WHITE);
        quickScanBtn.setFocusPainted(false);
        quickScanBtn.addActionListener(e -> mainFrame.switchToScanTabAndStartQuick());

        shieldToggleBtn = new JButton("Turn Shield OFF");
        shieldToggleBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        shieldToggleBtn.setBackground(new Color(45, 55, 70));
        shieldToggleBtn.setForeground(Color.WHITE);
        shieldToggleBtn.setFocusPainted(false);
        shieldToggleBtn.addActionListener(e -> toggleShield());

        heroRight.add(quickScanBtn);
        heroRight.add(shieldToggleBtn);

        JPanel centerHeroContent = new JPanel(new BorderLayout(15, 15));
        centerHeroContent.setOpaque(false);
        centerHeroContent.add(heroTextGroup, BorderLayout.CENTER);
        centerHeroContent.add(heroRight, BorderLayout.SOUTH);

        heroBanner.add(gaugePanel, BorderLayout.WEST);
        heroBanner.add(centerHeroContent, BorderLayout.CENTER);

        // --- Center: 4 Stat Cards Grid ---
        JPanel statsPanel = new JPanel(new GridLayout(1, 4, 15, 15));
        statsPanel.setOpaque(false);

        signaturesCard = new StatCard("VIRUS DEFINITIONS", String.valueOf(SignatureDatabase.getInstance().getSignatureCount()), "MD5, SHA-256 & YARA Rules", new Color(59, 130, 246));
        realTimeCard = new StatCard("REAL-TIME SHIELD", "ACTIVE", "Guarding Downloads & Desktop", new Color(16, 185, 129));
        quarantineCard = new StatCard("QUARANTINE VAULT", String.valueOf(QuarantineManager.getInstance().getQuarantineCount()), "XOR Encrypted Storage", new Color(168, 85, 247));
        threatsCard = new StatCard("THREATS CAUGHT", "0", "Total threats intercepted", new Color(239, 68, 68));

        statsPanel.add(signaturesCard);
        statsPanel.add(realTimeCard);
        statsPanel.add(quarantineCard);
        statsPanel.add(threatsCard);

        // --- Bottom: Analytics Chart + Security Actions + Recent Log Stream ---
        JPanel bottomGrid = new JPanel(new GridLayout(1, 3, 15, 15));
        bottomGrid.setOpaque(false);

        // Card 1: Security Analytics
        CyberCard analyticsCard = new CyberCard(new Color(50, 58, 72));
        JLabel chartTitle = new JLabel("📊 Weekly Security Activity");
        chartTitle.setFont(new Font("Segoe UI", Font.BOLD, 15));
        chartTitle.setForeground(Color.WHITE);

        AnalyticsChartPanel chart = new AnalyticsChartPanel();
        analyticsCard.add(chartTitle, BorderLayout.NORTH);
        analyticsCard.add(chart, BorderLayout.CENTER);

        // Card 2: Quick Actions
        CyberCard actionsCard = new CyberCard(new Color(50, 58, 72));
        JLabel qaTitle = new JLabel("⚡ Quick Security Actions");
        qaTitle.setFont(new Font("Segoe UI", Font.BOLD, 15));
        qaTitle.setForeground(Color.WHITE);

        JPanel qaBtnGrid = new JPanel(new GridLayout(4, 1, 8, 8));
        qaBtnGrid.setOpaque(false);

        JButton scanDownloadsBtn = new JButton("📁 Scan Downloads Directory");
        scanDownloadsBtn.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        scanDownloadsBtn.setBackground(new Color(36, 42, 54));
        scanDownloadsBtn.setForeground(Color.WHITE);
        scanDownloadsBtn.setFocusPainted(false);
        scanDownloadsBtn.addActionListener(e -> mainFrame.switchToScanTabWithFolder(new java.io.File(System.getProperty("user.home"), "Downloads")));

        JButton processInspectBtn = new JButton("⚙️ Open Process & Memory Inspector");
        processInspectBtn.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        processInspectBtn.setBackground(new Color(36, 42, 54));
        processInspectBtn.setForeground(Color.WHITE);
        processInspectBtn.setFocusPainted(false);
        processInspectBtn.addActionListener(e -> mainFrame.switchToProcessTab());

        JButton createEicarBtn = new JButton("🧪 Generate Safe EICAR Malware Test File");
        createEicarBtn.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        createEicarBtn.setBackground(new Color(36, 42, 54));
        createEicarBtn.setForeground(Color.WHITE);
        createEicarBtn.setFocusPainted(false);
        createEicarBtn.addActionListener(e -> createEicarTestFile());

        JButton viewVaultBtn = new JButton("🔒 Inspect Quarantine Vault");
        viewVaultBtn.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        viewVaultBtn.setBackground(new Color(36, 42, 54));
        viewVaultBtn.setForeground(Color.WHITE);
        viewVaultBtn.setFocusPainted(false);
        viewVaultBtn.addActionListener(e -> mainFrame.switchToQuarantineTab());

        qaBtnGrid.add(scanDownloadsBtn);
        qaBtnGrid.add(processInspectBtn);
        qaBtnGrid.add(createEicarBtn);
        qaBtnGrid.add(viewVaultBtn);

        actionsCard.add(qaTitle, BorderLayout.NORTH);
        actionsCard.add(qaBtnGrid, BorderLayout.CENTER);

        // Card 3: Live Security Log Feed
        CyberCard activityCard = new CyberCard(new Color(50, 58, 72));
        JLabel actTitle = new JLabel("📜 Security Event Audit Feed");
        actTitle.setFont(new Font("Segoe UI", Font.BOLD, 15));
        actTitle.setForeground(Color.WHITE);

        recentActivityModel = new DefaultListModel<>();
        JList<String> activityList = new JList<>(recentActivityModel);
        activityList.setBackground(new Color(22, 26, 34));
        activityList.setForeground(new Color(200, 215, 235));
        activityList.setFont(new Font("Consolas", Font.PLAIN, 11));

        JScrollPane scrollPane = new JScrollPane(activityList);
        scrollPane.setBorder(BorderFactory.createLineBorder(new Color(45, 52, 65)));

        activityCard.add(actTitle, BorderLayout.NORTH);
        activityCard.add(scrollPane, BorderLayout.CENTER);

        bottomGrid.add(analyticsCard);
        bottomGrid.add(actionsCard);
        bottomGrid.add(activityCard);

        // Layout Container
        JPanel topContainer = new JPanel(new BorderLayout(15, 15));
        topContainer.setOpaque(false);
        topContainer.add(heroBanner, BorderLayout.NORTH);
        topContainer.add(statsPanel, BorderLayout.CENTER);

        add(topContainer, BorderLayout.NORTH);
        add(bottomGrid, BorderLayout.CENTER);
    }

    private void toggleShield() {
        RealTimeMonitor monitor = RealTimeMonitor.getInstance();
        if (monitor.isRunning()) {
            monitor.stopMonitoring();
        } else {
            monitor.startMonitoring();
        }
    }

    public void updateDashboardStats() {
        boolean active = RealTimeMonitor.getInstance().isRunning();
        int qCount = QuarantineManager.getInstance().getQuarantineCount();

        int healthScore = 100;
        if (!active) healthScore -= 25;
        if (qCount > 0) healthScore -= Math.min(35, qCount * 10);
        if (threatCount > 0) healthScore -= 15;

        if (active) {
            heroBanner.setBackground(new Color(24, 45, 34));
            heroBanner.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(45, 140, 75), 1),
                new EmptyBorder(20, 25, 20, 25)
            ));
            statusTitle.setText("🛡️ SYSTEM IS FULLY PROTECTED");
            statusTitle.setForeground(new Color(110, 230, 150));
            statusSubtext.setText("Real-Time Sentinel Guard Active • YARA Heuristic Engine Enabled • Database Up to Date");
            shieldToggleBtn.setText("Turn Shield OFF");
            shieldToggleBtn.setBackground(new Color(60, 40, 45));
            realTimeCard.setValue("ACTIVE");
            realTimeCard.setSubtext("Guarding system");
        } else {
            heroBanner.setBackground(new Color(50, 35, 25));
            heroBanner.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(180, 90, 30), 1),
                new EmptyBorder(20, 25, 20, 25)
            ));
            statusTitle.setText("⚠️ REAL-TIME PROTECTION IS OFF");
            statusTitle.setForeground(new Color(255, 180, 80));
            statusSubtext.setText("System background file monitoring is currently disabled!");
            shieldToggleBtn.setText("Turn Shield ON");
            shieldToggleBtn.setBackground(new Color(16, 185, 129));
            realTimeCard.setValue("DISABLED");
            realTimeCard.setSubtext("Shield inactive");
        }

        gaugePanel.setSecurityScore(healthScore, active ? "FULLY SECURED" : "ACTION REQUIRED");
        signaturesCard.setValue(String.valueOf(SignatureDatabase.getInstance().getSignatureCount()));
        quarantineCard.setValue(String.valueOf(qCount));
        threatsCard.setValue(String.valueOf(threatCount));
    }

    private void createEicarTestFile() {
        try {
            java.io.File desktop = new java.io.File(System.getProperty("user.home"), "Desktop");
            if (!desktop.exists()) desktop = new java.io.File(System.getProperty("user.home"));

            java.io.File eicarFile = new java.io.File(desktop, "eicar_test_virus.txt");
            String eicarContent = "X5O!P%@AP[4\\PZX54(P^)7CC)$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

            java.nio.file.Files.write(eicarFile.toPath(), eicarContent.getBytes());

            JOptionPane.showMessageDialog(this,
                "EICAR test malware file created at:\n" + eicarFile.getAbsolutePath() + 
                "\n\nYou can now run a scan or check Real-Time Guard to verify SentinelAV detects it!",
                "Safe Test File Generated",
                JOptionPane.INFORMATION_MESSAGE);

            ActivityLogger.getInstance().info("Dashboard", "Generated EICAR test file at " + eicarFile.getAbsolutePath());

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Failed to create EICAR test file: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    @Override
    public void onFileDetected(java.nio.file.Path path, String eventType) {
        // Real-time event
    }

    @Override
    public void onThreatIntercepted(com.sentinel.av.model.ScanResult result) {
        threatCount++;
        SwingUtilities.invokeLater(this::updateDashboardStats);
    }

    @Override
    public void onMonitorStatusChanged(boolean isActive) {
        SwingUtilities.invokeLater(this::updateDashboardStats);
    }

    @Override
    public void onLogAdded(ActivityLog log) {
        SwingUtilities.invokeLater(() -> {
            recentActivityModel.addElement("[" + log.getTimestamp().substring(11) + "] [" + log.getLevel() + "] " + log.getMessage());
            if (recentActivityModel.size() > 60) {
                recentActivityModel.remove(0);
            }
        });
    }
}
