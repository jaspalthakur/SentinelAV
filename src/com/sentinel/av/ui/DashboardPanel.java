package com.sentinel.av.ui;

import com.sentinel.av.core.ActivityLogger;
import com.sentinel.av.core.QuarantineManager;
import com.sentinel.av.core.RealTimeMonitor;
import com.sentinel.av.core.SignatureDatabase;
import com.sentinel.av.model.ActivityLog;
import com.sentinel.av.model.ScanResult;
import com.sentinel.av.ui.components.AnalyticsChartPanel;
import com.sentinel.av.ui.components.CyberButton;
import com.sentinel.av.ui.components.CyberCard;
import com.sentinel.av.ui.components.CyberPalette;
import com.sentinel.av.ui.components.SecurityGaugePanel;
import com.sentinel.av.ui.components.StatCard;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

public class DashboardPanel extends JPanel implements RealTimeMonitor.MonitorEventListener, ActivityLogger.LogListener {

    private final MainFrame mainFrame;
    private JLabel statusTitle;
    private JLabel statusSubtext;
    private JPanel heroBanner;
    private CyberButton shieldToggleBtn;

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
        setBackground(CyberPalette.BACKGROUND);
        setBorder(new EmptyBorder(25, 25, 25, 25));

        initComponents();

        // Seed the live feed with anything already recorded this session.
        for (ActivityLog log : ActivityLogger.getInstance().getLogs()) {
            appendActivity(log);
        }

        RealTimeMonitor.getInstance().addListener(this);
        ActivityLogger.getInstance().addListener(this);

        updateDashboardStats();
    }

    private void initComponents() {
        // --- Top Hero Banner & Health Gauge ---
        heroBanner = new JPanel(new BorderLayout(20, 15));
        heroBanner.setBackground(CyberPalette.SURFACE_ACTIVE);
        heroBanner.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(CyberPalette.SAFE, 1),
            new EmptyBorder(20, 25, 20, 25)));

        // Left Score Gauge
        gaugePanel = new SecurityGaugePanel();
        gaugePanel.setSecurityScore(100, "FULLY SECURED");

        // Middle Banner Text
        JPanel heroTextGroup = new JPanel(new GridLayout(2, 1, 4, 4));
        heroTextGroup.setOpaque(false);

        statusTitle = new JLabel("\uD83D\uDEA1  SYSTEM IS FULLY PROTECTED");
        statusTitle.setFont(CyberPalette.FONT_TITLE_LARGE);
        statusTitle.setForeground(CyberPalette.SAFE);

        statusSubtext = new JLabel("Real-Time Sentinel Guard Active \u2022 YARA Heuristic Engine Enabled \u2022 Database Up to Date");
        statusSubtext.setFont(CyberPalette.FONT_BODY);
        statusSubtext.setForeground(CyberPalette.TEXT_SECONDARY);

        heroTextGroup.add(statusTitle);
        heroTextGroup.add(statusSubtext);

        // Right Hero Buttons
        JPanel heroRight = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 10));
        heroRight.setOpaque(false);

        CyberButton quickScanBtn = new CyberButton("\u26A1  Quick Scan", CyberButton.PRIMARY);
        quickScanBtn.setFont(CyberPalette.FONT_BODY_BOLD);
        quickScanBtn.addActionListener(e -> mainFrame.switchToScanTabAndStartQuick());

        shieldToggleBtn = new CyberButton("Turn Shield OFF", CyberButton.DANGER);
        shieldToggleBtn.setFont(CyberPalette.FONT_SMALL);
        shieldToggleBtn.addActionListener(e -> toggleShield());

        heroRight.add(quickScanBtn);
        heroRight.add(shieldToggleBtn);

        JPanel centerHeroContent = new JPanel(new BorderLayout(15, 15));
        centerHeroContent.setOpaque(false);
        centerHeroContent.add(heroTextGroup, BorderLayout.CENTER);
        centerHeroContent.add(heroRight, BorderLayout.SOUTH);

        heroBanner.add(gaugePanel, BorderLayout.WEST);
        heroBanner.add(centerHeroContent, BorderLayout.CENTER);

        // --- Center: 4 Stat Cards Grid (wraps on narrow windows) ---
        JPanel statsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 15));
        statsPanel.setOpaque(false);

        signaturesCard = new StatCard("VIRUS DEFINITIONS",
            String.valueOf(SignatureDatabase.getInstance().getSignatureCount()),
            "MD5, SHA-256 & YARA Rules", CyberPalette.ACCENT);
        realTimeCard = new StatCard("REAL-TIME SHIELD", "ACTIVE",
            "Guarding Downloads & Desktop", CyberPalette.SAFE);
        quarantineCard = new StatCard("QUARANTINE VAULT",
            String.valueOf(QuarantineManager.getInstance().getQuarantineCount()),
            "AES-256 Encrypted Storage", CyberPalette.PURPLE);
        threatsCard = new StatCard("THREATS CAUGHT", "0",
            "Total threats intercepted", CyberPalette.THREAT);

        statsPanel.add(signaturesCard);
        statsPanel.add(realTimeCard);
        statsPanel.add(quarantineCard);
        statsPanel.add(threatsCard);

        // --- Bottom: Analytics Chart + Security Actions + Recent Log Stream (wraps on narrow windows) ---
        JPanel bottomGrid = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 15));
        bottomGrid.setOpaque(false);

        // Card 1: Security Analytics
        CyberCard analyticsCard = new CyberCard(CyberPalette.BORDER);
        analyticsCard.setHoverEnabled(true);
        analyticsCard.setPreferredSize(new Dimension(420, 0));
        JLabel chartTitle = new JLabel("\uD83D\uDCCA  Weekly Security Activity");
        chartTitle.setFont(CyberPalette.FONT_TITLE_SMALL);
        chartTitle.setForeground(CyberPalette.TEXT_PRIMARY);

        AnalyticsChartPanel chart = new AnalyticsChartPanel();
        analyticsCard.add(chartTitle, BorderLayout.NORTH);
        analyticsCard.add(chart, BorderLayout.CENTER);

        // Card 2: Quick Actions
        CyberCard actionsCard = new CyberCard(CyberPalette.BORDER);
        actionsCard.setHoverEnabled(true);
        actionsCard.setPreferredSize(new Dimension(300, 0));
        JLabel qaTitle = new JLabel("\u26A1  Quick Security Actions");
        qaTitle.setFont(CyberPalette.FONT_TITLE_SMALL);
        qaTitle.setForeground(CyberPalette.TEXT_PRIMARY);

        JPanel qaBtnGrid = new JPanel(new GridLayout(4, 1, 8, 8));
        qaBtnGrid.setOpaque(false);

        CyberButton scanDownloadsBtn = new CyberButton("\uD83D\uDCC1  Scan Downloads Directory", CyberButton.SECONDARY);
        scanDownloadsBtn.setFont(CyberPalette.FONT_SMALL);
        scanDownloadsBtn.addActionListener(e -> mainFrame.switchToScanTabWithFolder(
            new File(System.getProperty("user.home"), "Downloads")));

        CyberButton processInspectBtn = new CyberButton("\u2699\uFE0F  Open Process & Memory Inspector",
            CyberButton.SECONDARY);
        processInspectBtn.setFont(CyberPalette.FONT_SMALL);
        processInspectBtn.addActionListener(e -> mainFrame.switchToProcessTab());

        CyberButton createEicarBtn = new CyberButton("\uD83E\uDEAA  Generate Safe EICAR Test File", CyberButton.SECONDARY);
        createEicarBtn.setFont(CyberPalette.FONT_SMALL);
        createEicarBtn.addActionListener(e -> createEicarTestFile());

        CyberButton viewVaultBtn = new CyberButton("\uD83D\uDD12  Inspect Quarantine Vault", CyberButton.SECONDARY);
        viewVaultBtn.setFont(CyberPalette.FONT_SMALL);
        viewVaultBtn.addActionListener(e -> mainFrame.switchToQuarantineTab());

        qaBtnGrid.add(scanDownloadsBtn);
        qaBtnGrid.add(processInspectBtn);
        qaBtnGrid.add(createEicarBtn);
        qaBtnGrid.add(viewVaultBtn);

        actionsCard.add(qaTitle, BorderLayout.NORTH);
        actionsCard.add(qaBtnGrid, BorderLayout.CENTER);

        // Card 3: Live Security Log Feed
        CyberCard activityCard = new CyberCard(CyberPalette.BORDER);
        activityCard.setHoverEnabled(true);
        activityCard.setPreferredSize(new Dimension(340, 0));
        JLabel actTitle = new JLabel("\uD83D\uDCDC  Security Event Audit Feed");
        actTitle.setFont(CyberPalette.FONT_TITLE_SMALL);
        actTitle.setForeground(CyberPalette.TEXT_PRIMARY);

        recentActivityModel = new DefaultListModel<>();
        JList<String> activityList = new JList<>(recentActivityModel);
        activityList.setBackground(CyberPalette.INPUT_BG);
        activityList.setForeground(CyberPalette.TEXT_PRIMARY);
        activityList.setFont(CyberPalette.FONT_CODE);

        JScrollPane scrollPane = new JScrollPane(activityList);
        scrollPane.setBorder(BorderFactory.createLineBorder(CyberPalette.BORDER));
        scrollPane.getViewport().setBackground(CyberPalette.INPUT_BG);

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
            heroBanner.setBackground(CyberPalette.SURFACE_ACTIVE);
            heroBanner.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(CyberPalette.SAFE, 1),
                new EmptyBorder(20, 25, 20, 25)));
            statusTitle.setText("\uD83D\uDEA1  SYSTEM IS FULLY PROTECTED");
            statusTitle.setForeground(CyberPalette.SAFE);
            statusSubtext.setText("Real-Time Sentinel Guard Active \u2022 YARA Heuristic Engine Enabled \u2022 Database Up to Date");
            shieldToggleBtn.setText("Turn Shield OFF");
            shieldToggleBtn.setVariant(CyberButton.DANGER);
            realTimeCard.setValue("ACTIVE");
            realTimeCard.setSubtext("Guarding system");
        } else {
            heroBanner.setBackground(new Color(50, 35, 25));
            heroBanner.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(CyberPalette.WARNING, 1),
                new EmptyBorder(20, 25, 20, 25)));
            statusTitle.setText("\u26A0  REAL-TIME PROTECTION IS OFF");
            statusTitle.setForeground(CyberPalette.WARNING);
            statusSubtext.setText("System background file monitoring is currently disabled!");
            shieldToggleBtn.setText("Turn Shield ON");
            shieldToggleBtn.setVariant(CyberButton.PRIMARY);
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
            File desktop = new File(System.getProperty("user.home"), "Desktop");
            if (!desktop.exists()) {
                desktop = new File(System.getProperty("user.home"));
            }

            File eicarFile = new File(desktop, "eicar_test_virus.txt");
            String eicarContent = "X5O!P%@AP[4\\PZX54(P^)7CC)$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

            Files.write(eicarFile.toPath(), eicarContent.getBytes());

            JOptionPane.showMessageDialog(this,
                "EICAR test malware file created at:\n" + eicarFile.getAbsolutePath()
                    + "\n\nYou can now run a scan or check Real-Time Guard to verify SentinelAV detects it!",
                "Safe Test File Generated", JOptionPane.INFORMATION_MESSAGE);

            ActivityLogger.getInstance().info("Dashboard",
                "Generated EICAR test file at " + eicarFile.getAbsolutePath());

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Failed to create EICAR test file: " + ex.getMessage(), "Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    @Override
    public void onFileDetected(Path path, String eventType) {
        // Real-time event
    }

    @Override
    public void onThreatIntercepted(ScanResult result) {
        threatCount++;
        SwingUtilities.invokeLater(this::updateDashboardStats);
    }

    @Override
    public void onMonitorStatusChanged(boolean isActive) {
        SwingUtilities.invokeLater(this::updateDashboardStats);
    }

    @Override
    public void onLogAdded(ActivityLog log) {
        SwingUtilities.invokeLater(() -> appendActivity(log));
    }

    private void appendActivity(ActivityLog log) {
        recentActivityModel.addElement("[" + log.getTimestamp().substring(11) + "] [" + log.getLevel() + "] "
            + log.getMessage());
        if (recentActivityModel.size() > 60) {
            recentActivityModel.remove(0);
        }
    }
}
