package com.sentinel.av.ui;

import com.sentinel.av.core.ActivityLogger;
import com.sentinel.av.core.ActivityTracker;
import com.sentinel.av.core.QuarantineManager;
import com.sentinel.av.core.RealTimeMonitor;
import com.sentinel.av.core.SignatureDatabase;
import com.sentinel.av.model.ActivityLog;
import com.sentinel.av.ui.components.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

public class HomePanel extends JPanel implements RealTimeMonitor.MonitorEventListener, ActivityLogger.LogListener {

    private final MainFrame mainFrame;
    private JLabel statusTitle;
    private JLabel statusSubtext;
    private JPanel heroBanner;
    private JPanel needsAttentionStrip;
    private JLabel needsAttentionLabel;
    
    private StatCard lastScanCard;
    private StatCard definitionsCard;
    private StatCard quarantineCard;
    private StatCard threatsCard;

    private AnalyticsChartPanel chartPanel;
    private TimelinePanel timelinePanel;

    public HomePanel(MainFrame mainFrame) {
        this.mainFrame = mainFrame;
        setLayout(new BorderLayout(16, 16));
        setBackground(CyberPalette.BACKGROUND);
        setBorder(new EmptyBorder(20, 24, 20, 24));

        initComponents();

        RealTimeMonitor.getInstance().addListener(this);
        ActivityLogger.getInstance().addListener(this);

        updateHomeState();
    }

    private void initComponents() {
        // --- 1. Hero Card ---
        heroBanner = new JPanel(new BorderLayout(20, 15));
        heroBanner.setBackground(CyberPalette.SURFACE);
        heroBanner.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(CyberPalette.SAFE, 1),
            new EmptyBorder(20, 24, 20, 24)
        ));

        // Hero Left Text
        JPanel heroLeftText = new JPanel(new GridLayout(2, 1, 4, 4));
        heroLeftText.setOpaque(false);

        statusTitle = new JLabel("System Protected");
        statusTitle.setFont(CyberPalette.FONT_TITLE_LARGE);
        statusTitle.setForeground(CyberPalette.SAFE);

        statusSubtext = new JLabel("Real-time protection active · Last scan: Never");
        statusSubtext.setFont(CyberPalette.FONT_BODY);
        statusSubtext.setForeground(CyberPalette.TEXT_SECONDARY);

        heroLeftText.add(statusTitle);
        heroLeftText.add(statusSubtext);

        // Hero Right Primary Action Button
        JPanel heroRight = new JPanel(new FlowLayout(FlowLayout.RIGHT, 12, 10));
        heroRight.setOpaque(false);

        JButton scanNowBtn = new JButton("▶  Scan Now");
        scanNowBtn.setFont(new Font("Segoe UI", Font.BOLD, 15));
        scanNowBtn.setBackground(CyberPalette.ACCENT);
        scanNowBtn.setForeground(Color.WHITE);
        scanNowBtn.setFocusPainted(false);
        scanNowBtn.setPreferredSize(new Dimension(160, 44));
        scanNowBtn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        scanNowBtn.addActionListener(e -> mainFrame.switchToScanTabAndStartQuick());

        heroRight.add(scanNowBtn);

        heroBanner.add(heroLeftText, BorderLayout.CENTER);
        heroBanner.add(heroRight, BorderLayout.EAST);

        // --- 2. Needs Attention Strip ---
        needsAttentionStrip = new JPanel(new BorderLayout(12, 0));
        needsAttentionStrip.setBackground(new Color(55, 38, 15));
        needsAttentionStrip.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(CyberPalette.WARNING, 1),
            new EmptyBorder(10, 16, 10, 16)
        ));

        needsAttentionLabel = new JLabel("⚠️  Real-Time Protection is currently turned OFF. System is exposed!");
        needsAttentionLabel.setFont(CyberPalette.FONT_BODY_BOLD);
        needsAttentionLabel.setForeground(CyberPalette.WARNING);

        JButton fixNowBtn = new JButton("Fix Now");
        fixNowBtn.setFont(CyberPalette.FONT_BODY_BOLD);
        fixNowBtn.setBackground(CyberPalette.WARNING);
        fixNowBtn.setForeground(Color.BLACK);
        fixNowBtn.setFocusPainted(false);
        fixNowBtn.addActionListener(e -> {
            RealTimeMonitor.getInstance().startMonitoring();
            updateHomeState();
        });

        needsAttentionStrip.add(needsAttentionLabel, BorderLayout.CENTER);
        needsAttentionStrip.add(fixNowBtn, BorderLayout.EAST);
        needsAttentionStrip.setVisible(false);

        // --- 3. Stat Row (4 Cards) ---
        JPanel statsPanel = new JPanel(new GridLayout(1, 4, 14, 14));
        statsPanel.setOpaque(false);

        lastScanCard = new StatCard("LAST SCAN", "Never", "Run a scan to check system", CyberPalette.ACCENT);
        definitionsCard = new StatCard("VIRUS DEFINITIONS", "8 Rules", "Updated Today", CyberPalette.SAFE);
        quarantineCard = new StatCard("QUARANTINE VAULT", String.valueOf(QuarantineManager.getInstance().getQuarantineCount()), "XOR Encrypted Vault", CyberPalette.PURPLE);
        threatsCard = new StatCard("THREATS BLOCKED", String.valueOf(ActivityTracker.getInstance().getTotalThreatsBlocked()), "Total threats intercepted", CyberPalette.THREAT);

        statsPanel.add(lastScanCard);
        statsPanel.add(definitionsCard);
        statsPanel.add(quarantineCard);
        statsPanel.add(threatsCard);

        // Top Grouping
        JPanel topGroup = new JPanel(new BorderLayout(12, 12));
        topGroup.setOpaque(false);
        topGroup.add(heroBanner, BorderLayout.NORTH);
        topGroup.add(needsAttentionStrip, BorderLayout.CENTER);
        topGroup.add(statsPanel, BorderLayout.SOUTH);

        // --- 4. Bottom Row: Activity Chart (2/3) + Security Timeline (1/3) ---
        JPanel bottomRow = new JPanel(new BorderLayout(16, 16));
        bottomRow.setOpaque(false);

        // Chart Card (2/3 width)
        CyberCard chartCard = new CyberCard(CyberPalette.BORDER);
        JLabel chartTitle = new JLabel("Weekly Security Activity");
        chartTitle.setFont(CyberPalette.FONT_TITLE_MEDIUM);
        chartTitle.setForeground(CyberPalette.TEXT_PRIMARY);

        chartPanel = new AnalyticsChartPanel();
        chartCard.add(chartTitle, BorderLayout.NORTH);
        chartCard.add(chartPanel, BorderLayout.CENTER);

        // Timeline Card (1/3 width)
        CyberCard timelineCard = new CyberCard(CyberPalette.BORDER);
        timelineCard.setPreferredSize(new Dimension(360, 0));

        JLabel timelineTitle = new JLabel("Security Activity Feed");
        timelineTitle.setFont(CyberPalette.FONT_TITLE_MEDIUM);
        timelineTitle.setForeground(CyberPalette.TEXT_PRIMARY);

        timelinePanel = new TimelinePanel();
        timelineCard.add(timelineTitle, BorderLayout.NORTH);
        timelineCard.add(timelinePanel, BorderLayout.CENTER);

        bottomRow.add(chartCard, BorderLayout.CENTER);
        bottomRow.add(timelineCard, BorderLayout.EAST);

        add(topGroup, BorderLayout.NORTH);
        add(bottomRow, BorderLayout.CENTER);
    }

    public void updateHomeState() {
        boolean active = RealTimeMonitor.getInstance().isRunning();
        ActivityTracker tracker = ActivityTracker.getInstance();
        boolean hasScanned = tracker.getLastScanTime() != null;

        if (!active) {
            heroBanner.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(CyberPalette.WARNING, 1),
                new EmptyBorder(20, 24, 20, 24)
            ));
            statusTitle.setText("Protection Paused");
            statusTitle.setForeground(CyberPalette.WARNING);
            statusSubtext.setText("Real-time shield is turned off · Last scan: " + tracker.getLastScanFormatted());
            needsAttentionLabel.setText("⚠️ Real-Time Protection is OFF. System background monitoring disabled!");
            needsAttentionStrip.setVisible(true);
        } else if (!hasScanned) {
            heroBanner.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(CyberPalette.WARNING, 1),
                new EmptyBorder(20, 24, 20, 24)
            ));
            statusTitle.setText("First Scan Needed");
            statusTitle.setForeground(CyberPalette.WARNING);
            statusSubtext.setText("Real-time shield active · Run your first scan to ensure full protection");
            needsAttentionLabel.setText("⚠️ You haven't run a scan yet. Click 'Scan Now' to check system health.");
            needsAttentionStrip.setVisible(true);
        } else {
            heroBanner.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(CyberPalette.SAFE, 1),
                new EmptyBorder(20, 24, 20, 24)
            ));
            statusTitle.setText("You're Protected");
            statusTitle.setForeground(CyberPalette.SAFE);
            statusSubtext.setText("Real-time shield active · Last scan: " + tracker.getLastScanFormatted());
            needsAttentionStrip.setVisible(false);
        }

        lastScanCard.setValue(tracker.getLastScanFormatted());
        definitionsCard.setValue(SignatureDatabase.getInstance().getSignatureCount() + " Rules");
        quarantineCard.setValue(String.valueOf(QuarantineManager.getInstance().getQuarantineCount()));
        threatsCard.setValue(String.valueOf(tracker.getTotalThreatsBlocked()));

        chartPanel.repaint();
        timelinePanel.refreshFeed();
    }

    @Override
    public void onFileDetected(java.nio.file.Path path, String eventType) {}

    @Override
    public void onThreatIntercepted(com.sentinel.av.model.ScanResult result) {
        SwingUtilities.invokeLater(this::updateHomeState);
    }

    @Override
    public void onMonitorStatusChanged(boolean isActive) {
        SwingUtilities.invokeLater(this::updateHomeState);
    }

    @Override
    public void onLogAdded(ActivityLog log) {
        SwingUtilities.invokeLater(this::updateHomeState);
    }
}
