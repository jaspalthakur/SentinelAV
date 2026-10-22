package com.sentinel.av.ui;

import com.sentinel.av.core.ActivityLogger;
import com.sentinel.av.core.RealTimeMonitor;
import com.sentinel.av.core.canary.RansomwareCanaryGuard;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.File;

public class MainFrame extends JFrame {

    private final CardLayout cardLayout = new CardLayout();
    private final JPanel mainContentPanel = new JPanel(cardLayout);

    private DashboardPanel dashboardPanel;
    private ScannerPanel scannerPanel;
    private ProcessPanel processPanel;
    private RealTimeMonitorPanel monitorPanel;
    private QuarantinePanel quarantinePanel;
    private SignaturesPanel signaturesPanel;
    private AttackCoveragePanel attackPanel;
    private LogsPanel logsPanel;

    private JButton navDashBtn;
    private JButton navScanBtn;
    private JButton navProcBtn;
    private JButton navGuardBtn;
    private JButton navQuarBtn;
    private JButton navSigBtn;
    private JButton navAttackBtn;
    private JButton navLogBtn;

    public MainFrame() {
        setTitle("SentinelAV — Cyber Security, EDR & Threat Intelligence Suite");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1260, 800);
        setMinimumSize(new Dimension(1080, 700));
        setLocationRelativeTo(null);

        initComponents();

        // Start Real-time Guard & Deploy Ransomware Canary Files by default
        RealTimeMonitor.getInstance().startMonitoring();
        RansomwareCanaryGuard.getInstance().deployCanaries();

        ActivityLogger.getInstance().system("AppInit", "SentinelAV Cyber Security Suite initialized with MITRE ATT&CK Engine.");
    }

    private void initComponents() {
        JPanel rootPanel = new JPanel(new BorderLayout());
        rootPanel.setBackground(new Color(20, 23, 29));

        // --- Left Sidebar Navigation ---
        JPanel sidebar = new JPanel(new BorderLayout());
        sidebar.setPreferredSize(new Dimension(250, 0));
        sidebar.setBackground(new Color(15, 17, 22));
        sidebar.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, new Color(40, 46, 58)));

        // App Brand Header
        JPanel brandPanel = new JPanel(new BorderLayout(12, 5));
        brandPanel.setOpaque(false);
        brandPanel.setBorder(new EmptyBorder(25, 20, 25, 20));

        JLabel brandIcon = new JLabel("🛡️");
        brandIcon.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 32));

        JLabel brandTitle = new JLabel("SENTINEL AV");
        brandTitle.setFont(new Font("Segoe UI", Font.BOLD, 19));
        brandTitle.setForeground(Color.WHITE);

        JLabel brandSub = new JLabel("v3.5 EDR & Threat Engine");
        brandSub.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        brandSub.setForeground(new Color(16, 185, 129));

        JPanel brandTextGroup = new JPanel(new GridLayout(2, 1));
        brandTextGroup.setOpaque(false);
        brandTextGroup.add(brandTitle);
        brandTextGroup.add(brandSub);

        brandPanel.add(brandIcon, BorderLayout.WEST);
        brandPanel.add(brandTextGroup, BorderLayout.CENTER);

        // Nav Buttons
        JPanel navMenu = new JPanel(new GridLayout(8, 1, 5, 5));
        navMenu.setOpaque(false);
        navMenu.setBorder(new EmptyBorder(10, 12, 10, 12));

        navDashBtn = createNavButton("📊 Dashboard Overview", "DASHBOARD");
        navScanBtn = createNavButton("🔍 Malware Scanner", "SCANNER");
        navProcBtn = createNavButton("⚙️ Process Inspector", "PROCESSES");
        navGuardBtn = createNavButton("📡 Real-Time Guard", "GUARD");
        navQuarBtn = createNavButton("🔒 Quarantine Vault", "QUARANTINE");
        navSigBtn = createNavButton("🧬 YARA & Definitions", "SIGNATURES");
        navAttackBtn = createNavButton("🎯 MITRE ATT&CK Matrix", "ATTACK");
        navLogBtn = createNavButton("📜 Security Audit Logs", "LOGS");

        navMenu.add(navDashBtn);
        navMenu.add(navScanBtn);
        navMenu.add(navProcBtn);
        navMenu.add(navGuardBtn);
        navMenu.add(navQuarBtn);
        navMenu.add(navSigBtn);
        navMenu.add(navAttackBtn);
        navMenu.add(navLogBtn);

        sidebar.add(brandPanel, BorderLayout.NORTH);
        sidebar.add(navMenu, BorderLayout.CENTER);

        // Bottom System Memory Status Widget
        JPanel systemWidget = new JPanel(new BorderLayout());
        systemWidget.setOpaque(false);
        systemWidget.setBorder(new EmptyBorder(15, 20, 20, 20));

        long maxMem = Runtime.getRuntime().maxMemory() / (1024 * 1024);
        long freeMem = Runtime.getRuntime().freeMemory() / (1024 * 1024);
        long usedMem = maxMem - freeMem;

        JLabel memLabel = new JLabel("JVM Memory: " + usedMem + "MB / " + maxMem + "MB");
        memLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        memLabel.setForeground(new Color(140, 155, 175));

        systemWidget.add(memLabel, BorderLayout.SOUTH);
        sidebar.add(systemWidget, BorderLayout.SOUTH);

        // --- Center Content Views ---
        dashboardPanel = new DashboardPanel(this);
        scannerPanel = new ScannerPanel(this);
        processPanel = new ProcessPanel(this);
        monitorPanel = new RealTimeMonitorPanel(this);
        quarantinePanel = new QuarantinePanel(this);
        signaturesPanel = new SignaturesPanel(this);
        attackPanel = new AttackCoveragePanel(this);
        logsPanel = new LogsPanel();

        mainContentPanel.add(dashboardPanel, "DASHBOARD");
        mainContentPanel.add(scannerPanel, "SCANNER");
        mainContentPanel.add(processPanel, "PROCESSES");
        mainContentPanel.add(monitorPanel, "GUARD");
        mainContentPanel.add(quarantinePanel, "QUARANTINE");
        mainContentPanel.add(signaturesPanel, "SIGNATURES");
        mainContentPanel.add(attackPanel, "ATTACK");
        mainContentPanel.add(logsPanel, "LOGS");

        rootPanel.add(sidebar, BorderLayout.WEST);
        rootPanel.add(mainContentPanel, BorderLayout.CENTER);

        setContentPane(rootPanel);
        highlightNavButton(navDashBtn);
    }

    private JButton createNavButton(String text, String cardName) {
        JButton btn = new JButton(text);
        btn.setFont(new Font("Segoe UI", Font.BOLD, 13));
        btn.setForeground(new Color(180, 195, 215));
        btn.setBackground(new Color(15, 17, 22));
        btn.setFocusPainted(false);
        btn.setHorizontalAlignment(SwingConstants.LEFT);
        btn.setBorder(new EmptyBorder(12, 16, 12, 16));
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));

        btn.addActionListener(e -> {
            cardLayout.show(mainContentPanel, cardName);
            highlightNavButton(btn);
            if ("PROCESSES".equals(cardName)) processPanel.refreshProcesses();
            if ("QUARANTINE".equals(cardName)) quarantinePanel.refreshTable();
            if ("SIGNATURES".equals(cardName)) signaturesPanel.refreshTable();
            if ("LOGS".equals(cardName)) logsPanel.refreshLogs();
        });

        return btn;
    }

    private void highlightNavButton(JButton selectedBtn) {
        for (JButton b : new JButton[]{navDashBtn, navScanBtn, navProcBtn, navGuardBtn, navQuarBtn, navSigBtn, navAttackBtn, navLogBtn}) {
            if (b == selectedBtn) {
                b.setBackground(new Color(30, 36, 48));
                b.setForeground(new Color(59, 130, 246));
            } else {
                b.setBackground(new Color(15, 17, 22));
                b.setForeground(new Color(180, 195, 215));
            }
        }
    }

    public void switchToScanTabAndStartQuick() {
        cardLayout.show(mainContentPanel, "SCANNER");
        highlightNavButton(navScanBtn);
        scannerPanel.startScan();
    }

    public void switchToScanTabWithFolder(File folder) {
        cardLayout.show(mainContentPanel, "SCANNER");
        highlightNavButton(navScanBtn);
        scannerPanel.setScanTargetAndStart(folder);
    }

    public void switchToProcessTab() {
        cardLayout.show(mainContentPanel, "PROCESSES");
        highlightNavButton(navProcBtn);
        processPanel.refreshProcesses();
    }

    public void switchToQuarantineTab() {
        cardLayout.show(mainContentPanel, "QUARANTINE");
        highlightNavButton(navQuarBtn);
        quarantinePanel.refreshTable();
    }

    public void updateDashboardStats() {
        if (dashboardPanel != null) {
            dashboardPanel.updateDashboardStats();
        }
    }
}
