package com.sentinel.av.ui;

import com.sentinel.av.Version;
import com.sentinel.av.core.ActivityLogger;
import com.sentinel.av.core.QuarantineManager;
import com.sentinel.av.core.RealTimeMonitor;
import com.sentinel.av.core.canary.RansomwareCanaryGuard;
import com.sentinel.av.ui.components.CyberPalette;
import com.sentinel.av.ui.components.IconUtils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.util.LinkedHashMap;
import java.util.Map;

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

    /** cardName -> navigation button, used by highlight + shortcuts. */
    private final Map<String, JButton> navButtons = new LinkedHashMap<>();

    private JLabel statusShieldLabel;
    private JLabel statusGuardLabel;
    private JLabel statusQuarantineLabel;
    private JLabel statusMemoryLabel;

    public MainFrame() {
        setTitle("SentinelAV — Cyber Security, EDR & Threat Intelligence Suite");
        setIconImage(IconUtils.createAppIcon(64));
        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                confirmExit();
            }
        });
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
        rootPanel.setBackground(CyberPalette.BACKGROUND);

        // --- Left Sidebar Navigation ---
        JPanel sidebar = new JPanel(new BorderLayout());
        sidebar.setPreferredSize(new Dimension(250, 0));
        sidebar.setBackground(new Color(15, 17, 22));
        sidebar.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, new Color(40, 46, 58)));

        // App Brand Header
        JPanel brandPanel = new JPanel(new BorderLayout(12, 5));
        brandPanel.setOpaque(false);
        brandPanel.setBorder(new javax.swing.border.EmptyBorder(25, 20, 25, 20));

        JLabel brandIcon = new JLabel("🛡️");
        brandIcon.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 32));

        JLabel brandTitle = new JLabel("SENTINEL AV");
        brandTitle.setFont(new Font("Segoe UI", Font.BOLD, 19));
        brandTitle.setForeground(Color.WHITE);

        JLabel brandSub = new JLabel("v" + Version.VERSION + " EDR & Threat Engine");
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
        navMenu.setBorder(new javax.swing.border.EmptyBorder(10, 12, 10, 12));

        navDashBtn = createNavButton("📊  Dashboard Overview", "DASHBOARD");
        navScanBtn = createNavButton("🔍  Malware Scanner", "SCANNER");
        navProcBtn = createNavButton("⚙️  Process Inspector", "PROCESSES");
        navGuardBtn = createNavButton("📡  Real-Time Guard", "GUARD");
        navQuarBtn = createNavButton("🔒  Quarantine Vault", "QUARANTINE");
        navSigBtn = createNavButton("🧬  YARA & Definitions", "SIGNATURES");
        navAttackBtn = createNavButton("🎯  MITRE ATT&CK Matrix", "ATTACK");
        navLogBtn = createNavButton("📜  Security Audit Logs", "LOGS");

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
        rootPanel.add(buildStatusBar(), BorderLayout.SOUTH);

        setContentPane(rootPanel);
        registerNavShortcuts();
        selectSection("DASHBOARD");
        refreshStatusBar();

        // Keep the footer status live.
        new Timer(2000, e -> refreshStatusBar()).start();
    }

    // ------------------------------------------------------------ navigation

    private JButton createNavButton(String text, String cardName) {
        JButton btn = new JButton(text);
        btn.setFont(new Font("Segoe UI", Font.BOLD, 13));
        btn.setForeground(new Color(180, 195, 215));
        btn.setBackground(new Color(15, 17, 22));
        btn.setFocusPainted(false);
        btn.setHorizontalAlignment(SwingConstants.LEFT);
        btn.setBorder(new javax.swing.border.EmptyBorder(12, 16, 12, 16));
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        btn.addActionListener(e -> selectSection(cardName));
        navButtons.put(cardName, btn);
        return btn;
    }

    /** Switches the center view, highlights its nav entry and refreshes live data. */
    private void selectSection(String cardName) {
        cardLayout.show(mainContentPanel, cardName);
        highlightNavButton(navButtons.get(cardName));

        switch (cardName) {
            case "PROCESSES" -> processPanel.refreshProcesses();
            case "QUARANTINE" -> quarantinePanel.refreshTable();
            case "SIGNATURES" -> signaturesPanel.refreshTable();
            case "LOGS" -> logsPanel.refreshLogs();
            case "GUARD" -> refreshStatusBar();
        }
    }

    private void highlightNavButton(JButton selectedBtn) {
        for (JButton b : navButtons.values()) {
            if (b == selectedBtn) {
                b.setBackground(new Color(30, 36, 48));
                b.setForeground(new Color(59, 130, 246));
            } else {
                b.setBackground(new Color(15, 17, 22));
                b.setForeground(new Color(180, 195, 215));
            }
        }
    }

    /** Ctrl+1..8 (Win/Linux) / Cmd+1..8 (macOS) jump straight to a section. */
    private void registerNavShortcuts() {
        JRootPane rootPane = getRootPane();
        int mask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        int digit = KeyEvent.VK_1;
        for (String cardName : navButtons.keySet()) {
            String id = "NAV-" + cardName;
            rootPane.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                    .put(KeyStroke.getKeyStroke(digit, mask), id);
            rootPane.getActionMap().put(id, new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    selectSection(cardName);
                }
            });
            digit++;
        }
    }

    // ------------------------------------------------------------- status bar

    private JPanel buildStatusBar() {
        JPanel statusBar = new JPanel(new BorderLayout(20, 0));
        statusBar.setBackground(new Color(15, 17, 22));
        statusBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, new Color(40, 46, 58)),
                new javax.swing.border.EmptyBorder(6, 16, 6, 16)));

        statusShieldLabel = new JLabel();
        statusGuardLabel = new JLabel();
        statusQuarantineLabel = new JLabel();
        statusMemoryLabel = new JLabel();

        JPanel leftGroup = new JPanel(new FlowLayout(FlowLayout.LEFT, 18, 0));
        leftGroup.setOpaque(false);
        leftGroup.add(statusShieldLabel);
        leftGroup.add(statusGuardLabel);
        leftGroup.add(statusQuarantineLabel);
        statusBar.add(leftGroup, BorderLayout.WEST);
        statusBar.add(statusMemoryLabel, BorderLayout.EAST);
        return statusBar;
    }

    private void refreshStatusBar() {
        boolean shield = RealTimeMonitor.getInstance().isRunning();
        boolean canary = RansomwareCanaryGuard.getInstance().isActive();
        long maxMem = Runtime.getRuntime().maxMemory() / (1024 * 1024);
        long usedMem = (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / (1024 * 1024);

        statusShieldLabel.setText(shield ? "🛡 Shield: ACTIVE" : "🛡 Shield: OFF");
        statusShieldLabel.setForeground(shield ? new Color(110, 230, 150) : new Color(255, 170, 80));
        statusGuardLabel.setText(canary ? "🦆 Tripwire: ARMED" : "🦆 Tripwire: DISARMED");
        statusGuardLabel.setForeground(canary
                ? new Color(160, 175, 195) : new Color(255, 170, 80));
        statusQuarantineLabel.setText("🔒 Vault: " + QuarantineManager.getInstance().getQuarantineCount());
        statusQuarantineLabel.setForeground(new Color(160, 175, 195));
        statusMemoryLabel.setText(usedMem + " MB / " + maxMem + " MB");
        statusMemoryLabel.setForeground(new Color(140, 155, 175));
    }

    // ----------------------------------------------------------------- exit

    /** Warns the user before tearing down any live protection. */
    private void confirmExit() {
        boolean shieldActive = RealTimeMonitor.getInstance().isRunning();

        Object[] options = {"Exit", "Cancel"};
        String message = shieldActive
                ? "The real-time shield and ransomware tripwire will stop.\nExit SentinelAV?"
                : "Exit SentinelAV?";
        int confirm = JOptionPane.showOptionDialog(this, message, "Exit SentinelAV",
                JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE, null, options, options[1]);

        if (confirm == 0) {
            RealTimeMonitor.getInstance().stopMonitoring();
            RansomwareCanaryGuard.getInstance().removeCanaries();
            ActivityLogger.getInstance().flush();
            dispose();
            System.exit(0);
        }
    }

    // ------------------------------------------------------------ public API

    public void switchToScanTabAndStartQuick() {
        selectSection("SCANNER");
        scannerPanel.startScan();
    }

    public void switchToScanTabWithFolder(File folder) {
        selectSection("SCANNER");
        scannerPanel.setScanTargetAndStart(folder);
    }

    public void switchToProcessTab() {
        selectSection("PROCESSES");
    }

    public void switchToQuarantineTab() {
        selectSection("QUARANTINE");
    }

    public void updateDashboardStats() {
        if (dashboardPanel != null) {
            dashboardPanel.updateDashboardStats();
        }
        refreshStatusBar();
    }
}
