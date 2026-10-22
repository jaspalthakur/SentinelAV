package com.sentinel.av.ui;

import com.sentinel.av.core.RealTimeMonitor;
import com.sentinel.av.model.ScanResult;
import com.sentinel.av.ui.components.CyberCard;
import com.sentinel.av.ui.components.CyberPalette;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.nio.file.Path;

public class ProtectionPanel extends JPanel implements RealTimeMonitor.MonitorEventListener {

    private final MainFrame mainFrame;
    private final RealTimeMonitor monitor;

    private JLabel statusTitle;
    private JLabel statusLabel;
    private JButton toggleBtn;
    private JPanel warningBanner;
    private DefaultListModel<String> watchedPathsModel;
    private DefaultListModel<String> eventsModel;

    public ProtectionPanel(MainFrame mainFrame) {
        this.mainFrame = mainFrame;
        this.monitor = RealTimeMonitor.getInstance();
        setLayout(new BorderLayout(16, 16));
        setBackground(CyberPalette.BACKGROUND);
        setBorder(new EmptyBorder(24, 24, 24, 24));

        initComponents();

        monitor.addListener(this);
        updateStatusUI(monitor.isRunning());
    }

    private void initComponents() {
        // --- Top Status & Toggle Banner ---
        CyberCard topCard = new CyberCard(CyberPalette.BORDER);

        JPanel statusTextPanel = new JPanel(new GridLayout(2, 1, 4, 4));
        statusTextPanel.setOpaque(false);

        statusTitle = new JLabel("Real-Time Protection Guard");
        statusTitle.setFont(CyberPalette.FONT_TITLE_LARGE);
        statusTitle.setForeground(CyberPalette.TEXT_PRIMARY);

        statusLabel = new JLabel("Status: Active · Monitoring file downloads and system activity");
        statusLabel.setFont(CyberPalette.FONT_BODY);
        statusLabel.setForeground(CyberPalette.TEXT_SECONDARY);

        statusTextPanel.add(statusTitle);
        statusTextPanel.add(statusLabel);

        toggleBtn = new JButton("Pause Protection");
        toggleBtn.setFont(CyberPalette.FONT_BODY_BOLD);
        toggleBtn.setFocusPainted(false);
        toggleBtn.setPreferredSize(new Dimension(160, 40));
        toggleBtn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        toggleBtn.addActionListener(e -> handleToggleClick());

        topCard.add(statusTextPanel, BorderLayout.CENTER);
        topCard.add(toggleBtn, BorderLayout.EAST);

        // Warning Banner when OFF
        warningBanner = new JPanel(new BorderLayout(10, 0));
        warningBanner.setBackground(new Color(55, 38, 15));
        warningBanner.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(CyberPalette.WARNING, 1),
            new EmptyBorder(10, 16, 10, 16)
        ));

        JLabel warnText = new JLabel("⚠️ Real-Time Protection is PAUSED. Downloads and new files are NOT being scanned!");
        warnText.setFont(CyberPalette.FONT_BODY_BOLD);
        warnText.setForeground(CyberPalette.WARNING);

        JButton resumeBtn = new JButton("Resume Protection");
        resumeBtn.setFont(CyberPalette.FONT_BODY_BOLD);
        resumeBtn.setBackground(CyberPalette.SAFE);
        resumeBtn.setForeground(Color.WHITE);
        resumeBtn.addActionListener(e -> monitor.startMonitoring());

        warningBanner.add(warnText, BorderLayout.CENTER);
        warningBanner.add(resumeBtn, BorderLayout.EAST);
        warningBanner.setVisible(false);

        JPanel topGroup = new JPanel(new BorderLayout(12, 12));
        topGroup.setOpaque(false);
        topGroup.add(topCard, BorderLayout.NORTH);
        topGroup.add(warningBanner, BorderLayout.SOUTH);

        // --- Center Split View: Monitored Folders + Live Event Log ---
        JPanel centerSplit = new JPanel(new GridLayout(1, 2, 16, 16));
        centerSplit.setOpaque(false);

        // Monitored Folders
        CyberCard watchedCard = new CyberCard(CyberPalette.BORDER);
        JLabel watchedTitle = new JLabel("Monitored Directories");
        watchedTitle.setFont(CyberPalette.FONT_TITLE_MEDIUM);
        watchedTitle.setForeground(CyberPalette.TEXT_PRIMARY);

        watchedPathsModel = new DefaultListModel<>();
        for (Path p : monitor.getWatchedPaths()) {
            watchedPathsModel.addElement(p.toString());
        }

        JList<String> watchedList = new JList<>(watchedPathsModel);
        watchedList.setBackground(new Color(15, 20, 34));
        watchedList.setForeground(CyberPalette.TEXT_PRIMARY);
        watchedList.setFont(CyberPalette.FONT_CODE);

        JScrollPane watchedScroll = new JScrollPane(watchedList);
        watchedScroll.setBorder(BorderFactory.createLineBorder(CyberPalette.BORDER));

        JButton addFolderBtn = new JButton("+ Add Directory");
        addFolderBtn.setFont(CyberPalette.FONT_BODY);
        addFolderBtn.setBackground(CyberPalette.SURFACE_HOVER);
        addFolderBtn.setForeground(CyberPalette.TEXT_PRIMARY);
        addFolderBtn.addActionListener(e -> addDirectoryToWatch());

        watchedCard.add(watchedTitle, BorderLayout.NORTH);
        watchedCard.add(watchedScroll, BorderLayout.CENTER);
        watchedCard.add(addFolderBtn, BorderLayout.SOUTH);

        // Live Activity Event Feed
        CyberCard eventsCard = new CyberCard(CyberPalette.BORDER);
        JLabel eventsTitle = new JLabel("Live File Intercept Feed");
        eventsTitle.setFont(CyberPalette.FONT_TITLE_MEDIUM);
        eventsTitle.setForeground(CyberPalette.TEXT_PRIMARY);

        eventsModel = new DefaultListModel<>();
        JList<String> eventsList = new JList<>(eventsModel);
        eventsList.setBackground(new Color(15, 20, 34));
        eventsList.setForeground(CyberPalette.TEXT_SECONDARY);
        eventsList.setFont(CyberPalette.FONT_CODE);

        JScrollPane eventsScroll = new JScrollPane(eventsList);
        eventsScroll.setBorder(BorderFactory.createLineBorder(CyberPalette.BORDER));

        eventsCard.add(eventsTitle, BorderLayout.NORTH);
        eventsCard.add(eventsScroll, BorderLayout.CENTER);

        centerSplit.add(watchedCard);
        centerSplit.add(eventsCard);

        add(topGroup, BorderLayout.NORTH);
        add(centerSplit, BorderLayout.CENTER);
    }

    private void handleToggleClick() {
        if (monitor.isRunning()) {
            String[] options = {"Pause for 15 minutes", "Pause for 1 hour", "Turn OFF until restart", "Cancel"};
            int res = JOptionPane.showOptionDialog(this,
                "Temporarily pause Real-Time Shield protection?",
                "Pause Protection Options",
                JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE, null, options, options[0]);

            if (res >= 0 && res <= 2) {
                monitor.stopMonitoring();
            }
        } else {
            monitor.startMonitoring();
        }
    }

    private void addDirectoryToWatch() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        int res = chooser.showOpenDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            Path selected = chooser.getSelectedFile().toPath();
            monitor.addWatchedDirectory(selected);
            if (!watchedPathsModel.contains(selected.toString())) {
                watchedPathsModel.addElement(selected.toString());
            }
        }
    }

    private void updateStatusUI(boolean isActive) {
        if (isActive) {
            statusTitle.setText("Real-Time Protection Active");
            statusTitle.setForeground(CyberPalette.SAFE);
            statusLabel.setText("Status: ACTIVE · Background file monitoring active in real time");
            toggleBtn.setText("Pause Protection");
            toggleBtn.setBackground(CyberPalette.SURFACE_HOVER);
            toggleBtn.setForeground(CyberPalette.TEXT_PRIMARY);
            warningBanner.setVisible(false);
        } else {
            statusTitle.setText("Real-Time Protection Paused");
            statusTitle.setForeground(CyberPalette.WARNING);
            statusLabel.setText("Status: PAUSED · System background file monitoring is currently off");
            toggleBtn.setText("Resume Protection");
            toggleBtn.setBackground(CyberPalette.SAFE);
            toggleBtn.setForeground(Color.WHITE);
            warningBanner.setVisible(true);
        }
    }

    @Override
    public void onFileDetected(Path path, String eventType) {
        SwingUtilities.invokeLater(() -> {
            eventsModel.addElement("[" + eventType + "] " + path.getFileName() + " (" + path.getParent() + ")");
            if (eventsModel.size() > 200) {
                eventsModel.remove(0);
            }
        });
    }

    @Override
    public void onThreatIntercepted(ScanResult result) {
        SwingUtilities.invokeLater(() -> {
            eventsModel.addElement("🚨 [THREAT INTERCEPTED] " + result.getThreatName() + " -> " + result.getFileName());
        });
    }

    @Override
    public void onMonitorStatusChanged(boolean isActive) {
        SwingUtilities.invokeLater(() -> updateStatusUI(isActive));
    }
}
