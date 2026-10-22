package com.sentinel.av.ui;

import com.sentinel.av.core.RealTimeMonitor;
import com.sentinel.av.model.ScanResult;
import com.sentinel.av.ui.components.CyberButton;
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
    private CyberButton toggleBtn;
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

        statusLabel = new JLabel("Status: Active \u2022 Monitoring file downloads and system activity");
        statusLabel.setFont(CyberPalette.FONT_BODY);
        statusLabel.setForeground(CyberPalette.TEXT_SECONDARY);

        statusTextPanel.add(statusTitle);
        statusTextPanel.add(statusLabel);

        toggleBtn = new CyberButton("Pause Protection", CyberButton.SECONDARY);
        toggleBtn.setFont(CyberPalette.FONT_BODY_BOLD);
        toggleBtn.setPreferredSize(new Dimension(160, 40));
        toggleBtn.addActionListener(e -> handleToggleClick());

        topCard.add(statusTextPanel, BorderLayout.CENTER);
        topCard.add(toggleBtn, BorderLayout.EAST);

        // Warning Banner when OFF
        warningBanner = new JPanel(new BorderLayout(10, 0));
        warningBanner.setBackground(CyberPalette.WARNING_BG);
        warningBanner.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(CyberPalette.WARNING, 1),
            new EmptyBorder(10, 16, 10, 16)));

        JLabel warnText = new JLabel("\u26A0  Real-Time Protection is PAUSED. Downloads and new files are NOT being scanned!");
        warnText.setFont(CyberPalette.FONT_BODY_BOLD);
        warnText.setForeground(CyberPalette.WARNING);

        CyberButton resumeBtn = new CyberButton("Resume Protection", CyberButton.PRIMARY);
        resumeBtn.setFont(CyberPalette.FONT_BODY_BOLD);
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
        watchedCard.setHoverEnabled(true);

        JLabel watchedTitle = new JLabel("Monitored Directories");
        watchedTitle.setFont(CyberPalette.FONT_TITLE_SMALL);
        watchedTitle.setForeground(CyberPalette.TEXT_PRIMARY);

        watchedPathsModel = new DefaultListModel<>();
        for (Path p : monitor.getWatchedPaths()) {
            watchedPathsModel.addElement(p.toString());
        }

        JList<String> watchedList = new JList<>(watchedPathsModel);
        watchedList.setBackground(CyberPalette.BACKGROUND);
        watchedList.setForeground(CyberPalette.TEXT_PRIMARY);
        watchedList.setFont(CyberPalette.FONT_CODE);

        JScrollPane watchedScroll = new JScrollPane(watchedList);
        watchedScroll.setBorder(BorderFactory.createLineBorder(CyberPalette.BORDER));

        CyberButton addFolderBtn = new CyberButton("+ Add Directory", CyberButton.SECONDARY);
        addFolderBtn.setFont(CyberPalette.FONT_SMALL);
        addFolderBtn.addActionListener(e -> addDirectoryToWatch());

        watchedCard.add(watchedTitle, BorderLayout.NORTH);
        watchedCard.add(watchedScroll, BorderLayout.CENTER);
        watchedCard.add(addFolderBtn, BorderLayout.SOUTH);

        // Live Activity Event Feed
        CyberCard eventsCard = new CyberCard(CyberPalette.BORDER);
        eventsCard.setHoverEnabled(true);

        JLabel eventsTitle = new JLabel("Live File Intercept Feed");
        eventsTitle.setFont(CyberPalette.FONT_TITLE_SMALL);
        eventsTitle.setForeground(CyberPalette.TEXT_PRIMARY);

        eventsModel = new DefaultListModel<>();
        JList<String> eventsList = new JList<>(eventsModel);
        eventsList.setBackground(CyberPalette.BACKGROUND);
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
            statusLabel.setText("Status: ACTIVE \u2022 Background file monitoring active in real time");
            toggleBtn.setText("Pause Protection");
            toggleBtn.setVariant(CyberButton.SECONDARY);
            warningBanner.setVisible(false);
        } else {
            statusTitle.setText("Real-Time Protection Paused");
            statusTitle.setForeground(CyberPalette.WARNING);
            statusLabel.setText("Status: PAUSED \u2022 System background file monitoring is currently off");
            toggleBtn.setText("Resume Protection");
            toggleBtn.setVariant(CyberButton.PRIMARY);
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
            eventsModel.addElement("\uD83D\uDEA8 [THREAT INTERCEPTED] " + result.getThreatName()
                    + " -> " + result.getFileName());
        });
    }

    @Override
    public void onMonitorStatusChanged(boolean isActive) {
        SwingUtilities.invokeLater(() -> updateStatusUI(isActive));
    }
}
