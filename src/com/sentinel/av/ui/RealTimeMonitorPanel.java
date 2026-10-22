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

public class RealTimeMonitorPanel extends JPanel implements RealTimeMonitor.MonitorEventListener {

    private final MainFrame mainFrame;
    private final RealTimeMonitor monitor;

    private JLabel statusLabel;
    private CyberButton toggleBtn;
    private DefaultListModel<String> watchedPathsModel;
    private DefaultListModel<String> eventsModel;

    public RealTimeMonitorPanel(MainFrame mainFrame) {
        this.mainFrame = mainFrame;
        this.monitor = RealTimeMonitor.getInstance();
        setLayout(new BorderLayout(15, 15));
        setBackground(CyberPalette.BACKGROUND);
        setBorder(new EmptyBorder(25, 25, 25, 25));

        initComponents();

        monitor.addListener(this);
        updateStatusUI(monitor.isRunning());
    }

    private void initComponents() {
        // --- Top Status & Toggle Banner ---
        CyberCard topCard = new CyberCard(CyberPalette.BORDER);

        JPanel statusTextPanel = new JPanel(new GridLayout(2, 1, 4, 4));
        statusTextPanel.setOpaque(false);

        JLabel titleLabel = new JLabel("\uD83D\uDEA1  Real-Time System Shield & File Watcher");
        titleLabel.setFont(CyberPalette.FONT_TITLE_SMALL);
        titleLabel.setForeground(CyberPalette.TEXT_PRIMARY);

        statusLabel = new JLabel("Status: Unknown");
        statusLabel.setFont(CyberPalette.FONT_SMALL);
        statusLabel.setForeground(CyberPalette.TEXT_SECONDARY);

        statusTextPanel.add(titleLabel);
        statusTextPanel.add(statusLabel);

        toggleBtn = new CyberButton("Turn OFF Shield", CyberButton.DANGER);
        toggleBtn.setFont(CyberPalette.FONT_BODY_BOLD);
        toggleBtn.addActionListener(e -> {
            if (monitor.isRunning()) {
                monitor.stopMonitoring();
            } else {
                monitor.startMonitoring();
            }
        });

        topCard.add(statusTextPanel, BorderLayout.CENTER);
        topCard.add(toggleBtn, BorderLayout.EAST);

        // --- Center Split View: Watched Directories + Live Intercept Feed ---
        JPanel centerSplit = new JPanel(new GridLayout(1, 2, 20, 20));
        centerSplit.setOpaque(false);

        // Left Panel: Watched Directories
        CyberCard watchedCard = new CyberCard(CyberPalette.BORDER);

        JLabel watchedTitle = new JLabel("\uD83D\uDCC1  Monitored Directories");
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

        CyberButton addFolderBtn = new CyberButton("\u2795  Add Directory to Watch", CyberButton.SECONDARY);
        addFolderBtn.setFont(CyberPalette.FONT_SMALL);
        addFolderBtn.addActionListener(e -> addDirectoryToWatch());

        watchedCard.add(watchedTitle, BorderLayout.NORTH);
        watchedCard.add(watchedScroll, BorderLayout.CENTER);
        watchedCard.add(addFolderBtn, BorderLayout.SOUTH);

        // Right Panel: Live Activity Event Stream
        CyberCard eventsCard = new CyberCard(CyberPalette.BORDER);

        JLabel eventsTitle = new JLabel("\u26A1  Live Intercepted File Stream");
        eventsTitle.setFont(CyberPalette.FONT_TITLE_SMALL);
        eventsTitle.setForeground(CyberPalette.TEXT_PRIMARY);

        eventsModel = new DefaultListModel<>();
        JList<String> eventsList = new JList<>(eventsModel);
        eventsList.setBackground(CyberPalette.BACKGROUND);
        eventsList.setForeground(CyberPalette.SAFE);
        eventsList.setFont(CyberPalette.FONT_CODE);

        JScrollPane eventsScroll = new JScrollPane(eventsList);
        eventsScroll.setBorder(BorderFactory.createLineBorder(CyberPalette.BORDER));

        eventsCard.add(eventsTitle, BorderLayout.NORTH);
        eventsCard.add(eventsScroll, BorderLayout.CENTER);

        centerSplit.add(watchedCard);
        centerSplit.add(eventsCard);

        add(topCard, BorderLayout.NORTH);
        add(centerSplit, BorderLayout.CENTER);
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
            statusLabel.setText("Status: ACTIVE \u2014 Continuously monitoring file system changes in real time.");
            statusLabel.setForeground(CyberPalette.SAFE);
            toggleBtn.setText("Turn OFF Shield");
            toggleBtn.setVariant(CyberButton.DANGER);
        } else {
            statusLabel.setText("Status: INACTIVE \u2014 Background file monitoring is currently turned off.");
            statusLabel.setForeground(CyberPalette.WARNING);
            toggleBtn.setText("Turn ON Shield");
            toggleBtn.setVariant(CyberButton.PRIMARY);
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
