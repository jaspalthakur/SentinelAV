package com.sentinel.av.ui;

import com.sentinel.av.core.RealTimeMonitor;
import com.sentinel.av.model.ScanResult;
import com.sentinel.av.ui.components.CyberPalette;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.nio.file.Path;
import java.nio.file.Paths;

public class RealTimeMonitorPanel extends JPanel implements RealTimeMonitor.MonitorEventListener {

    private final MainFrame mainFrame;
    private final RealTimeMonitor monitor;

    private JLabel statusLabel;
    private JButton toggleBtn;
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
        JPanel topCard = new JPanel(new BorderLayout(15, 15));
        topCard.setBackground(CyberPalette.SURFACE);
        topCard.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(CyberPalette.BORDER, 1),
            new EmptyBorder(20, 25, 20, 25)
        ));

        JPanel statusTextPanel = new JPanel(new GridLayout(2, 1, 4, 4));
        statusTextPanel.setOpaque(false);

        JLabel titleLabel = new JLabel("🛡️ Real-Time System Shield & File Watcher");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 18));
        titleLabel.setForeground(Color.WHITE);

        statusLabel = new JLabel("Status: Unknown");
        statusLabel.setFont(new Font("Segoe UI", Font.PLAIN, 13));

        statusTextPanel.add(titleLabel);
        statusTextPanel.add(statusLabel);

        toggleBtn = new JButton("Toggle Shield");
        toggleBtn.setFont(new Font("Segoe UI", Font.BOLD, 14));
        toggleBtn.setFocusPainted(false);
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
        JPanel watchedCard = new JPanel(new BorderLayout(10, 10));
        watchedCard.setBackground(CyberPalette.SURFACE);
        watchedCard.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(CyberPalette.BORDER, 1),
            new EmptyBorder(15, 20, 15, 20)
        ));

        JLabel watchedTitle = new JLabel("📁 Monitored Directories");
        watchedTitle.setFont(new Font("Segoe UI", Font.BOLD, 15));
        watchedTitle.setForeground(Color.WHITE);

        watchedPathsModel = new DefaultListModel<>();
        for (Path p : monitor.getWatchedPaths()) {
            watchedPathsModel.addElement(p.toString());
        }

        JList<String> watchedList = new JList<>(watchedPathsModel);
        watchedList.setBackground(CyberPalette.BACKGROUND);
        watchedList.setForeground(CyberPalette.TEXT_PRIMARY);
        watchedList.setFont(new Font("Consolas", Font.PLAIN, 12));

        JScrollPane watchedScroll = new JScrollPane(watchedList);
        watchedScroll.setBorder(BorderFactory.createLineBorder(CyberPalette.BORDER));

        JButton addFolderBtn = new JButton("➕ Add Directory to Watch");
        addFolderBtn.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        addFolderBtn.setBackground(new Color(45, 55, 70));
        addFolderBtn.setForeground(Color.WHITE);
        addFolderBtn.addActionListener(e -> addDirectoryToWatch());

        watchedCard.add(watchedTitle, BorderLayout.NORTH);
        watchedCard.add(watchedScroll, BorderLayout.CENTER);
        watchedCard.add(addFolderBtn, BorderLayout.SOUTH);

        // Right Panel: Live Activity Event Stream
        JPanel eventsCard = new JPanel(new BorderLayout(10, 10));
        eventsCard.setBackground(CyberPalette.SURFACE);
        eventsCard.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(CyberPalette.BORDER, 1),
            new EmptyBorder(15, 20, 15, 20)
        ));

        JLabel eventsTitle = new JLabel("⚡ Live Intercepted File Stream");
        eventsTitle.setFont(new Font("Segoe UI", Font.BOLD, 15));
        eventsTitle.setForeground(Color.WHITE);

        eventsModel = new DefaultListModel<>();
        JList<String> eventsList = new JList<>(eventsModel);
        eventsList.setBackground(CyberPalette.BACKGROUND);
        eventsList.setForeground(new Color(180, 230, 190));
        eventsList.setFont(new Font("Consolas", Font.PLAIN, 12));

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
            statusLabel.setText("Status: ACTIVE — Continuously monitoring file system changes in real time.");
            statusLabel.setForeground(new Color(120, 230, 150));
            toggleBtn.setText("Turn OFF Shield");
            toggleBtn.setBackground(new Color(170, 50, 50));
            toggleBtn.setForeground(Color.WHITE);
        } else {
            statusLabel.setText("Status: INACTIVE — Background file monitoring is currently turned off.");
            statusLabel.setForeground(new Color(255, 170, 80));
            toggleBtn.setText("Turn ON Shield");
            toggleBtn.setBackground(new Color(40, 140, 75));
            toggleBtn.setForeground(Color.WHITE);
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
            eventsModel.addElement("🚨 [INTERCEPTED THREAT] " + result.getThreatName() + " -> " + result.getFileName());
            JOptionPane.showMessageDialog(this,
                "🚨 REAL-TIME SHIELD INTERCEPTED A MALWARE THREAT!\n\nThreat: " + result.getThreatName() +
                "\nFile: " + result.getFileName() +
                "\n\nThe file has been automatically isolated in Quarantine Vault.",
                "Real-Time Threat Intercepted",
                JOptionPane.WARNING_MESSAGE);
        });
    }

    @Override
    public void onMonitorStatusChanged(boolean isActive) {
        SwingUtilities.invokeLater(() -> updateStatusUI(isActive));
    }
}
