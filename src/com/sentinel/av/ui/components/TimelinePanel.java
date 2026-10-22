package com.sentinel.av.ui.components;

import com.sentinel.av.core.ActivityLogger;
import com.sentinel.av.model.ActivityLog;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.List;

public class TimelinePanel extends JPanel implements ActivityLogger.LogListener {

    private final JPanel listContainer;

    public TimelinePanel() {
        setLayout(new BorderLayout());
        setOpaque(false);

        listContainer = new JPanel();
        listContainer.setLayout(new BoxLayout(listContainer, BoxLayout.Y_AXIS));
        listContainer.setOpaque(false);

        JScrollPane scrollPane = new JScrollPane(listContainer);
        scrollPane.setOpaque(false);
        scrollPane.getViewport().setOpaque(false);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

        add(scrollPane, BorderLayout.CENTER);

        ActivityLogger.getInstance().addListener(this);
        refreshFeed();
    }

    public void refreshFeed() {
        listContainer.removeAll();
        List<ActivityLog> logs = ActivityLogger.getInstance().getLogs();

        if (logs.isEmpty()) {
            JLabel emptyLabel = new JLabel("No security activity recorded yet.", SwingConstants.CENTER);
            emptyLabel.setFont(CyberPalette.FONT_BODY);
            emptyLabel.setForeground(CyberPalette.TEXT_MUTED);
            emptyLabel.setBorder(new EmptyBorder(30, 10, 30, 10));
            listContainer.add(emptyLabel);
        } else {
            // Show last 30 logs in reverse chronological order
            int count = 0;
            for (int i = logs.size() - 1; i >= 0 && count < 30; i--) {
                ActivityLog log = logs.get(i);
                listContainer.add(createTimelineItem(log));
                listContainer.add(Box.createRigidArea(new Dimension(0, 6)));
                count++;
            }
        }

        listContainer.revalidate();
        listContainer.repaint();
    }

    private JPanel createTimelineItem(ActivityLog log) {
        JPanel item = new JPanel(new BorderLayout(10, 2));
        item.setOpaque(false);
        item.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, CyberPalette.BORDER),
            new EmptyBorder(6, 4, 6, 4)
        ));

        // Severity Dot
        Color dotColor;
        switch (log.getLevel()) {
            case THREAT_DETECTED:
                dotColor = CyberPalette.THREAT;
                break;
            case QUARANTINE:
            case WARNING:
                dotColor = CyberPalette.WARNING;
                break;
            case SYSTEM:
                dotColor = CyberPalette.SAFE;
                break;
            default:
                dotColor = CyberPalette.ACCENT;
                break;
        }

        JLabel dotLabel = new JLabel("●");
        dotLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        dotLabel.setForeground(dotColor);

        // Header: Relative Time + Category
        String timeStr = log.getTimestamp().length() > 11 ? log.getTimestamp().substring(11) : log.getTimestamp();
        JLabel headerLabel = new JLabel("[" + timeStr + "] " + log.getCategory());
        headerLabel.setFont(CyberPalette.FONT_BODY_BOLD);
        headerLabel.setForeground(CyberPalette.TEXT_PRIMARY);

        // Message text area (word wrapped!)
        JTextArea msgArea = new JTextArea(log.getMessage());
        msgArea.setFont(CyberPalette.FONT_BODY);
        msgArea.setForeground(CyberPalette.TEXT_SECONDARY);
        msgArea.setLineWrap(true);
        msgArea.setWrapStyleWord(true);
        msgArea.setOpaque(false);
        msgArea.setEditable(false);
        msgArea.setBorder(null);

        JPanel content = new JPanel(new BorderLayout(2, 2));
        content.setOpaque(false);
        content.add(headerLabel, BorderLayout.NORTH);
        content.add(msgArea, BorderLayout.CENTER);

        item.add(dotLabel, BorderLayout.WEST);
        item.add(content, BorderLayout.CENTER);

        return item;
    }

    @Override
    public void onLogAdded(ActivityLog log) {
        SwingUtilities.invokeLater(this::refreshFeed);
    }
}
