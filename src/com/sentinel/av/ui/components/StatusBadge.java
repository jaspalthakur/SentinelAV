package com.sentinel.av.ui.components;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * Small pill-shaped badge communicating a status or severity at a glance.
 *
 * <p>Badges use {@link CyberPalette} semantic colors so risk levels are
 * communicated consistently across the app.</p>
 */
public class StatusBadge extends JLabel {

    public StatusBadge(String text, Color bg, Color fg) {
        super(text, SwingConstants.CENTER);
        setOpaque(true);
        setBackground(bg);
        setForeground(fg);
        setFont(new Font("Segoe UI", Font.BOLD, 11));
        setBorder(new EmptyBorder(3, 10, 3, 10));
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        int w = getWidth();
        int h = getHeight();
        g2.setColor(getBackground());
        g2.fillRoundRect(0, 0, w - 1, h - 1, h, h); // fully pill-shaped
        g2.dispose();
        super.paintComponent(g);
    }

    public static StatusBadge createSeverityBadge(String severityStr) {
        if (severityStr == null) {
            return new StatusBadge("LOW", CyberPalette.SAFE_BG, new Color(140, 220, 140));
        }
        switch (severityStr.toUpperCase()) {
            case "CRITICAL":
                return new StatusBadge("CRITICAL", CyberPalette.THREAT_BG, new Color(255, 120, 120));
            case "HIGH":
                return new StatusBadge("HIGH", new Color(90, 45, 15), new Color(255, 170, 90));
            case "MEDIUM":
                return new StatusBadge("MEDIUM", new Color(80, 80, 20), new Color(255, 235, 120));
            default:
                return new StatusBadge("LOW", CyberPalette.SAFE_BG, new Color(140, 220, 140));
        }
    }

    public static StatusBadge createStatusBadge(String statusStr) {
        switch (statusStr.toUpperCase()) {
            case "CLEAN":
                return new StatusBadge("CLEAN", CyberPalette.SAFE_BG, new Color(120, 230, 150));
            case "INFECTED":
                return new StatusBadge("INFECTED", CyberPalette.THREAT_BG, new Color(255, 120, 120));
            case "QUARANTINED":
                return new StatusBadge("QUARANTINED", CyberPalette.PURPLE_BG, new Color(210, 160, 255));
            case "DELETED":
                return new StatusBadge("DELETED", new Color(45, 45, 55), new Color(180, 180, 180));
            default:
                return new StatusBadge(statusStr, CyberPalette.INPUT_BG, Color.WHITE);
        }
    }
}
