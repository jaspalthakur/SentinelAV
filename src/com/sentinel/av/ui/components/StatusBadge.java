package com.sentinel.av.ui.components;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

public class StatusBadge extends JLabel {

    public StatusBadge(String text, Color bg, Color fg) {
        super(text, SwingConstants.CENTER);
        setOpaque(true);
        setBackground(bg);
        setForeground(fg);
        setFont(new Font("Segoe UI", Font.BOLD, 11));
        setBorder(new EmptyBorder(4, 10, 4, 10));
    }

    public static StatusBadge createSeverityBadge(String severityStr) {
        if (severityStr == null) return new StatusBadge("LOW", new Color(40, 70, 40), new Color(140, 220, 140));
        switch (severityStr.toUpperCase()) {
            case "CRITICAL":
                return new StatusBadge("CRITICAL", new Color(100, 20, 20), new Color(255, 120, 120));
            case "HIGH":
                return new StatusBadge("HIGH", new Color(90, 45, 15), new Color(255, 170, 90));
            case "MEDIUM":
                return new StatusBadge("MEDIUM", new Color(80, 80, 20), new Color(255, 235, 120));
            default:
                return new StatusBadge("LOW", new Color(30, 60, 80), new Color(130, 200, 255));
        }
    }

    public static StatusBadge createStatusBadge(String statusStr) {
        switch (statusStr.toUpperCase()) {
            case "CLEAN":
                return new StatusBadge("CLEAN", new Color(20, 70, 40), new Color(120, 230, 150));
            case "INFECTED":
                return new StatusBadge("INFECTED", new Color(100, 20, 20), new Color(255, 120, 120));
            case "QUARANTINED":
                return new StatusBadge("QUARANTINED", new Color(80, 50, 120), new Color(210, 160, 255));
            case "DELETED":
                return new StatusBadge("DELETED", new Color(60, 60, 60), new Color(180, 180, 180));
            default:
                return new StatusBadge(statusStr, new Color(40, 40, 50), Color.WHITE);
        }
    }
}
