package com.sentinel.av.ui.components;

import javax.swing.*;
import java.awt.*;

public class SecurityGaugePanel extends JPanel {

    private int score = 100; // 0 to 100
    private String statusText = "SYSTEM PROTECTED";
    private Color arcColor = new Color(16, 185, 129); // Emerald Green

    public SecurityGaugePanel() {
        setPreferredSize(new Dimension(170, 170));
        setOpaque(false);
    }

    public void setSecurityScore(int score, String statusText) {
        this.score = Math.max(0, Math.min(100, score));
        this.statusText = statusText;

        if (this.score >= 90) {
            this.arcColor = new Color(16, 185, 129); // Emerald
        } else if (this.score >= 60) {
            this.arcColor = new Color(245, 158, 11); // Amber
        } else {
            this.arcColor = new Color(239, 68, 68); // Crimson Red
        }

        repaint();
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        int width = getWidth();
        int height = getHeight();
        int size = Math.min(width, height) - 20;
        int x = (width - size) / 2;
        int y = (height - size) / 2;

        int strokeWidth = 14;

        // Background Track Circle Arc (240 degrees arc)
        g2.setColor(new Color(40, 46, 58));
        g2.setStroke(new BasicStroke(strokeWidth, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        g2.drawArc(x + strokeWidth / 2, y + strokeWidth / 2, size - strokeWidth, size - strokeWidth, 150, -240);

        // Value Arc
        int fillAngle = (int) (-240.0 * (score / 100.0));
        g2.setColor(arcColor);
        g2.setStroke(new BasicStroke(strokeWidth, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        g2.drawArc(x + strokeWidth / 2, y + strokeWidth / 2, size - strokeWidth, size - strokeWidth, 150, fillAngle);

        // Center Score Text
        g2.setFont(new Font("Segoe UI", Font.BOLD, 32));
        g2.setColor(Color.WHITE);
        String scoreStr = score + "%";
        FontMetrics fm = g2.getFontMetrics();
        int scoreX = (width - fm.stringWidth(scoreStr)) / 2;
        int scoreY = (height / 2) + 6;
        g2.drawString(scoreStr, scoreX, scoreY);

        // Subtext
        g2.setFont(new Font("Segoe UI", Font.BOLD, 10));
        g2.setColor(new Color(160, 175, 195));
        FontMetrics fm2 = g2.getFontMetrics();
        int subX = (width - fm2.stringWidth("HEALTH INDEX")) / 2;
        g2.drawString("HEALTH INDEX", subX, scoreY + 22);

        g2.dispose();
    }
}
