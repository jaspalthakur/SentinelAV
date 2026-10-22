package com.sentinel.av.ui.components;

import com.sentinel.av.core.ActivityTracker;

import javax.swing.*;
import java.awt.*;
import java.util.Map;

public class AnalyticsChartPanel extends JPanel {

    public AnalyticsChartPanel() {
        setOpaque(false);
        setPreferredSize(new Dimension(340, 180));
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        int width = getWidth();
        int height = getHeight();

        ActivityTracker tracker = ActivityTracker.getInstance();
        Map<String, Integer> scansMap = tracker.getDailyScansMap();
        Map<String, Integer> threatsMap = tracker.getDailyThreatsMap();

        int totalActivity = tracker.getTotalFilesScanned();

        // Empty state when no activity recorded
        if (totalActivity == 0) {
            g2.setColor(CyberPalette.TEXT_MUTED);
            g2.setFont(CyberPalette.FONT_BODY);
            String emptyMsg = "No scan activity recorded yet. Run your first scan!";
            FontMetrics fm = g2.getFontMetrics();
            int x = (width - fm.stringWidth(emptyMsg)) / 2;
            int y = height / 2;
            g2.drawString(emptyMsg, x, y);

            // Subtle dashed box
            g2.setStroke(new BasicStroke(1.0f, BasicStroke.CAP_BUTT, BasicStroke.JOIN_MITER, 10.0f, new float[]{4.0f}, 0.0f));
            g2.drawRoundRect(20, 20, width - 40, height - 40, 10, 10);
            g2.dispose();
            return;
        }

        int padding = 30;
        int chartW = width - (padding * 2);
        int chartH = height - (padding * 2) - 20;

        // Draw Axes Lines
        g2.setColor(CyberPalette.BORDER);
        g2.setStroke(new BasicStroke(1.0f));
        g2.drawLine(padding, height - padding - 20, width - padding, height - padding - 20);

        String[] days = scansMap.keySet().toArray(new String[0]);
        int maxScan = 1;
        for (int val : scansMap.values()) {
            if (val > maxScan) maxScan = val;
        }

        int barWidth = Math.max(14, (chartW / days.length) - 16);

        for (int i = 0; i < days.length; i++) {
            String day = days[i];
            int scanVal = scansMap.getOrDefault(day, 0);
            int threatVal = threatsMap.getOrDefault(day, 0);

            int x = padding + (i * (chartW / days.length)) + 10;
            int h = (int) (((double) scanVal / maxScan) * chartH);
            int y = height - padding - 20 - h;

            if (h > 0) {
                GradientPaint gp = new GradientPaint(x, y, CyberPalette.ACCENT, x, y + h, new Color(29, 78, 216));
                g2.setPaint(gp);
                g2.fillRoundRect(x, y, barWidth, h, 4, 4);
            }

            if (threatVal > 0) {
                g2.setColor(CyberPalette.THREAT);
                g2.fillOval(x + (barWidth / 2) - 4, y - 10, 8, 8);
            }

            g2.setFont(CyberPalette.FONT_SMALL);
            g2.setColor(CyberPalette.TEXT_SECONDARY);
            g2.drawString(day, x + (barWidth / 2) - 10, height - padding + 2);
        }

        // Legend
        g2.setColor(CyberPalette.ACCENT);
        g2.fillRoundRect(width - 150, 10, 10, 10, 2, 2);
        g2.setColor(CyberPalette.TEXT_SECONDARY);
        g2.setFont(CyberPalette.FONT_SMALL);
        g2.drawString("Files Checked", width - 135, 19);

        g2.dispose();
    }
}
