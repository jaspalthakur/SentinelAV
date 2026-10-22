package com.sentinel.av.ui.components;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

public class CyberCard extends JPanel {

    private final Color borderColor;
    private final Color bgColorTop;
    private final Color bgColorBottom;
    private final int cornerRadius = 12;

    public CyberCard(LayoutManager layout, Color borderColor) {
        super(layout);
        this.borderColor = borderColor != null ? borderColor : CyberPalette.BORDER;
        this.bgColorTop = CyberPalette.SURFACE;
        this.bgColorBottom = CyberPalette.SURFACE;
        setOpaque(false);
        setBorder(new EmptyBorder(16, 20, 16, 20));
    }

    public CyberCard(Color borderColor) {
        this(new BorderLayout(10, 10), borderColor);
    }

    public CyberCard() {
        this(new BorderLayout(10, 10), CyberPalette.BORDER);
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        int width = getWidth();
        int height = getHeight();

        // Surface Fill
        g2.setColor(bgColorTop);
        g2.fillRoundRect(0, 0, width - 1, height - 1, cornerRadius, cornerRadius);

        // Border
        g2.setColor(borderColor);
        g2.setStroke(new BasicStroke(1.0f));
        g2.drawRoundRect(0, 0, width - 1, height - 1, cornerRadius, cornerRadius);

        g2.dispose();
        super.paintComponent(g);
    }
}
