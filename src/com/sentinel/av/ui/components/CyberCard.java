package com.sentinel.av.ui.components;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * Polished container card with rounded corners, a border, and a subtle hover
 * elevation effect.
 *
 * <p>Cards render a solid surface fill with a 1px border. When
 * {@link #setHoverEnabled(boolean)} is enabled and the mouse enters, the card
 * shifts to {@link CyberPalette#SURFACE_HOVER} and a faint inner glow is drawn,
 * giving a lightweight tactile response without drop-shadow dependencies.
 */
public class CyberCard extends JPanel {

    private final Color borderColor;
    private final int cornerRadius = 12;
    private boolean hoverEnabled = false;
    private boolean hovered = false;

    public CyberCard(LayoutManager layout, Color borderColor) {
        super(layout);
        this.borderColor = borderColor != null ? borderColor : CyberPalette.BORDER;
        setOpaque(false);
        setBorder(new EmptyBorder(16, 20, 16, 20));
        installHover();
    }

    public CyberCard(Color borderColor) {
        this(new BorderLayout(10, 10), borderColor);
    }

    public CyberCard() {
        this(new BorderLayout(10, 10), CyberPalette.BORDER);
    }

    /** Enable or disable the hover elevation effect. Default is off. */
    public void setHoverEnabled(boolean enabled) {
        this.hoverEnabled = enabled;
    }

    private void installHover() {
        if (!hoverEnabled) {
            return;
        }
        addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseEntered(java.awt.event.MouseEvent e) {
                hovered = true;
                repaint();
            }

            @Override
            public void mouseExited(java.awt.event.MouseEvent e) {
                hovered = false;
                repaint();
            }
        });
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        int width = getWidth();
        int height = getHeight();

        // Surface fill - lift slightly on hover
        g2.setColor(hovered && hoverEnabled ? CyberPalette.SURFACE_HOVER : CyberPalette.SURFACE);
        g2.fillRoundRect(0, 0, width - 1, height - 1, cornerRadius, cornerRadius);

        // Faint inner glow on hover for tactile feedback
        if (hovered && hoverEnabled) {
            g2.setColor(new Color(255, 255, 255, 10));
            g2.setStroke(new BasicStroke(1.0f));
            g2.drawRoundRect(1, 1, width - 3, height - 3, cornerRadius - 1, cornerRadius - 1);
        }

        // Border
        g2.setColor(borderColor);
        g2.setStroke(new BasicStroke(1.0f));
        g2.drawRoundRect(0, 0, width - 1, height - 1, cornerRadius, cornerRadius);

        g2.dispose();
        super.paintComponent(g);
    }
}
