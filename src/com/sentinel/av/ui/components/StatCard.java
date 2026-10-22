package com.sentinel.av.ui.components;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * Metric card displaying a large value with a title and subtext.
 *
 * <p>The card uses {@link CyberPalette} colors exclusively and supports a
 * subtle hover lift when {@link #setHoverEnabled(boolean)} is turned on.</p>
 */
public class StatCard extends JPanel {

    private final JLabel titleLabel;
    private final JLabel valueLabel;
    private final JLabel subtextLabel;
    private Color accentColor;
    private boolean hovered = false;
    private boolean hoverEnabled = false;

    public StatCard(String title, String initialValue, String subtext, Color accentColor) {
        this(title, initialValue, subtext, accentColor, false);
    }

    public StatCard(String title, String initialValue, String subtext, Color accentColor, boolean hoverEnabled) {
        this.accentColor = accentColor != null ? accentColor : CyberPalette.ACCENT;
        this.hoverEnabled = hoverEnabled;

        setLayout(new BorderLayout(8, 8));
        setBackground(CyberPalette.SURFACE);
        setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 4, 0, 0, this.accentColor),
                new EmptyBorder(14, 18, 14, 18)));
        setOpaque(true);
        setPreferredSize(new Dimension(210, 0));

        titleLabel = new JLabel(title);
        titleLabel.setFont(CyberPalette.FONT_CAPTION);
        titleLabel.setForeground(CyberPalette.TEXT_MUTED);

        valueLabel = new JLabel(initialValue);
        valueLabel.setFont(new Font("Segoe UI", Font.BOLD, 24));
        valueLabel.setForeground(CyberPalette.TEXT_PRIMARY);

        subtextLabel = new JLabel(subtext);
        subtextLabel.setFont(CyberPalette.FONT_CAPTION);
        subtextLabel.setForeground(CyberPalette.TEXT_SECONDARY);

        JPanel textPanel = new JPanel(new GridLayout(3, 1, 2, 2));
        textPanel.setOpaque(false);
        textPanel.add(titleLabel);
        textPanel.add(valueLabel);
        textPanel.add(subtextLabel);

        add(textPanel, BorderLayout.CENTER);

        if (hoverEnabled) {
            installHover();
        }
    }

    private void installHover() {
        addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseEntered(java.awt.event.MouseEvent e) {
                hovered = true;
                refreshLook();
            }

            @Override
            public void mouseExited(java.awt.event.MouseEvent e) {
                hovered = false;
                refreshLook();
            }
        });
    }

    private void refreshLook() {
        setBackground(hovered ? CyberPalette.SURFACE_HOVER : CyberPalette.SURFACE);
        repaint();
    }

    public void setValue(String value) {
        valueLabel.setText(value);
    }

    public void setSubtext(String subtext) {
        subtextLabel.setText(subtext);
    }

    public void setAccentColor(Color accentColor) {
        this.accentColor = accentColor != null ? accentColor : CyberPalette.ACCENT;
        setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 4, 0, 0, this.accentColor),
                new EmptyBorder(14, 18, 14, 18)));
    }
}
