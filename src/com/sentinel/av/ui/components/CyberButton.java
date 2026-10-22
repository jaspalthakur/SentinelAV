package com.sentinel.av.ui.components;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

/**
 * Themed SentinelAV button with built-in hover/pressed/disabled states.
 *
 * <p>Variants:</p>
 * <ul>
 *   <li>{@link #PRIMARY} - accent fill, used for the main action on a page.</li>
 *   <li>{@link #SECONDARY} - surface fill, secondary actions.</li>
 *   <li>{@link #DANGER} - red fill, destructive actions (confirmation required).</li>
 *   <li>{@link #GHOST} - transparent fill, subtle/tertiary actions.</li>
 * </ul>
 *
 * <p>Example:</p>
 * <pre>
 * CyberButton btn = new CyberButton("Scan Now", CyberButton.PRIMARY, IconUtils.getIcon(IconType.SCAN, ...));
 * btn.addActionListener(e -> ...);
 * </pre>
 */
public class CyberButton extends JButton {

    public static final Variant PRIMARY = new Variant(
            CyberPalette.BTN_PRIMARY_BG, CyberPalette.BTN_PRIMARY_BG_HOVER, CyberPalette.BTN_PRIMARY_FG);
    public static final Variant SECONDARY = new Variant(
            CyberPalette.BTN_SECONDARY_BG, CyberPalette.BTN_SECONDARY_BG_HOVER, CyberPalette.BTN_SECONDARY_FG);
    public static final Variant DANGER = new Variant(
            CyberPalette.BTN_DANGER_BG, CyberPalette.BTN_DANGER_BG_HOVER, CyberPalette.BTN_DANGER_FG);
    public static final Variant GHOST = new Variant(
            CyberPalette.BTN_GHOST_BG, CyberPalette.BTN_GHOST_BG_HOVER, CyberPalette.BTN_GHOST_FG);

    public static final class Variant {
        final Color bg;
        final Color bgHover;
        final Color fg;

        Variant(Color bg, Color bgHover, Color fg) {
            this.bg = bg;
            this.bgHover = bgHover;
            this.fg = fg;
        }
    }

    private Variant variant;
    private boolean armed = false;

    public CyberButton(String text, Variant variant) {
        super(text);
        this.variant = variant;
        init();
    }

    public CyberButton(String text, Icon icon, Variant variant) {
        super(text, icon);
        this.variant = variant;
        init();
    }

    /** Switch the visual variant at runtime (used for active nav state). */
    public void setVariant(Variant newVariant) {
        this.variant = newVariant;
        applyVariant(newVariant, armed && isEnabled());
    }

    private void init() {
        setFont(CyberPalette.FONT_BODY_BOLD);
        setFocusPainted(false);
        setBorderPainted(false);
        setOpaque(false);
        setCursor(new Cursor(Cursor.HAND_CURSOR));
        applyVariant(variant, false);

        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                armed = true;
                applyVariant(variant, true);
            }

            @Override
            public void mouseExited(MouseEvent e) {
                armed = false;
                applyVariant(variant, false);
            }

            @Override
            public void mousePressed(MouseEvent e) {
                applyVariant(variant, true);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                applyVariant(variant, armed);
            }
        });
    }

    private void applyVariant(Variant v, boolean hover) {
        Color bg = hover ? v.bgHover : v.bg;
        if (!isEnabled()) {
            bg = CyberPalette.BTN_DISABLED_BG;
        }
        setBackground(bg);
        setForeground(isEnabled() ? v.fg : CyberPalette.BTN_DISABLED_FG);
        repaint();
    }

    @Override
    public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
        applyVariant(variant, armed && enabled);
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        int w = getWidth();
        int h = getHeight();

        // Background fill
        g2.setColor(getBackground());
        g2.fillRoundRect(0, 0, w - 1, h - 1, 8, 8);

        // Subtle inner highlight on primary hover
        if (variant == PRIMARY && armed && isEnabled()) {
            g2.setColor(new Color(255, 255, 255, 12));
            g2.setStroke(new BasicStroke(1.0f));
            g2.drawRoundRect(1, 1, w - 3, h - 3, 7, 7);
        }

        g2.dispose();
        super.paintComponent(g);
    }
}
