package com.sentinel.av.ui.components;

import javax.swing.*;
import java.awt.*;
import java.awt.geom.Path2D;

public class IconUtils {

    public enum IconType {
        HOME, SCAN, PROTECTION, QUARANTINE, UPDATES, HISTORY, ADVANCED, SETTINGS, SHIELD_OK, WARNING, THREAT
    }

    public static Icon getIcon(IconType type, Color color, int size) {
        return new Icon() {
            @Override
            public void paintIcon(Component c, Graphics g, int x, int y) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(color);
                g2.setStroke(new BasicStroke(2.0f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));

                int s = size;
                int ox = x;
                int oy = y;

                switch (type) {
                    case HOME:
                        Path2D home = new Path2D.Double();
                        home.moveTo(ox + s * 0.5, oy + s * 0.15);
                        home.lineTo(ox + s * 0.85, oy + s * 0.45);
                        home.lineTo(ox + s * 0.85, oy + s * 0.85);
                        home.lineTo(ox + s * 0.15, oy + s * 0.85);
                        home.lineTo(ox + s * 0.15, oy + s * 0.45);
                        home.closePath();
                        g2.draw(home);
                        break;

                    case SCAN:
                        g2.drawOval(ox + (int)(s * 0.2), oy + (int)(s * 0.2), (int)(s * 0.45), (int)(s * 0.45));
                        g2.drawLine(ox + (int)(s * 0.55), oy + (int)(s * 0.55), ox + (int)(s * 0.85), oy + (int)(s * 0.85));
                        break;

                    case PROTECTION:
                    case SHIELD_OK:
                        Path2D shield = new Path2D.Double();
                        shield.moveTo(ox + s * 0.5, oy + s * 0.1);
                        shield.lineTo(ox + s * 0.85, oy + s * 0.25);
                        shield.lineTo(ox + s * 0.85, oy + s * 0.6);
                        shield.curveTo(ox + s * 0.85, oy + s * 0.8, ox + s * 0.6, oy + s * 0.9, ox + s * 0.5, oy + s * 0.95);
                        shield.curveTo(ox + s * 0.4, oy + s * 0.9, ox + s * 0.15, oy + s * 0.8, ox + s * 0.15, oy + s * 0.6);
                        shield.lineTo(ox + s * 0.15, oy + s * 0.25);
                        shield.closePath();
                        g2.draw(shield);
                        break;

                    case QUARANTINE:
                        g2.drawRoundRect(ox + (int)(s * 0.2), oy + (int)(s * 0.4), (int)(s * 0.6), (int)(s * 0.45), 4, 4);
                        g2.drawArc(ox + (int)(s * 0.3), oy + (int)(s * 0.15), (int)(s * 0.4), (int)(s * 0.5), 0, 180);
                        break;

                    case UPDATES:
                        g2.drawArc(ox + (int)(s * 0.2), oy + (int)(s * 0.2), (int)(s * 0.6), (int)(s * 0.6), 45, 270);
                        g2.drawLine(ox + (int)(s * 0.65), oy + (int)(s * 0.15), ox + (int)(s * 0.8), oy + (int)(s * 0.3));
                        g2.drawLine(ox + (int)(s * 0.8), oy + (int)(s * 0.3), ox + (int)(s * 0.65), oy + (int)(s * 0.4));
                        break;

                    case HISTORY:
                        g2.drawOval(ox + (int)(s * 0.15), oy + (int)(s * 0.15), (int)(s * 0.7), (int)(s * 0.7));
                        g2.drawLine(ox + (int)(s * 0.5), oy + (int)(s * 0.3), ox + (int)(s * 0.5), oy + (int)(s * 0.5));
                        g2.drawLine(ox + (int)(s * 0.5), oy + (int)(s * 0.5), ox + (int)(s * 0.7), oy + (int)(s * 0.5));
                        break;

                    case ADVANCED:
                    case SETTINGS:
                        g2.drawOval(ox + (int)(s * 0.3), oy + (int)(s * 0.3), (int)(s * 0.4), (int)(s * 0.4));
                        g2.drawLine(ox + (int)(s * 0.5), oy + (int)(s * 0.1), ox + (int)(s * 0.5), oy + (int)(s * 0.9));
                        g2.drawLine(ox + (int)(s * 0.1), oy + (int)(s * 0.5), ox + (int)(s * 0.9), oy + (int)(s * 0.5));
                        break;

                    case WARNING:
                        Path2D tri = new Path2D.Double();
                        tri.moveTo(ox + s * 0.5, oy + s * 0.15);
                        tri.lineTo(ox + s * 0.85, oy + s * 0.85);
                        tri.lineTo(ox + s * 0.15, oy + s * 0.85);
                        tri.closePath();
                        g2.draw(tri);
                        g2.drawLine(ox + (int)(s * 0.5), oy + (int)(s * 0.45), ox + (int)(s * 0.5), oy + (int)(s * 0.65));
                        g2.fillOval(ox + (int)(s * 0.48), oy + (int)(s * 0.72), 3, 3);
                        break;

                    case THREAT:
                        g2.drawOval(ox + (int)(s * 0.2), oy + (int)(s * 0.2), (int)(s * 0.6), (int)(s * 0.6));
                        g2.drawLine(ox + (int)(s * 0.3), oy + (int)(s * 0.3), ox + (int)(s * 0.7), oy + (int)(s * 0.7));
                        g2.drawLine(ox + (int)(s * 0.7), oy + (int)(s * 0.3), ox + (int)(s * 0.3), oy + (int)(s * 0.7));
                        break;
                }

                g2.dispose();
            }

            @Override
            public int getIconWidth() { return size; }

            @Override
            public int getIconHeight() { return size; }
        };
    }
}
