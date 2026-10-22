package com.sentinel.av.ui.components;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

public class StatCard extends JPanel {

    private final JLabel titleLabel;
    private final JLabel valueLabel;
    private final JLabel subtextLabel;

    public StatCard(String title, String initialValue, String subtext, Color accentColor) {
        setLayout(new BorderLayout(5, 5));
        setBackground(CyberPalette.SURFACE);
        setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 4, 0, 0, accentColor),
            new EmptyBorder(15, 18, 15, 18)
        ));

        titleLabel = new JLabel(title);
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 13));
        titleLabel.setForeground(CyberPalette.TEXT_SECONDARY);

        valueLabel = new JLabel(initialValue);
        valueLabel.setFont(new Font("Segoe UI", Font.BOLD, 26));
        valueLabel.setForeground(CyberPalette.TEXT_PRIMARY);

        subtextLabel = new JLabel(subtext);
        subtextLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        subtextLabel.setForeground(CyberPalette.TEXT_MUTED);

        JPanel textPanel = new JPanel(new GridLayout(3, 1, 2, 2));
        textPanel.setOpaque(false);
        textPanel.add(titleLabel);
        textPanel.add(valueLabel);
        textPanel.add(subtextLabel);

        add(textPanel, BorderLayout.CENTER);
    }

    public void setValue(String value) {
        valueLabel.setText(value);
    }

    public void setSubtext(String subtext) {
        subtextLabel.setText(subtext);
    }
}
