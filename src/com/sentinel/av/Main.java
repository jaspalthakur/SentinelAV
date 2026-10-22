package com.sentinel.av;

import com.sentinel.av.ui.MainFrame;

import javax.swing.*;

public class Main {

    public static void main(String[] args) {
        // Set FlatLaf Dark Look and Feel if available
        try {
            UIManager.setLookAndFeel("com.formdev.flatlaf.FlatDarkLaf");
        } catch (Exception e) {
            try {
                // Fallback to Nimbus
                for (UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                    if ("Nimbus".equals(info.getName())) {
                        UIManager.setLookAndFeel(info.getClassName());
                        break;
                    }
                }
            } catch (Exception ignored) {}
        }

        SwingUtilities.invokeLater(() -> {
            MainFrame app = new MainFrame();
            app.setVisible(true);
        });
    }
}
