package com.sentinel.av;

import com.sentinel.av.cli.CliRunner;
import com.sentinel.av.ui.MainFrame;

import javax.swing.UIManager;
import javax.swing.SwingUtilities;

public class Main {

    public static void main(String[] args) {
        // Any argument switches to headless CLI mode; no arguments launches the GUI.
        if (args != null && args.length > 0) {
            System.exit(CliRunner.run(args));
            return;
        }
        launchGui();
    }

    private static void launchGui() {
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
            } catch (Exception ignored) {
                // Default cross-platform look and feel is fine.
            }
        }

        SwingUtilities.invokeLater(() -> {
            MainFrame app = new MainFrame();
            app.setVisible(true);
        });
    }
}
