
package com.sentinel.av;

import com.sentinel.av.cli.CliRunner;
import com.sentinel.av.ui.MainFrame;

import javax.swing.UIManager;
import javax.swing.SwingUtilities;

public class Main {

    public static void main(String[] args) {

        // GraalVM Native Image diagnostic setting
        System.setProperty(
            "java.home",
            "C:\\graalvm\\graalvm-community-25.5.5.0.3+1.1"
        );

        // Arguments switch to CLI mode
        if (args != null && args.length > 0) {
            System.exit(CliRunner.run(args));
            return;
        }

        launchGui();
    }

    private static void launchGui() {
        try {
            UIManager.setLookAndFeel(
                "com.formdev.flatlaf.FlatDarkLaf"
            );
        } catch (Exception e) {
            try {
                for (UIManager.LookAndFeelInfo info :
                        UIManager.getInstalledLookAndFeels()) {

                    if ("Nimbus".equals(info.getName())) {
                        UIManager.setLookAndFeel(info.getClassName());
                        break;
                    }
                }
            } catch (Exception ignored) {
                // Default look and feel
            }
        }

        SwingUtilities.invokeLater(() -> {
            MainFrame app = new MainFrame();
            app.setVisible(true);
        });
    }
}
