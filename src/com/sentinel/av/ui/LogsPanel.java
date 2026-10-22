package com.sentinel.av.ui;

import com.sentinel.av.core.ActivityLogger;
import com.sentinel.av.model.ActivityLog;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.util.List;

public class LogsPanel extends JPanel implements ActivityLogger.LogListener {

    private final ActivityLogger logger;
    private DefaultTableModel tableModel;
    private JTable logsTable;
    private JComboBox<String> filterBox;

    public LogsPanel() {
        this.logger = ActivityLogger.getInstance();
        setLayout(new BorderLayout(15, 15));
        setBackground(new Color(24, 27, 33));
        setBorder(new EmptyBorder(25, 25, 25, 25));

        initComponents();

        logger.addListener(this);
        refreshLogs();
    }

    private void initComponents() {
        // --- Top Header Card ---
        JPanel topCard = new JPanel(new BorderLayout(10, 10));
        topCard.setBackground(new Color(33, 37, 44));
        topCard.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(50, 56, 68), 1),
            new EmptyBorder(15, 20, 15, 20)
        ));

        JLabel titleLabel = new JLabel("📜 System Activity & Threat Audit Logs");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        titleLabel.setForeground(Color.WHITE);

        JPanel rightControls = new JPanel(new FlowLayout(FlowLayout.RIGHT, 12, 0));
        rightControls.setOpaque(false);

        JLabel filterLabel = new JLabel("Filter Level:");
        filterLabel.setForeground(new Color(200, 210, 225));

        filterBox = new JComboBox<>(new String[]{"ALL", "THREAT_DETECTED", "QUARANTINE", "SYSTEM", "INFO", "WARNING"});
        filterBox.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        filterBox.addActionListener(e -> refreshLogs());

        JButton clearBtn = new JButton("🧹 Clear Logs");
        clearBtn.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        clearBtn.setBackground(new Color(50, 56, 68));
        clearBtn.setForeground(Color.WHITE);
        clearBtn.addActionListener(e -> {
            logger.clearLogs();
            refreshLogs();
        });

        JButton exportBtn = new JButton("💾 Export Logs");
        exportBtn.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        exportBtn.setBackground(new Color(40, 120, 180));
        exportBtn.setForeground(Color.WHITE);
        exportBtn.addActionListener(e -> exportLogs());

        rightControls.add(filterLabel);
        rightControls.add(filterBox);
        rightControls.add(clearBtn);
        rightControls.add(exportBtn);

        topCard.add(titleLabel, BorderLayout.WEST);
        topCard.add(rightControls, BorderLayout.EAST);

        // --- Center Table Card ---
        JPanel tableCard = new JPanel(new BorderLayout(10, 10));
        tableCard.setBackground(new Color(33, 37, 44));
        tableCard.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(50, 56, 68), 1),
            new EmptyBorder(15, 20, 15, 20)
        ));

        String[] cols = {"Timestamp", "Level", "Category", "Event Description"};
        tableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };

        logsTable = new JTable(tableModel);
        logsTable.setBackground(new Color(25, 29, 36));
        logsTable.setForeground(Color.WHITE);
        logsTable.setGridColor(new Color(45, 52, 65));
        logsTable.setRowHeight(26);
        logsTable.setFont(new Font("Consolas", Font.PLAIN, 12));
        logsTable.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 12));
        logsTable.getTableHeader().setBackground(new Color(38, 44, 54));
        logsTable.getTableHeader().setForeground(new Color(200, 215, 235));

        JScrollPane scrollPane = new JScrollPane(logsTable);
        scrollPane.setBorder(BorderFactory.createLineBorder(new Color(45, 52, 65)));

        tableCard.add(scrollPane, BorderLayout.CENTER);

        add(topCard, BorderLayout.NORTH);
        add(tableCard, BorderLayout.CENTER);
    }

    public void refreshLogs() {
        tableModel.setRowCount(0);
        String selectedFilter = (String) filterBox.getSelectedItem();
        List<ActivityLog> logs = logger.getLogs();

        for (ActivityLog log : logs) {
            if ("ALL".equals(selectedFilter) || log.getLevel().name().equalsIgnoreCase(selectedFilter)) {
                tableModel.addRow(new Object[]{
                    log.getTimestamp(),
                    log.getLevel().name(),
                    log.getCategory(),
                    log.getMessage()
                });
            }
        }
    }

    private void exportLogs() {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("SentinelAV_ExportedLogs.txt"));
        int res = chooser.showSaveDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            File dest = chooser.getSelectedFile();
            StringBuilder sb = new StringBuilder();
            for (ActivityLog log : logger.getLogs()) {
                sb.append(String.format("[%s] [%s] [%s] %s%n", log.getTimestamp(), log.getLevel(), log.getCategory(), log.getMessage()));
            }
            try {
                Files.write(dest.toPath(), sb.toString().getBytes());
                JOptionPane.showMessageDialog(this, "Logs exported to " + dest.getAbsolutePath(), "Export Success", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Failed to export logs: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    @Override
    public void onLogAdded(ActivityLog log) {
        SwingUtilities.invokeLater(this::refreshLogs);
    }
}
