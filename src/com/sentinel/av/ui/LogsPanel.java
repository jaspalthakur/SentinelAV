package com.sentinel.av.ui;

import com.sentinel.av.core.ActivityLogger;
import com.sentinel.av.model.ActivityLog;
import com.sentinel.av.ui.components.CyberButton;
import com.sentinel.av.ui.components.CyberCard;
import com.sentinel.av.ui.components.CyberPalette;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
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
        setBackground(CyberPalette.BACKGROUND);
        setBorder(new EmptyBorder(25, 25, 25, 25));

        initComponents();

        logger.addListener(this);
        refreshLogs();
    }

    private void initComponents() {
        // --- Top Header Card ---
        CyberCard topCard = new CyberCard(CyberPalette.BORDER);

        JLabel titleLabel = new JLabel("\uD83D\uDCDC  System Activity & Threat Audit Logs");
        titleLabel.setFont(CyberPalette.FONT_TITLE_SMALL);
        titleLabel.setForeground(CyberPalette.TEXT_PRIMARY);

        JPanel rightControls = new JPanel(new FlowLayout(FlowLayout.RIGHT, 12, 0));
        rightControls.setOpaque(false);

        JLabel filterLabel = new JLabel("Filter Level:");
        filterLabel.setForeground(CyberPalette.TEXT_SECONDARY);
        filterLabel.setFont(CyberPalette.FONT_SMALL);

        filterBox = new JComboBox<>(new String[]{"ALL", "THREAT_DETECTED", "QUARANTINE", "SYSTEM", "INFO", "WARNING"});
        filterBox.setFont(CyberPalette.FONT_SMALL);
        filterBox.setBackground(CyberPalette.INPUT_BG);
        filterBox.setForeground(CyberPalette.TEXT_PRIMARY);
        filterBox.addActionListener(e -> refreshLogs());

        CyberButton clearBtn = new CyberButton("\uD83D\uDC19  Clear Logs", CyberButton.SECONDARY);
        clearBtn.setFont(CyberPalette.FONT_SMALL);
        clearBtn.addActionListener(e -> {
            logger.clearLogs();
            refreshLogs();
        });

        CyberButton exportBtn = new CyberButton("\uD83D\uDCBE  Export Logs", CyberButton.PRIMARY);
        exportBtn.setFont(CyberPalette.FONT_SMALL);
        exportBtn.addActionListener(e -> exportLogs());

        rightControls.add(filterLabel);
        rightControls.add(filterBox);
        rightControls.add(clearBtn);
        rightControls.add(exportBtn);

        topCard.add(titleLabel, BorderLayout.WEST);
        topCard.add(rightControls, BorderLayout.EAST);

        // --- Center Table Card ---
        CyberCard tableCard = new CyberCard(CyberPalette.BORDER);

        String[] cols = {"Timestamp", "Level", "Category", "Event Description"};
        tableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        logsTable = new JTable(tableModel) {
            @Override
            public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
                Component c = super.prepareRenderer(renderer, row, column);
                if (c instanceof JComponent) {
                    boolean isSelected = isRowSelected(row);
                    if (isSelected) {
                        c.setBackground(CyberPalette.BORDER_ACTIVE);
                    } else {
                        c.setBackground(row % 2 == 0 ? CyberPalette.BACKGROUND
                                : new Color(15, 22, 40));
                    }
                }
                return c;
            }
        };
        logsTable.setForeground(CyberPalette.TEXT_PRIMARY);
        logsTable.setGridColor(CyberPalette.BORDER);
        logsTable.setRowHeight(26);
        logsTable.setFont(CyberPalette.FONT_CODE);
        logsTable.getTableHeader().setFont(CyberPalette.FONT_BODY_BOLD);
        logsTable.getTableHeader().setBackground(CyberPalette.SURFACE_HOVER);
        logsTable.getTableHeader().setForeground(CyberPalette.TEXT_PRIMARY);
        logsTable.getTableHeader().setReorderingAllowed(false);
        logsTable.setAutoCreateRowSorter(true);
        logsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        logsTable.setIntercellSpacing(new Dimension(0, 1));

        JScrollPane scrollPane = new JScrollPane(logsTable);
        scrollPane.setBorder(BorderFactory.createLineBorder(CyberPalette.BORDER));
        scrollPane.getViewport().setBackground(CyberPalette.BACKGROUND);

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
                sb.append(String.format("[%s] [%s] [%s] %s%n",
                    log.getTimestamp(), log.getLevel(), log.getCategory(), log.getMessage()));
            }
            try {
                Files.write(dest.toPath(), sb.toString().getBytes());
                JOptionPane.showMessageDialog(this, "Logs exported to " + dest.getAbsolutePath(),
                        "Export Success", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Failed to export logs: " + ex.getMessage(), "Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    @Override
    public void onLogAdded(ActivityLog log) {
        SwingUtilities.invokeLater(this::refreshLogs);
    }
}
