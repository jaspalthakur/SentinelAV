package com.sentinel.av.ui;

import com.sentinel.av.core.ActivityLogger;
import com.sentinel.av.core.ProcessInspector;
import com.sentinel.av.ui.components.CyberButton;
import com.sentinel.av.ui.components.CyberCard;
import com.sentinel.av.ui.components.CyberPalette;
import com.sentinel.av.ui.components.StatusBadge;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.io.File;
import java.util.List;

public class ProcessPanel extends JPanel {

    private final MainFrame mainFrame;
    private DefaultTableModel tableModel;
    private JTable processTable;
    private JLabel countLabel;
    private JComboBox<String> filterBox;

    public ProcessPanel(MainFrame mainFrame) {
        this.mainFrame = mainFrame;
        setLayout(new BorderLayout(15, 15));
        setBackground(CyberPalette.BACKGROUND);
        setBorder(new EmptyBorder(25, 25, 25, 25));

        initComponents();
        refreshProcesses();
    }

    private void initComponents() {
        // --- Top Header Card ---
        CyberCard topCard = new CyberCard(CyberPalette.BORDER);

        JLabel titleLabel = new JLabel("\u2699\uFE0F  System Process & Memory Inspector");
        titleLabel.setFont(CyberPalette.FONT_TITLE_SMALL);
        titleLabel.setForeground(CyberPalette.TEXT_PRIMARY);

        countLabel = new JLabel("Active Processes: 0");
        countLabel.setFont(CyberPalette.FONT_SMALL);
        countLabel.setForeground(CyberPalette.TEXT_SECONDARY);

        JPanel titleGroup = new JPanel(new GridLayout(2, 1, 4, 4));
        titleGroup.setOpaque(false);
        titleGroup.add(titleLabel);
        titleGroup.add(countLabel);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        btnRow.setOpaque(false);

        filterBox = new JComboBox<>(new String[]{"ALL", "HIGH / CRITICAL ONLY", "MEDIUM & ABOVE"});
        filterBox.setFont(CyberPalette.FONT_SMALL);
        filterBox.setBackground(CyberPalette.INPUT_BG);
        filterBox.setForeground(CyberPalette.TEXT_PRIMARY);
        filterBox.addActionListener(e -> refreshProcesses());

        CyberButton refreshBtn = new CyberButton("\u27F3  Refresh List", CyberButton.SECONDARY);
        refreshBtn.setFont(CyberPalette.FONT_SMALL);
        refreshBtn.addActionListener(e -> refreshProcesses());

        CyberButton scanProcBtn = new CyberButton("\uD83D\uDD0D  Scan Process Binary", CyberButton.PRIMARY);
        scanProcBtn.setFont(CyberPalette.FONT_SMALL);
        scanProcBtn.addActionListener(e -> scanSelectedProcess());

        CyberButton killBtn = new CyberButton("\uD83D\uDDD1  Terminate Process", CyberButton.DANGER);
        killBtn.setFont(CyberPalette.FONT_SMALL);
        killBtn.addActionListener(e -> terminateSelectedProcess());

        btnRow.add(new JLabel("Filter:"));
        btnRow.add(filterBox);
        btnRow.add(refreshBtn);
        btnRow.add(scanProcBtn);
        btnRow.add(killBtn);

        topCard.add(titleGroup, BorderLayout.CENTER);
        topCard.add(btnRow, BorderLayout.EAST);

        // --- Center Table Card ---
        CyberCard tableCard = new CyberCard(CyberPalette.BORDER);

        String[] cols = {"PID", "Process Name", "Risk Level", "Risk Reason", "Executable Path", "Command Line"};
        tableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        processTable = new JTable(tableModel) {
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
        processTable.setForeground(CyberPalette.TEXT_PRIMARY);
        processTable.setGridColor(CyberPalette.BORDER);
        processTable.setRowHeight(30);
        processTable.setFont(CyberPalette.FONT_CODE);
        processTable.getTableHeader().setFont(CyberPalette.FONT_BODY_BOLD);
        processTable.getTableHeader().setBackground(CyberPalette.SURFACE_HOVER);
        processTable.getTableHeader().setForeground(CyberPalette.TEXT_PRIMARY);
        processTable.getTableHeader().setReorderingAllowed(false);
        processTable.setAutoCreateRowSorter(true);
        processTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        processTable.setIntercellSpacing(new Dimension(0, 1));

        // Risk Level Cell Renderer
        processTable.getColumnModel().getColumn(2).setCellRenderer((table, value, isSelected, hasFocus, row, column) -> {
            if (value != null) {
                return StatusBadge.createSeverityBadge(value.toString());
            }
            return new JLabel("");
        });

        JScrollPane scrollPane = new JScrollPane(processTable);
        scrollPane.setBorder(BorderFactory.createLineBorder(CyberPalette.BORDER));
        scrollPane.getViewport().setBackground(CyberPalette.BACKGROUND);

        tableCard.add(scrollPane, BorderLayout.CENTER);

        add(topCard, BorderLayout.NORTH);
        add(tableCard, BorderLayout.CENTER);
    }

    /** Maps the selected view row to the model index, so sorting stays consistent. */
    private int selectedModelRow() {
        int viewRow = processTable.getSelectedRow();
        if (viewRow < 0) {
            return -1;
        }
        return processTable.convertRowIndexToModel(viewRow);
    }

    public void refreshProcesses() {
        tableModel.setRowCount(0);
        List<ProcessInspector.ProcessInfo> list = ProcessInspector.getRunningProcesses();
        String filter = (String) filterBox.getSelectedItem();

        int count = 0;
        for (ProcessInspector.ProcessInfo p : list) {
            boolean include = true;
            if ("HIGH / CRITICAL ONLY".equals(filter)) {
                include = p.getRiskLevel().ordinal() >= 2; // HIGH or CRITICAL
            } else if ("MEDIUM & ABOVE".equals(filter)) {
                include = p.getRiskLevel().ordinal() >= 1; // MEDIUM, HIGH, or CRITICAL
            }

            if (include) {
                count++;
                tableModel.addRow(new Object[]{
                    p.getPid(),
                    p.getName(),
                    p.getRiskLevel().name(),
                    p.getRiskReason(),
                    p.getExecutablePath(),
                    p.getCommandLine()
                });
            }
        }
        countLabel.setText("Active Processes: " + count + " (Total system: " + list.size() + ")");
    }

    private void scanSelectedProcess() {
        int selectedRow = selectedModelRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(this, "Please select a process from the table.", "No Process Selected",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        String pathStr = (String) tableModel.getValueAt(selectedRow, 4);
        if (pathStr != null && !pathStr.isEmpty() && !pathStr.contains("Undisclosed")) {
            File targetFile = new File(pathStr);
            if (targetFile.exists()) {
                mainFrame.switchToScanTabWithFolder(targetFile);
            } else {
                JOptionPane.showMessageDialog(this, "Executable file path not accessible: " + pathStr,
                        "File Not Found", JOptionPane.WARNING_MESSAGE);
            }
        } else {
            JOptionPane.showMessageDialog(this, "Process path is system protected or undisclosed.",
                    "Scan Unavailable", JOptionPane.WARNING_MESSAGE);
        }
    }

    private void terminateSelectedProcess() {
        int selectedRow = selectedModelRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(this, "Please select a process to terminate.", "No Process Selected",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        long pid = (long) tableModel.getValueAt(selectedRow, 0);
        String name = (String) tableModel.getValueAt(selectedRow, 1);

        Object[] options = {"Terminate", "Cancel"};
        int confirm = JOptionPane.showOptionDialog(this,
            "Are you sure you want to FORCE TERMINATE process: " + name + " (PID: " + pid + ")?",
            "Confirm Process Termination", JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE,
            null, options, options[1]);

        if (confirm == 0) {
            if (ProcessInspector.terminateProcess(pid)) {
                ActivityLogger.getInstance().warning("ProcessInspector",
                    "Terminated process " + name + " (PID: " + pid + ")");
                refreshProcesses();
                JOptionPane.showMessageDialog(this, "Process terminated successfully.", "Terminated",
                        JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this,
                    "Failed to terminate process PID " + pid + " (Access Denied or Process Exited).", "Error",
                    JOptionPane.ERROR_MESSAGE);
            }
        }
    }
}
