package com.sentinel.av.ui;

import com.sentinel.av.core.ActivityLogger;
import com.sentinel.av.core.ProcessInspector;
import com.sentinel.av.ui.components.StatusBadge;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
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
        setBackground(new Color(24, 27, 33));
        setBorder(new EmptyBorder(25, 25, 25, 25));

        initComponents();
        refreshProcesses();
    }

    private void initComponents() {
        // --- Top Header Card ---
        JPanel topCard = new JPanel(new BorderLayout(10, 10));
        topCard.setBackground(new Color(33, 37, 44));
        topCard.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(50, 56, 68), 1),
            new EmptyBorder(15, 20, 15, 20)
        ));

        JLabel titleLabel = new JLabel("⚙️ System Process & Memory Inspector");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        titleLabel.setForeground(Color.WHITE);

        countLabel = new JLabel("Active Processes: 0");
        countLabel.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        countLabel.setForeground(new Color(170, 185, 205));

        JPanel titleGroup = new JPanel(new GridLayout(2, 1, 4, 4));
        titleGroup.setOpaque(false);
        titleGroup.add(titleLabel);
        titleGroup.add(countLabel);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        btnRow.setOpaque(false);

        filterBox = new JComboBox<>(new String[]{"ALL", "HIGH / CRITICAL ONLY", "MEDIUM & ABOVE"});
        filterBox.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        filterBox.addActionListener(e -> refreshProcesses());

        JButton refreshBtn = new JButton("🔄 Refresh List");
        refreshBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        refreshBtn.setBackground(new Color(45, 55, 70));
        refreshBtn.setForeground(Color.WHITE);
        refreshBtn.addActionListener(e -> refreshProcesses());

        JButton scanProcBtn = new JButton("🔍 Scan Process Binary");
        scanProcBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        scanProcBtn.setBackground(new Color(40, 120, 200));
        scanProcBtn.setForeground(Color.WHITE);
        scanProcBtn.addActionListener(e -> scanSelectedProcess());

        JButton killBtn = new JButton("🛑 Terminate Process");
        killBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        killBtn.setBackground(new Color(180, 50, 50));
        killBtn.setForeground(Color.WHITE);
        killBtn.addActionListener(e -> terminateSelectedProcess());

        btnRow.add(new JLabel("Filter:"));
        btnRow.add(filterBox);
        btnRow.add(refreshBtn);
        btnRow.add(scanProcBtn);
        btnRow.add(killBtn);

        topCard.add(titleGroup, BorderLayout.CENTER);
        topCard.add(btnRow, BorderLayout.EAST);

        // --- Center Table Card ---
        JPanel tableCard = new JPanel(new BorderLayout(10, 10));
        tableCard.setBackground(new Color(33, 37, 44));
        tableCard.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(50, 56, 68), 1),
            new EmptyBorder(15, 20, 15, 20)
        ));

        String[] cols = {"PID", "Process Name", "Risk Level", "Risk Reason", "Executable Path", "Command Line"};
        tableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };

        processTable = new JTable(tableModel);
        processTable.setBackground(new Color(25, 29, 36));
        processTable.setForeground(Color.WHITE);
        processTable.setGridColor(new Color(45, 52, 65));
        processTable.setRowHeight(28);
        processTable.setFont(new Font("Consolas", Font.PLAIN, 12));
        processTable.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 12));
        processTable.getTableHeader().setBackground(new Color(38, 44, 54));
        processTable.getTableHeader().setForeground(new Color(200, 215, 235));

        // Risk Level Cell Renderer
        processTable.getColumnModel().getColumn(2).setCellRenderer((table, value, isSelected, hasFocus, row, column) -> {
            if (value != null) {
                return StatusBadge.createSeverityBadge(value.toString());
            }
            return new JLabel("");
        });

        JScrollPane scrollPane = new JScrollPane(processTable);
        scrollPane.setBorder(BorderFactory.createLineBorder(new Color(45, 52, 65)));

        tableCard.add(scrollPane, BorderLayout.CENTER);

        add(topCard, BorderLayout.NORTH);
        add(tableCard, BorderLayout.CENTER);
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
        int selectedRow = processTable.getSelectedRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(this, "Please select a process from the table.", "No Process Selected", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String pathStr = (String) tableModel.getValueAt(selectedRow, 4);
        if (pathStr != null && !pathStr.isEmpty() && !pathStr.contains("Undisclosed")) {
            File targetFile = new File(pathStr);
            if (targetFile.exists()) {
                mainFrame.switchToScanTabWithFolder(targetFile);
            } else {
                JOptionPane.showMessageDialog(this, "Executable file path not accessible: " + pathStr, "File Not Found", JOptionPane.WARNING_MESSAGE);
            }
        } else {
            JOptionPane.showMessageDialog(this, "Process path is system protected or undisclosed.", "Scan Unavailable", JOptionPane.WARNING_MESSAGE);
        }
    }

    private void terminateSelectedProcess() {
        int selectedRow = processTable.getSelectedRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(this, "Please select a process to terminate.", "No Process Selected", JOptionPane.WARNING_MESSAGE);
            return;
        }

        long pid = (long) tableModel.getValueAt(selectedRow, 0);
        String name = (String) tableModel.getValueAt(selectedRow, 1);

        int confirm = JOptionPane.showConfirmDialog(this,
            "Are you sure you want to FORCE TERMINATE process: " + name + " (PID: " + pid + ")?",
            "Confirm Process Termination", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);

        if (confirm == JOptionPane.YES_OPTION) {
            if (ProcessInspector.terminateProcess(pid)) {
                ActivityLogger.getInstance().warning("ProcessInspector", "Terminated process " + name + " (PID: " + pid + ")");
                refreshProcesses();
                JOptionPane.showMessageDialog(this, "Process terminated successfully.", "Terminated", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this, "Failed to terminate process PID " + pid + " (Access Denied or Process Exited).", "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
}
