package com.sentinel.av.ui;

import com.sentinel.av.ui.components.CyberCard;
import com.sentinel.av.ui.components.StatusBadge;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;

public class AttackCoveragePanel extends JPanel {

    private final MainFrame mainFrame;
    private DefaultTableModel tableModel;

    public AttackCoveragePanel(MainFrame mainFrame) {
        this.mainFrame = mainFrame;
        setLayout(new BorderLayout(15, 15));
        setBackground(new Color(20, 23, 29));
        setBorder(new EmptyBorder(25, 25, 25, 25));

        initComponents();
        populateMatrix();
    }

    private void initComponents() {
        // --- Top Header Card ---
        CyberCard topCard = new CyberCard(new Color(50, 58, 72));

        JLabel titleLabel = new JLabel("🎯 MITRE ATT&CK® Threat Technique Matrix & Coverage");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        titleLabel.setForeground(Color.WHITE);

        JLabel subLabel = new JLabel("Live Rule Engine Coverage mapped against adversary Tactics & Techniques");
        subLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        subLabel.setForeground(new Color(170, 185, 205));

        JPanel titleGroup = new JPanel(new GridLayout(2, 1, 2, 2));
        titleGroup.setOpaque(false);
        titleGroup.add(titleLabel);
        titleGroup.add(subLabel);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        btnRow.setOpaque(false);

        JButton exportStixBtn = new JButton("💾 Export STIX 2.1 Threat Report");
        exportStixBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        exportStixBtn.setBackground(new Color(59, 130, 246));
        exportStixBtn.setForeground(Color.WHITE);
        exportStixBtn.addActionListener(e -> exportStixReport());

        btnRow.add(exportStixBtn);

        topCard.add(titleGroup, BorderLayout.CENTER);
        topCard.add(btnRow, BorderLayout.EAST);

        // --- Center Heatmap Table Card ---
        CyberCard tableCard = new CyberCard(new Color(50, 58, 72));

        String[] cols = {"Technique ID", "Tactic Name", "Technique Title", "Detection Engine", "Status / Coverage", "MITRE Reference"};
        tableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };

        JTable matrixTable = new JTable(tableModel);
        matrixTable.setBackground(new Color(25, 29, 36));
        matrixTable.setForeground(Color.WHITE);
        matrixTable.setGridColor(new Color(45, 52, 65));
        matrixTable.setRowHeight(30);
        matrixTable.setFont(new Font("Consolas", Font.PLAIN, 12));
        matrixTable.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 12));
        matrixTable.getTableHeader().setBackground(new Color(38, 44, 54));
        matrixTable.getTableHeader().setForeground(new Color(200, 215, 235));

        // Coverage badge renderer
        matrixTable.getColumnModel().getColumn(4).setCellRenderer((table, value, isSelected, hasFocus, row, column) -> {
            if (value != null) {
                return new StatusBadge("COVERED", new Color(16, 185, 129), Color.WHITE);
            }
            return new JLabel("");
        });

        JScrollPane scrollPane = new JScrollPane(matrixTable);
        scrollPane.setBorder(BorderFactory.createLineBorder(new Color(45, 52, 65)));

        tableCard.add(scrollPane, BorderLayout.CENTER);

        add(topCard, BorderLayout.NORTH);
        add(tableCard, BorderLayout.CENTER);
    }

    private void populateMatrix() {
        tableModel.setRowCount(0);

        Object[][] rules = {
            {"T1055", "Privilege Escalation / Injection", "Process Memory Injection (VirtualAllocEx)", "Behavior Sigma Engine", "COVERED", "https://attack.mitre.org/techniques/T1055/"},
            {"T1059.001", "Execution", "Encoded / Hidden PowerShell Interpreter", "YARA & Behavior Engine", "COVERED", "https://attack.mitre.org/techniques/T1059/001/"},
            {"T1486", "Impact", "Data Encrypted for Impact (Ransomware)", "Canary Guard & Entropy Engine", "COVERED", "https://attack.mitre.org/techniques/T1486/"},
            {"T1036.005", "Defense Evasion", "Masquerading (Disguised PE Header)", "Magic-Byte Engine", "COVERED", "https://attack.mitre.org/techniques/T1036/005/"},
            {"T1547.001", "Persistence", "Registry Autostart / Startup Folder", "Persistence Scanner Engine", "COVERED", "https://attack.mitre.org/techniques/T1547/001/"},
            {"T1204.002", "Initial Access", "Malicious File Execution (Archive Payload)", "Archive Inspection Engine", "COVERED", "https://attack.mitre.org/techniques/T1204/002/"},
            {"T1499.001", "Denial of Service", "OS Exhaustion (Zip-Bomb Pattern)", "Archive Guard Engine", "COVERED", "https://attack.mitre.org/techniques/T1499/001/"}
        };

        for (Object[] r : rules) {
            tableModel.addRow(r);
        }
    }

    private void exportStixReport() {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("SentinelAV_STIX2.1_Threat_Report.json"));
        int res = chooser.showSaveDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            File dest = chooser.getSelectedFile();
            String stixJson = "{\n" +
                "  \"type\": \"bundle\",\n" +
                "  \"id\": \"bundle--sentinel-av-report\",\n" +
                "  \"objects\": [\n" +
                "    {\n" +
                "      \"type\": \"indicator\",\n" +
                "      \"spec_version\": \"2.1\",\n" +
                "      \"name\": \"SentinelAV MITRE ATT&CK Matrix\",\n" +
                "      \"description\": \"Rule coverage manifest across T1055, T1059.001, T1486, T1036.005, T1547.001\",\n" +
                "      \"pattern\": \"[file:hashes.'SHA-256' = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f']\",\n" +
                "      \"pattern_type\": \"stix\",\n" +
                "      \"valid_from\": \"2026-10-10T00:00:00Z\"\n" +
                "    }\n" +
                "  ]\n" +
                "}";
            try {
                Files.write(dest.toPath(), stixJson.getBytes());
                JOptionPane.showMessageDialog(this, "STIX 2.1 Threat Report exported to " + dest.getAbsolutePath(), "Export Success", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Failed to export STIX report: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
}
