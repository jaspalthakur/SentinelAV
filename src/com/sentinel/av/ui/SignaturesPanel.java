package com.sentinel.av.ui;

import com.sentinel.av.core.ActivityLogger;
import com.sentinel.av.core.SignatureDatabase;
import com.sentinel.av.model.VirusSignature;
import com.sentinel.av.ui.components.StatusBadge;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.util.List;

public class SignaturesPanel extends JPanel {

    private final MainFrame mainFrame;
    private final SignatureDatabase db;

    private DefaultTableModel tableModel;
    private JTable signaturesTable;
    private JLabel countLabel;

    public SignaturesPanel(MainFrame mainFrame) {
        this.mainFrame = mainFrame;
        this.db = SignatureDatabase.getInstance();
        setLayout(new BorderLayout(15, 15));
        setBackground(new Color(24, 27, 33));
        setBorder(new EmptyBorder(25, 25, 25, 25));

        initComponents();
        refreshTable();
    }

    private void initComponents() {
        // --- Top Header Card ---
        JPanel topCard = new JPanel(new BorderLayout(10, 10));
        topCard.setBackground(new Color(33, 37, 44));
        topCard.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(50, 56, 68), 1),
            new EmptyBorder(15, 20, 15, 20)
        ));

        JLabel titleLabel = new JLabel("🧬 Virus Signature Database & Definitions");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        titleLabel.setForeground(Color.WHITE);

        countLabel = new JLabel("Total Loaded Signatures: 0");
        countLabel.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        countLabel.setForeground(new Color(170, 185, 205));

        JPanel titleContainer = new JPanel(new GridLayout(2, 1, 4, 4));
        titleContainer.setOpaque(false);
        titleContainer.add(titleLabel);
        titleContainer.add(countLabel);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        btnRow.setOpaque(false);

        JButton addSigBtn = new JButton("➕ Add Custom Signature");
        addSigBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        addSigBtn.setBackground(new Color(40, 120, 200));
        addSigBtn.setForeground(Color.WHITE);
        addSigBtn.addActionListener(e -> showAddSignatureDialog());

        JButton generateEicarBtn = new JButton("🧪 Create EICAR Test File");
        generateEicarBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        generateEicarBtn.setBackground(new Color(45, 130, 75));
        generateEicarBtn.setForeground(Color.WHITE);
        generateEicarBtn.addActionListener(e -> generateEicarFile());

        btnRow.add(addSigBtn);
        btnRow.add(generateEicarBtn);

        topCard.add(titleContainer, BorderLayout.CENTER);
        topCard.add(btnRow, BorderLayout.EAST);

        // --- Center Table Card ---
        JPanel tableCard = new JPanel(new BorderLayout(10, 10));
        tableCard.setBackground(new Color(33, 37, 44));
        tableCard.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(50, 56, 68), 1),
            new EmptyBorder(15, 20, 15, 20)
        ));

        String[] cols = {"ID", "Threat Name", "Type", "Hash / Pattern", "Severity", "Description"};
        tableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };

        signaturesTable = new JTable(tableModel);
        signaturesTable.setBackground(new Color(25, 29, 36));
        signaturesTable.setForeground(Color.WHITE);
        signaturesTable.setGridColor(new Color(45, 52, 65));
        signaturesTable.setRowHeight(28);
        signaturesTable.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        signaturesTable.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 12));
        signaturesTable.getTableHeader().setBackground(new Color(38, 44, 54));
        signaturesTable.getTableHeader().setForeground(new Color(200, 215, 235));

        // Severity renderer
        signaturesTable.getColumnModel().getColumn(4).setCellRenderer((table, value, isSelected, hasFocus, row, column) -> {
            if (value != null) {
                return StatusBadge.createSeverityBadge(value.toString());
            }
            return new JLabel("");
        });

        JScrollPane scrollPane = new JScrollPane(signaturesTable);
        scrollPane.setBorder(BorderFactory.createLineBorder(new Color(45, 52, 65)));

        tableCard.add(scrollPane, BorderLayout.CENTER);

        add(topCard, BorderLayout.NORTH);
        add(tableCard, BorderLayout.CENTER);
    }

    public void refreshTable() {
        tableModel.setRowCount(0);
        List<VirusSignature> sigs = db.getAllSignatures();
        for (VirusSignature s : sigs) {
            tableModel.addRow(new Object[]{
                s.getId(),
                s.getName(),
                s.getHashType(),
                s.isPattern() ? s.getPattern() : s.getHash(),
                s.getSeverity().name(),
                s.getDescription()
            });
        }
        countLabel.setText("Total Loaded Signatures: " + sigs.size());
    }

    private void showAddSignatureDialog() {
        JTextField nameField = new JTextField();
        JComboBox<String> typeBox = new JComboBox<>(new String[]{"MD5", "SHA-256", "Pattern"});
        JTextField valueField = new JTextField();
        JComboBox<VirusSignature.Severity> severityBox = new JComboBox<>(VirusSignature.Severity.values());
        JTextField descField = new JTextField();

        JPanel panel = new JPanel(new GridLayout(5, 2, 8, 8));
        panel.add(new JLabel("Threat Name:"));
        panel.add(nameField);
        panel.add(new JLabel("Type:"));
        panel.add(typeBox);
        panel.add(new JLabel("Hash / Pattern:"));
        panel.add(valueField);
        panel.add(new JLabel("Severity:"));
        panel.add(severityBox);
        panel.add(new JLabel("Description:"));
        panel.add(descField);

        int res = JOptionPane.showConfirmDialog(this, panel, "Add New Virus Definition", JOptionPane.OK_CANCEL_OPTION);
        if (res == JOptionPane.OK_OPTION) {
            String name = nameField.getText().trim();
            String type = (String) typeBox.getSelectedItem();
            String value = valueField.getText().trim();
            VirusSignature.Severity sev = (VirusSignature.Severity) severityBox.getSelectedItem();
            String desc = descField.getText().trim();

            if (name.isEmpty() || value.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Name and Hash/Pattern fields cannot be empty.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            String id = "SIG-" + (db.getSignatureCount() + 1000);
            VirusSignature sig;
            if ("Pattern".equalsIgnoreCase(type)) {
                sig = new VirusSignature(id, name, value, sev, desc, true);
            } else {
                sig = new VirusSignature(id, name, value, type, sev, desc);
            }

            db.addCustomSignature(sig);
            refreshTable();
            mainFrame.updateDashboardStats();
            ActivityLogger.getInstance().info("Signatures", "Added custom signature: " + name);
            JOptionPane.showMessageDialog(this, "Signature added successfully!", "Added", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void generateEicarFile() {
        try {
            File desktop = new File(System.getProperty("user.home"), "Desktop");
            if (!desktop.exists()) desktop = new File(System.getProperty("user.home"));

            File eicarFile = new File(desktop, "eicar_test_virus.txt");
            String eicarContent = "X5O!P%@AP[4\\PZX54(P^)7CC)$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

            Files.write(eicarFile.toPath(), eicarContent.getBytes());

            JOptionPane.showMessageDialog(this,
                "EICAR test malware file generated at:\n" + eicarFile.getAbsolutePath() + 
                "\n\nYou can now run a scan or use Real-Time Guard to test detection!",
                "Safe EICAR Generated",
                JOptionPane.INFORMATION_MESSAGE);

            ActivityLogger.getInstance().info("Signatures", "Generated EICAR test file at " + eicarFile.getAbsolutePath());

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Failed to create EICAR test file: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
}
