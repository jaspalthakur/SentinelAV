package com.sentinel.av.ui;

import com.sentinel.av.core.ActivityLogger;
import com.sentinel.av.core.SignatureDatabase;
import com.sentinel.av.model.VirusSignature;
import com.sentinel.av.ui.components.CyberButton;
import com.sentinel.av.ui.components.CyberCard;
import com.sentinel.av.ui.components.CyberPalette;
import com.sentinel.av.ui.components.StatusBadge;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumnModel;
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
        setBackground(CyberPalette.BACKGROUND);
        setBorder(new EmptyBorder(25, 25, 25, 25));

        initComponents();
        refreshTable();
    }

    private void initComponents() {
        // --- Top Header Card ---
        CyberCard topCard = new CyberCard(CyberPalette.BORDER);

        JLabel titleLabel = new JLabel("\uD83E\uDCDC  Virus Signature Database & Definitions");
        titleLabel.setFont(CyberPalette.FONT_TITLE_SMALL);
        titleLabel.setForeground(CyberPalette.TEXT_PRIMARY);

        countLabel = new JLabel("Total Loaded Signatures: 0");
        countLabel.setFont(CyberPalette.FONT_SMALL);
        countLabel.setForeground(CyberPalette.TEXT_SECONDARY);

        JPanel titleContainer = new JPanel(new GridLayout(2, 1, 4, 4));
        titleContainer.setOpaque(false);
        titleContainer.add(titleLabel);
        titleContainer.add(countLabel);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        btnRow.setOpaque(false);

        CyberButton addSigBtn = new CyberButton("\u2795  Add Custom Signature", CyberButton.PRIMARY);
        addSigBtn.setFont(CyberPalette.FONT_SMALL);
        addSigBtn.addActionListener(e -> showAddSignatureDialog());

        CyberButton generateEicarBtn = new CyberButton("\uD83E\uDEAA  Create EICAR Test File", CyberButton.SECONDARY);
        generateEicarBtn.setFont(CyberPalette.FONT_SMALL);
        generateEicarBtn.addActionListener(e -> generateEicarFile());

        btnRow.add(addSigBtn);
        btnRow.add(generateEicarBtn);

        topCard.add(titleContainer, BorderLayout.CENTER);
        topCard.add(btnRow, BorderLayout.EAST);

        // --- Center Table Card ---
        CyberCard tableCard = new CyberCard(CyberPalette.BORDER);

        String[] cols = {"ID", "Threat Name", "Type", "Hash / Pattern", "Severity", "Description"};
        tableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        signaturesTable = new JTable(tableModel) {
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
        signaturesTable.setForeground(CyberPalette.TEXT_PRIMARY);
        signaturesTable.setGridColor(CyberPalette.BORDER);
        signaturesTable.setRowHeight(30);
        signaturesTable.setFont(CyberPalette.FONT_BODY);
        signaturesTable.getTableHeader().setFont(CyberPalette.FONT_BODY_BOLD);
        signaturesTable.getTableHeader().setBackground(CyberPalette.SURFACE_HOVER);
        signaturesTable.getTableHeader().setForeground(CyberPalette.TEXT_PRIMARY);
        signaturesTable.getTableHeader().setReorderingAllowed(false);
        signaturesTable.setAutoCreateRowSorter(true);
        signaturesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        signaturesTable.setIntercellSpacing(new Dimension(0, 1));

        // Severity renderer
        signaturesTable.getColumnModel().getColumn(4).setCellRenderer((table, value, isSelected, hasFocus, row, column) -> {
            if (value != null) {
                return StatusBadge.createSeverityBadge(value.toString());
            }
            return new JLabel("");
        });

        JScrollPane scrollPane = new JScrollPane(signaturesTable);
        scrollPane.setBorder(BorderFactory.createLineBorder(CyberPalette.BORDER));
        scrollPane.getViewport().setBackground(CyberPalette.BACKGROUND);

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

        JPanel panel = new JPanel(new GridLayout(5, 2, 10, 10));
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

        for (Component c : panel.getComponents()) {
            if (c instanceof JLabel) {
                ((JLabel) c).setForeground(CyberPalette.TEXT_PRIMARY);
                ((JLabel) c).setFont(CyberPalette.FONT_BODY);
            } else if (c instanceof JComboBox<?> || c instanceof JTextField) {
                c.setFont(CyberPalette.FONT_BODY);
                c.setBackground(CyberPalette.INPUT_BG);
                c.setForeground(CyberPalette.TEXT_PRIMARY);
            }
        }

        int res = JOptionPane.showConfirmDialog(this, panel, "Add New Virus Definition",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (res == JOptionPane.OK_OPTION) {
            String name = nameField.getText().trim();
            String type = (String) typeBox.getSelectedItem();
            String value = valueField.getText().trim();
            VirusSignature.Severity sev = (VirusSignature.Severity) severityBox.getSelectedItem();
            String desc = descField.getText().trim();

            if (name.isEmpty() || value.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Name and Hash/Pattern fields cannot be empty.", "Error",
                        JOptionPane.ERROR_MESSAGE);
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
            JOptionPane.showMessageDialog(this, "Signature added successfully!", "Added",
                    JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void generateEicarFile() {
        try {
            File desktop = new File(System.getProperty("user.home"), "Desktop");
            if (!desktop.exists()) {
                desktop = new File(System.getProperty("user.home"));
            }

            File eicarFile = new File(desktop, "eicar_test_virus.txt");
            String eicarContent = "X5O!P%@AP[4\\PZX54(P^)7CC)$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

            Files.write(eicarFile.toPath(), eicarContent.getBytes());

            JOptionPane.showMessageDialog(this,
                "EICAR test malware file generated at:\n" + eicarFile.getAbsolutePath()
                    + "\n\nYou can now run a scan or use Real-Time Guard to test detection!",
                "Safe EICAR Generated", JOptionPane.INFORMATION_MESSAGE);

            ActivityLogger.getInstance().info("Signatures",
                "Generated EICAR test file at " + eicarFile.getAbsolutePath());

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Failed to create EICAR test file: " + ex.getMessage(), "Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }
}
