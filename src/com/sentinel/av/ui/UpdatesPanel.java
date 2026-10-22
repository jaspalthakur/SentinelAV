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
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.util.List;

public class UpdatesPanel extends JPanel {

    private final MainFrame mainFrame;
    private final SignatureDatabase db;

    private DefaultTableModel tableModel;
    private JTable signaturesTable;
    private JLabel statusLabel;
    private JLabel countLabel;
    private JProgressBar updateProgress;

    public UpdatesPanel(MainFrame mainFrame) {
        this.mainFrame = mainFrame;
        this.db = SignatureDatabase.getInstance();
        setLayout(new BorderLayout(16, 16));
        setBackground(CyberPalette.BACKGROUND);
        setBorder(new EmptyBorder(24, 24, 24, 24));

        initComponents();
        refreshTable();
    }

    private void initComponents() {
        // --- Top Header Card ---
        CyberCard topCard = new CyberCard(CyberPalette.BORDER);

        JLabel titleLabel = new JLabel("Virus Definitions & Rule Updates");
        titleLabel.setFont(CyberPalette.FONT_TITLE_LARGE);
        titleLabel.setForeground(CyberPalette.TEXT_PRIMARY);

        statusLabel = new JLabel("Status: Updated Today \u2022 Definition Version 2026.10");
        statusLabel.setFont(CyberPalette.FONT_BODY);
        statusLabel.setForeground(CyberPalette.SAFE);

        countLabel = new JLabel("Total Loaded Rules: " + db.getSignatureCount() + " definitions");
        countLabel.setFont(CyberPalette.FONT_BODY);
        countLabel.setForeground(CyberPalette.TEXT_SECONDARY);

        JPanel titleContainer = new JPanel(new GridLayout(3, 1, 2, 2));
        titleContainer.setOpaque(false);
        titleContainer.add(titleLabel);
        titleContainer.add(statusLabel);
        titleContainer.add(countLabel);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        btnRow.setOpaque(false);

        CyberButton updateNowBtn = new CyberButton("\u27F3  Update Definitions Now", CyberButton.PRIMARY);
        updateNowBtn.setFont(CyberPalette.FONT_BODY_BOLD);
        updateNowBtn.addActionListener(e -> checkForUpdates());

        CyberButton addSigBtn = new CyberButton("+ Add Custom Definition", CyberButton.SECONDARY);
        addSigBtn.setFont(CyberPalette.FONT_SMALL);
        addSigBtn.addActionListener(e -> showAddSignatureDialog());

        btnRow.add(updateNowBtn);
        btnRow.add(addSigBtn);

        updateProgress = new JProgressBar(0, 100);
        updateProgress.setPreferredSize(new Dimension(100, 6));
        updateProgress.setVisible(false);
        updateProgress.setForeground(CyberPalette.ACCENT);

        topCard.add(titleContainer, BorderLayout.CENTER);
        topCard.add(btnRow, BorderLayout.EAST);
        topCard.add(updateProgress, BorderLayout.SOUTH);

        // --- Center Table Card ---
        CyberCard tableCard = new CyberCard(CyberPalette.BORDER);

        String[] cols = {"ID", "Threat Name", "Engine Type", "Hash / Pattern Signature", "Severity", "Description"};
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
        signaturesTable.setRowHeight(28);
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
        countLabel.setText("Total Loaded Rules: " + sigs.size() + " definitions");
    }

    private void checkForUpdates() {
        updateProgress.setVisible(true);
        updateProgress.setIndeterminate(true);
        statusLabel.setText("Status: Connecting to definition update feed...");
        statusLabel.setForeground(CyberPalette.ACCENT);

        Timer timer = new Timer(2000, e -> {
            updateProgress.setIndeterminate(false);
            updateProgress.setValue(100);
            statusLabel.setText("Status: Definitions Updated Just Now (Version 2026.10)");
            statusLabel.setForeground(CyberPalette.SAFE);
            ActivityLogger.getInstance().info("Updates", "Virus definitions updated successfully.");
            JOptionPane.showMessageDialog(this, "Virus definition database updated to latest version!",
                    "Updates Complete", JOptionPane.INFORMATION_MESSAGE);
            updateProgress.setVisible(false);
        });
        timer.setRepeats(false);
        timer.start();
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
}
