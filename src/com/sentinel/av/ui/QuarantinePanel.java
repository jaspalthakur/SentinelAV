package com.sentinel.av.ui;

import com.sentinel.av.core.QuarantineManager;
import com.sentinel.av.model.QuarantineItem;
import com.sentinel.av.model.ScanResult;
import com.sentinel.av.ui.components.CyberButton;
import com.sentinel.av.ui.components.CyberCard;
import com.sentinel.av.ui.components.CyberPalette;
import com.sentinel.av.ui.components.StatusBadge;
import com.sentinel.av.ui.components.ThreatDetailDialog;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.List;

public class QuarantinePanel extends JPanel {

    private final MainFrame mainFrame;
    private final QuarantineManager qManager;

    private DefaultTableModel tableModel;
    private JTable quarantineTable;
    private JLabel itemCountLabel;

    public QuarantinePanel(MainFrame mainFrame) {
        this.mainFrame = mainFrame;
        this.qManager = QuarantineManager.getInstance();
        setLayout(new BorderLayout(15, 15));
        setBackground(CyberPalette.BACKGROUND);
        setBorder(new EmptyBorder(25, 25, 25, 25));

        initComponents();
        refreshTable();
    }

    private void initComponents() {
        // --- Top Header Card ---
        CyberCard topCard = new CyberCard(CyberPalette.BORDER);

        JLabel titleLabel = new JLabel("\uD83D\uDD12  Quarantine Vault (AES-256 Encrypted)");
        titleLabel.setFont(CyberPalette.FONT_TITLE_SMALL);
        titleLabel.setForeground(CyberPalette.TEXT_PRIMARY);

        itemCountLabel = new JLabel("Total Encrypted Vault Items: 0");
        itemCountLabel.setFont(CyberPalette.FONT_SMALL);
        itemCountLabel.setForeground(CyberPalette.TEXT_SECONDARY);

        JPanel titleContainer = new JPanel(new GridLayout(2, 1, 4, 4));
        titleContainer.setOpaque(false);
        titleContainer.add(titleLabel);
        titleContainer.add(itemCountLabel);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        btnRow.setOpaque(false);

        CyberButton inspectBtn = new CyberButton("\uD83D\uDD0D  Inspect Risk Reasons", CyberButton.PRIMARY);
        inspectBtn.setFont(CyberPalette.FONT_SMALL);
        inspectBtn.addActionListener(e -> showSelectedThreatDetail());

        CyberButton restoreBtn = new CyberButton("\u21A9  Restore File", CyberButton.SECONDARY);
        restoreBtn.setFont(CyberPalette.FONT_SMALL);
        restoreBtn.addActionListener(e -> restoreSelected());

        CyberButton deleteBtn = new CyberButton("\uD83D\uDDD1\uFE0F  Delete File", CyberButton.DANGER);
        deleteBtn.setFont(CyberPalette.FONT_SMALL);
        deleteBtn.addActionListener(e -> deleteSelected());

        btnRow.add(inspectBtn);
        btnRow.add(restoreBtn);
        btnRow.add(deleteBtn);

        topCard.add(titleContainer, BorderLayout.CENTER);
        topCard.add(btnRow, BorderLayout.EAST);

        // --- Center Table Card ---
        CyberCard tableCard = new CyberCard(CyberPalette.BORDER);

        String[] cols = {"File Name", "Threat Name", "Risk Score", "Severity", "Date Quarantined", "Original Path"};
        tableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        quarantineTable = new JTable(tableModel) {
            // Zebra striping for readability
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
        quarantineTable.setForeground(CyberPalette.TEXT_PRIMARY);
        quarantineTable.setGridColor(CyberPalette.BORDER);
        quarantineTable.setRowHeight(30);
        quarantineTable.setFont(CyberPalette.FONT_BODY);
        quarantineTable.getTableHeader().setFont(CyberPalette.FONT_BODY_BOLD);
        quarantineTable.getTableHeader().setBackground(CyberPalette.SURFACE_HOVER);
        quarantineTable.getTableHeader().setForeground(CyberPalette.TEXT_PRIMARY);
        quarantineTable.getTableHeader().setReorderingAllowed(false);
        quarantineTable.setAutoCreateRowSorter(true);
        quarantineTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        quarantineTable.setIntercellSpacing(new Dimension(0, 1));

        // Severity renderer
        quarantineTable.getColumnModel().getColumn(3).setCellRenderer((table, value, isSelected, hasFocus, row, column) -> {
            if (value != null) {
                return StatusBadge.createSeverityBadge(value.toString());
            }
            return new JLabel("");
        });

        // Double click inspector
        quarantineTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    showSelectedThreatDetail();
                }
            }
        });

        JScrollPane scrollPane = new JScrollPane(quarantineTable);
        scrollPane.setBorder(BorderFactory.createLineBorder(CyberPalette.BORDER));
        scrollPane.getViewport().setBackground(CyberPalette.BACKGROUND);

        tableCard.add(scrollPane, BorderLayout.CENTER);

        add(topCard, BorderLayout.NORTH);
        add(tableCard, BorderLayout.CENTER);
    }

    public void refreshTable() {
        tableModel.setRowCount(0);
        List<QuarantineItem> items = qManager.getItems();
        for (QuarantineItem item : items) {
            tableModel.addRow(new Object[]{
                item.getFileName(),
                item.getThreatName(),
                item.getRiskScore() + "/100",
                item.getSeverity() != null ? item.getSeverity().name() : "HIGH",
                item.getQuarantineTimeFormatted(),
                item.getOriginalPath()
            });
        }
        itemCountLabel.setText("Total Encrypted Vault Items: " + items.size());
    }

    /** Maps the selected view row to the model index, so sorting stays consistent. */
    private int selectedModelRow() {
        int viewRow = quarantineTable.getSelectedRow();
        if (viewRow < 0) {
            return -1;
        }
        return quarantineTable.convertRowIndexToModel(viewRow);
    }

    private void showSelectedThreatDetail() {
        int selectedRow = selectedModelRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(this, "Please select an item from the quarantine vault.",
                    "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        List<QuarantineItem> items = qManager.getItems();
        if (selectedRow < items.size()) {
            QuarantineItem item = items.get(selectedRow);

            ScanResult dummyResult = new ScanResult(
                new File(item.getOriginalPath()),
                item.getFileSize(),
                new com.sentinel.av.core.RiskScoreEngine.RiskScoreBreakdown(
                    item.getRiskScore(),
                    com.sentinel.av.core.RiskScoreEngine.Verdict.HIGH_RISK,
                    item.getReasons(),
                    item.getThreatName()
                ),
                "AES-256 Vault Item",
                "Quarantine Vault Engine"
            );

            ThreatDetailDialog dialog = new ThreatDetailDialog(
                SwingUtilities.getWindowAncestor(this),
                dummyResult,
                null,
                () -> deleteSelected()
            );
            dialog.setVisible(true);
        }
    }

    private void restoreSelected() {
        int selectedRow = selectedModelRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(this,
                    "Please select a quarantined file from the table.", "No Selection",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        List<QuarantineItem> items = qManager.getItems();
        if (selectedRow < items.size()) {
            QuarantineItem item = items.get(selectedRow);
            int confirm = JOptionPane.showConfirmDialog(this,
                "Are you sure you want to RESTORE file: " + item.getFileName() + " back to original location?\nLocation: "
                    + item.getOriginalPath(),
                "Confirm AES-256 Decryption & Restore", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);

            if (confirm == JOptionPane.YES_OPTION) {
                if (qManager.restoreFile(item)) {
                    JOptionPane.showMessageDialog(this, "File restored and AES decrypted successfully!", "Restored",
                            JOptionPane.INFORMATION_MESSAGE);
                    refreshTable();
                    mainFrame.updateDashboardStats();
                } else {
                    JOptionPane.showMessageDialog(this, "Failed to restore file.", "Error",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }
    }

    private void deleteSelected() {
        int selectedRow = selectedModelRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(this,
                    "Please select a quarantined file to delete.", "No Selection",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        List<QuarantineItem> items = qManager.getItems();
        if (selectedRow < items.size()) {
            QuarantineItem item = items.get(selectedRow);
            Object[] options = {"Delete Forever", "Cancel"};
            int confirm = JOptionPane.showOptionDialog(this,
                "Permanently delete file: " + item.getFileName() + "? This action cannot be undone!",
                "Confirm Delete", JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE,
                null, options, options[1]);

            if (confirm == 0) {
                if (qManager.deletePermanently(item)) {
                    refreshTable();
                    mainFrame.updateDashboardStats();
                }
            }
        }
    }
}
