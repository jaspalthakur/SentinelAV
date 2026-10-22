package com.sentinel.av.ui.components;

import com.sentinel.av.model.ScanResult;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.File;
import java.util.List;

public class ThreatDetailDialog extends JDialog {

    public ThreatDetailDialog(Window owner, ScanResult result, Runnable onQuarantine, Runnable onDelete) {
        super(owner, "🚨 Threat Verdict & Explainable Risk Analysis", ModalityType.APPLICATION_MODAL);
        setSize(620, 520);
        setLocationRelativeTo(owner);
        setLayout(new BorderLayout(15, 15));

        JPanel mainPanel = new JPanel(new BorderLayout(15, 15));
        mainPanel.setBackground(new Color(24, 28, 36));
        mainPanel.setBorder(new EmptyBorder(20, 25, 20, 25));

        // --- Top Header Card ---
        JPanel headerCard = new JPanel(new BorderLayout(15, 10));
        headerCard.setOpaque(false);

        JLabel titleLabel = new JLabel("🚨 " + result.getThreatName());
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 18));
        titleLabel.setForeground(new Color(239, 68, 68));

        JLabel subLabel = new JLabel("Detection Engine: " + result.getDetectionMethod());
        subLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        subLabel.setForeground(new Color(170, 185, 205));

        // MITRE ATT&CK + matched hash: the "why am I seeing this" line
        List<String> techniques = result.getAttackTechniques();
        StringBuilder detail = new StringBuilder();
        if (!techniques.isEmpty()) {
            detail.append("MITRE ATT&CK: ").append(String.join(", ", techniques));
        }
        if (result.getMatchedHash() != null && !result.getMatchedHash().isBlank()) {
            if (detail.length() > 0) detail.append("   |   ");
            detail.append("SHA-256: ").append(result.getMatchedHash());
        }
        if (detail.length() == 0) detail.append("SHA-256: not matched against known signatures");
        JLabel detailLabel = new JLabel(detail.toString());
        detailLabel.setFont(new Font("Consolas", Font.PLAIN, 11));
        detailLabel.setForeground(new Color(140, 155, 175));

        JPanel titleGroup = new JPanel(new GridLayout(3, 1, 2, 2));
        titleGroup.setOpaque(false);
        titleGroup.add(titleLabel);
        titleGroup.add(subLabel);
        titleGroup.add(detailLabel);

        StatusBadge severityBadge = StatusBadge.createSeverityBadge(
            result.getSeverity() != null ? result.getSeverity().name() : "HIGH"
        );

        headerCard.add(titleGroup, BorderLayout.CENTER);
        headerCard.add(severityBadge, BorderLayout.EAST);

        // --- Middle Content: Score & Explainable Reasons ---
        JPanel centerGrid = new JPanel(new BorderLayout(15, 15));
        centerGrid.setOpaque(false);

        // Risk Meter Card
        CyberCard scoreCard = new CyberCard(new Color(60, 68, 82));
        scoreCard.setPreferredSize(new Dimension(180, 0));

        SecurityGaugePanel gauge = new SecurityGaugePanel();
        gauge.setSecurityScore(result.getRiskScore(), verdictLabelFor(result.getRiskScore()));
        scoreCard.add(gauge, BorderLayout.CENTER);

        // Reasons List Card
        CyberCard reasonsCard = new CyberCard(new Color(60, 68, 82));
        JLabel reasonsTitle = new JLabel("🔍 Explainable Risk Signals (" + result.getReasons().size() + " triggers):");
        reasonsTitle.setFont(new Font("Segoe UI", Font.BOLD, 14));
        reasonsTitle.setForeground(Color.WHITE);

        DefaultListModel<String> model = new DefaultListModel<>();
        for (String reason : result.getReasons()) {
            model.addElement("• " + reason);
        }
        if (model.isEmpty()) {
            model.addElement("• Hash matched with known malware definition.");
        }

        JList<String> list = new JList<>(model);
        list.setBackground(new Color(20, 24, 32));
        list.setForeground(new Color(220, 230, 245));
        list.setFont(new Font("Segoe UI", Font.PLAIN, 12));

        JScrollPane scroll = new JScrollPane(list);
        scroll.setBorder(BorderFactory.createLineBorder(new Color(45, 52, 65)));

        reasonsCard.add(reasonsTitle, BorderLayout.NORTH);
        reasonsCard.add(scroll, BorderLayout.CENTER);

        centerGrid.add(scoreCard, BorderLayout.WEST);
        centerGrid.add(reasonsCard, BorderLayout.CENTER);

        // --- Bottom File Info & Action Buttons ---
        JPanel bottomCard = new JPanel(new BorderLayout(10, 10));
        bottomCard.setOpaque(false);

        JTextArea pathText = new JTextArea("File Path: " + result.getFilePath() + "\nFile Size: " + result.getFileSize() + " bytes");
        pathText.setFont(new Font("Consolas", Font.PLAIN, 11));
        pathText.setForeground(new Color(160, 175, 195));
        pathText.setOpaque(false);
        pathText.setEditable(false);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        btnRow.setOpaque(false);

        JButton quarantineBtn = new JButton("🔒 Quarantine File");
        quarantineBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        quarantineBtn.setBackground(new Color(168, 85, 247));
        quarantineBtn.setForeground(Color.WHITE);
        quarantineBtn.addActionListener(e -> {
            dispose();
            if (onQuarantine != null) onQuarantine.run();
        });

        JButton deleteBtn = new JButton("🗑 Permanent Delete");
        deleteBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        deleteBtn.setBackground(new Color(185, 28, 28));
        deleteBtn.setForeground(Color.WHITE);
        deleteBtn.addActionListener(e -> {
            dispose();
            if (onDelete != null) onDelete.run();
        });

        JButton closeBtn = new JButton("Close");
        closeBtn.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        closeBtn.setBackground(new Color(45, 55, 70));
        closeBtn.setForeground(Color.WHITE);
        closeBtn.addActionListener(e -> dispose());

        btnRow.add(quarantineBtn);
        btnRow.add(deleteBtn);
        btnRow.add(closeBtn);

        bottomCard.add(pathText, BorderLayout.NORTH);
        bottomCard.add(btnRow, BorderLayout.SOUTH);

        mainPanel.add(headerCard, BorderLayout.NORTH);
        mainPanel.add(centerGrid, BorderLayout.CENTER);
        mainPanel.add(bottomCard, BorderLayout.SOUTH);

        setContentPane(mainPanel);
        getRootPane().setDefaultButton(closeBtn);

        // ESC closes the dialog.
        KeyStroke escape = KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_ESCAPE, 0);
        getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(escape, "ESCAPE");
        getRootPane().getActionMap().put("ESCAPE", new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                dispose();
            }
        });
    }

    private static String verdictLabelFor(int score) {
        if (score >= 95) return "CRITICAL THREAT";
        if (score >= 75) return "HIGH RISK";
        if (score >= 45) return "SUSPICIOUS";
        return "LOW RISK";
    }
}
