package com.sentinel.av.ui.components;

import java.awt.Color;
import java.awt.Font;

public class CyberPalette {
    // Core Color Theme
    public static final Color BACKGROUND = new Color(11, 16, 32);     // #0B1020
    public static final Color SURFACE = new Color(19, 26, 46);        // #131A2E
    public static final Color SURFACE_HOVER = new Color(28, 38, 64);  // #1C2640
    public static final Color BORDER = new Color(31, 42, 68);         // #1F2A44
    public static final Color BORDER_ACTIVE = new Color(59, 130, 246); // #3B82F6

    // Typography Colors
    public static final Color TEXT_PRIMARY = new Color(230, 234, 242); // #E6EAF2
    public static final Color TEXT_SECONDARY = new Color(154, 167, 189); // #9AA7BD (High contrast)
    public static final Color TEXT_MUTED = new Color(110, 125, 150);

    // Severity Palette
    public static final Color SAFE = new Color(34, 197, 94);          // #22C55E (Green)
    public static final Color WARNING = new Color(245, 158, 11);      // #F59E0B (Amber)
    public static final Color THREAT = new Color(239, 68, 68);        // #EF4444 (Red)
    public static final Color ACCENT = new Color(59, 130, 246);       // #3B82F6 (Blue)
    public static final Color PURPLE = new Color(168, 85, 247);       // #A855F7

    // Fonts (Minimum 12-13px for secondary readability)
    public static final Font FONT_TITLE_LARGE = new Font("Segoe UI", Font.BOLD, 22);
    public static final Font FONT_TITLE_MEDIUM = new Font("Segoe UI", Font.BOLD, 16);
    public static final Font FONT_BODY_BOLD = new Font("Segoe UI", Font.BOLD, 13);
    public static final Font FONT_BODY = new Font("Segoe UI", Font.PLAIN, 13);
    public static final Font FONT_SMALL = new Font("Segoe UI", Font.PLAIN, 12);
    public static final Font FONT_CODE = new Font("Consolas", Font.PLAIN, 12);
}
