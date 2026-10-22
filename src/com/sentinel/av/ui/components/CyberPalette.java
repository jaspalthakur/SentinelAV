package com.sentinel.av.ui.components;

import java.awt.Color;
import java.awt.Font;

public class CyberPalette {
    // ------------------------------------------------------------------ Core
    public static final Color BACKGROUND = new Color(11, 16, 32);     // #0B1020
    public static final Color SURFACE = new Color(19, 26, 46);        // #131A2E
    public static final Color SURFACE_HOVER = new Color(28, 38, 64);  // #1C2640
    public static final Color SURFACE_ACTIVE = new Color(36, 48, 76); // #24304C
    public static final Color BORDER = new Color(31, 42, 68);         // #1F2A44
    public static final Color BORDER_ACTIVE = new Color(59, 130, 246); // #3B82F6
    public static final Color BORDER_FOCUS = new Color(99, 102, 241); // #6366F1
    public static final Color DIVIDER = new Color(255, 255, 255, 18); // subtle separator

    // ----------------------------------------------------------------- Typography
    public static final Color TEXT_PRIMARY = new Color(230, 234, 242); // #E6EAF2
    public static final Color TEXT_SECONDARY = new Color(154, 167, 189); // #9AA7BD
    public static final Color TEXT_MUTED = new Color(110, 125, 150);   // #6E7D96
    public static final Color TEXT_INVERSE = new Color(11, 16, 32);    // text on accent

    // ----------------------------------------------------------------- Semantic / Severity
    public static final Color SAFE = new Color(34, 197, 94);          // #22C55E
    public static final Color SAFE_BG = new Color(20, 70, 40);
    public static final Color WARNING = new Color(245, 158, 11);      // #F59E0B
    public static final Color WARNING_BG = new Color(90, 63, 7);
    public static final Color THREAT = new Color(239, 68, 68);        // #EF4444
    public static final Color THREAT_BG = new Color(74, 20, 20);
    public static final Color ACCENT = new Color(59, 130, 246);       // #3B82F6
    public static final Color ACCENT_BG = new Color(30, 58, 138);
    public static final Color PURPLE = new Color(168, 85, 247);       // #A855F7
    public static final Color PURPLE_BG = new Color(70, 30, 100);
    public static final Color INFO = new Color(14, 165, 233);         // #0EA5E9

    // ----------------------------------------------------------------- Button / interactive states
    public static final Color BTN_PRIMARY_BG = ACCENT;
    public static final Color BTN_PRIMARY_BG_HOVER = new Color(37, 99, 235);
    public static final Color BTN_PRIMARY_FG = Color.WHITE;
    public static final Color BTN_SECONDARY_BG = SURFACE_HOVER;
    public static final Color BTN_SECONDARY_BG_HOVER = SURFACE_ACTIVE;
    public static final Color BTN_SECONDARY_FG = TEXT_PRIMARY;
    public static final Color BTN_DANGER_BG = new Color(185, 28, 28);
    public static final Color BTN_DANGER_BG_HOVER = new Color(153, 27, 27);
    public static final Color BTN_DANGER_FG = Color.WHITE;
    public static final Color BTN_GHOST_BG = new Color(0, 0, 0, 0);
    public static final Color BTN_GHOST_BG_HOVER = SURFACE_HOVER;
    public static final Color BTN_GHOST_FG = TEXT_SECONDARY;
    public static final Color BTN_DISABLED_BG = new Color(45, 52, 65);
    public static final Color BTN_DISABLED_FG = new Color(110, 125, 150);

    // ----------------------------------------------------------------- Input / focus
    public static final Color INPUT_BG = new Color(15, 20, 34);
    public static final Color INPUT_BORDER = BORDER;
    public static final Color INPUT_FOCUS_BORDER = BORDER_FOCUS;
    public static final Color PLACEHOLDER = new Color(110, 125, 150);

    // ----------------------------------------------------------------- Misc
    public static final Color SHADOW = new Color(0, 0, 0, 60);
    public static final Color GLASS = new Color(255, 255, 255, 8);

    // ----------------------------------------------------------------- Fonts
    public static final Font FONT_TITLE_LARGE = new Font("Segoe UI", Font.BOLD, 22);
    public static final Font FONT_TITLE_MEDIUM = new Font("Segoe UI", Font.BOLD, 16);
    public static final Font FONT_TITLE_SMALL = new Font("Segoe UI", Font.BOLD, 14);
    public static final Font FONT_BODY_BOLD = new Font("Segoe UI", Font.BOLD, 13);
    public static final Font FONT_BODY = new Font("Segoe UI", Font.PLAIN, 13);
    public static final Font FONT_SMALL = new Font("Segoe UI", Font.PLAIN, 12);
    public static final Font FONT_CAPTION = new Font("Segoe UI", Font.PLAIN, 11);
    public static final Font FONT_CODE = new Font("Consolas", Font.PLAIN, 12);
    public static final Font FONT_ICON = new Font("Segoe UI Emoji", Font.PLAIN, 14);
}
