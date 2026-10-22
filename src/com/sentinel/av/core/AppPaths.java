package com.sentinel.av.core;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Single source of truth for where SentinelAV keeps its on-disk state.
 *
 * <p>By default everything lives under {@code %USERPROFILE%\.sentinel_av}. Pass
 * {@code -Dsentinelav.data.dir=<path>} to relocate the whole data directory, which
 * makes isolated test runs and portable installs possible.</p>
 */
public final class AppPaths {

    /** System property that overrides the default data directory. */
    public static final String DATA_DIR_PROPERTY = "sentinelav.data.dir";

    private AppPaths() {
    }

    public static Path dataDir() {
        String override = System.getProperty(DATA_DIR_PROPERTY);
        if (override != null && !override.isBlank()) {
            return Paths.get(override.trim()).toAbsolutePath().normalize();
        }
        return Paths.get(System.getProperty("user.home"), ".sentinel_av").toAbsolutePath().normalize();
    }

    public static Path quarantineDir() {
        return dataDir().resolve("quarantine");
    }

    public static Path logFile() {
        return dataDir().resolve("sentinel_activity.log");
    }

    public static Path signatureFile() {
        return dataDir().resolve("signatures.db");
    }
}
