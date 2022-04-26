package com.github.imoliwer.cryptography.util;

/**
 * This utility class represents a "checker".
 */
public final class Checker {
    /** No need for instantiation. **/
    private Checker() {
        throw new IllegalStateException("Checker cannot be instantiated");
    }

    /**
     * Check if a mode is it's expected range.
     *
     * @param mode {@link Integer} the operation mode to check.
     */
    public static void checkMode(int mode) {
        if (mode == 1 || mode == 2)
            return;
        throw new RuntimeException("Mode operation must be 1 (encryption) or 2 (decryption).");
    }
}