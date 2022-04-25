package com.github.imoliwer.cryptography.data;

import com.github.imoliwer.cryptography.helper.Converter;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

/**
 * The options for the string converter ({@link Converter#STRING}).
 */
public final class StringOptions {
    /** {@link Boolean} whether the string should be encoded to and decoded from Base64. **/
    private boolean base64;

    /**
     * No need for instantiation outside private states.
     */
    private StringOptions() {
        this.base64 = false;
    }

    /**
     * Apply the state of Base64 in this string options instance.
     *
     * @return {@link StringOptions}
     */
    public StringOptions withBase64() {
        this.base64 = true;
        return this;
    }

    /**
     * Get whether a string should be encoded to and decoded from Base64.
     *
     * @return {@link Boolean}
     */
    public boolean isBase64() {
        return this.base64;
    }

    /**
     * Create a new & clean instance of string options.
     *
     * @return {@link StringOptions}
     */
    @Contract(value = " -> new", pure = true)
    public static @NotNull StringOptions create() {
        return new StringOptions();
    }
}