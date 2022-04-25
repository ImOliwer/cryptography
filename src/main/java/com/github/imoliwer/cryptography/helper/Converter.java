package com.github.imoliwer.cryptography.helper;

import com.github.imoliwer.cryptography.data.StringOptions;
import org.jetbrains.annotations.NotNull;

import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * This interface represents a method of which is used
 * to convert a byte array (from) into a specific type (to).
 */
public interface Converter<To, Options> {
    /** {@link Converter} the default converter (byte array) - just returns the incoming bytes. **/
    Converter<byte[], Object> BYTE = new Converter<>() {
        @Override
        public byte[] convert(int opmode, byte[] from, Object $) {
            return from;
        }

        @Override
        public @NotNull Class<? extends byte[]> getConversionType() {
            return byte[].class;
        }
    };

    /** {@link Converter} the converter for strings. **/
    Converter<String, StringOptions> STRING = new Converter<>() {
        @Override
        public String convert(int opmode, byte[] from, StringOptions options) {
            final boolean isBase64 = options != null && options.isBase64();

            if (opmode == 1) {
                return isBase64 ? Base64.getEncoder().encodeToString(from) : new String(from, UTF_8);
            }

            return new String(isBase64 ? Base64.getDecoder().decode(from) : from, UTF_8);
        }

        @Override
        public @NotNull Class<? extends String> getConversionType() {
            return String.class;
        }
    };

    /**
     * Convert an array of bytes into said parameterized type.
     *
     * @param opmode {@link Integer} the cipher operation mode that was used.
     * @param from {@link Byte} array of bytes to be converted.
     * @param options {@link Options} the options involved in ciphering (if any, null otherwise).
     * @return {@link To}
     */
    To convert(int opmode, byte[] from, Options options);

    /**
     * Get the type of class of this converter.
     *
     * @return {@link Class}
     */
    @NotNull Class<? extends To> getConversionType();
}