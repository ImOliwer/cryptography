package com.github.imoliwer.cryptography;

import java.security.Key;

import static java.util.Base64.getDecoder;
import static java.util.Base64.getEncoder;

/**
 * This interface represents the absolute BASE for byte ciphers.
 */
public interface ByteCipher<K extends Key> {
    /**
     * Cipher a byte array of data with corresponding operation mode using
     * an internal {@link Key}.
     *
     * @param mode {@link Integer} the operation mode to use (encryption=1, decryption=2).
     * @param handle {@link Byte} array of bytes to cipher.
     * @return {@link Byte} array of bytes after finalization of the cipher.
     */
    byte[] cipher(int mode, byte[] handle);

    /**
     * Cipher a byte array of data with corresponding operation mode
     * using passed down key ({@link K}), rather than internal.
     *
     * @param mode {@link Integer} the operation mode to use (encryption=1, decryption=2).
     * @param handle {@link Byte} array of bytes to cipher.
     * @param key {@link K} the key to be used.
     * @return {@link Byte} array of bytes after finalization of the cipher.
     */
    default byte[] cipher(int mode, byte[] handle, K key) {
        throw new UnsupportedOperationException();
    }

    /**
     * Encode encrypted data into a base64 string.
     *
     * @param encrypted {@link Byte} array of bytes to be encoded.
     * @return {@link String}
     */
    static String toString(byte[] encrypted) {
        return getEncoder().encodeToString(encrypted);
    }

    /**
     * Decode a base64 string back into it's original byte array.
     *
     * @param string {@link String} the encoded string to decode.
     * @return {@link Byte} original byte array.
     */
    static byte[] fromString(String string) {
        return getDecoder().decode(string);
    }
}