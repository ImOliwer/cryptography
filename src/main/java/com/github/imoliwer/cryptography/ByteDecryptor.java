package com.github.imoliwer.cryptography;

/**
 * This interface represents an object of which is in relation to, and/or itself a decryptor.
 */
@FunctionalInterface
public interface ByteDecryptor {
    byte[] decrypt(byte[] handle);
}