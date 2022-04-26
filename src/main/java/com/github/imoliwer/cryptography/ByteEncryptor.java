package com.github.imoliwer.cryptography;

/**
 * This interface represents an object of which is in relation to, and/or itself an encryptor.
 */
@FunctionalInterface
public interface ByteEncryptor {
    byte[] encrypt(byte[] handle);
}