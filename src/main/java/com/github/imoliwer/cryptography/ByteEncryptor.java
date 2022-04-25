package com.github.imoliwer.cryptography;

/**
 * This interface represents an object of which is in relation to, and/or itself an encryptor.
 */
@FunctionalInterface
public interface ByteEncryptor<Type, Options> {
    Type encrypt(byte[] handle, Options options);
}