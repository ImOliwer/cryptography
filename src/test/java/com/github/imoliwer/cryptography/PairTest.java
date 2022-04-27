package com.github.imoliwer.cryptography;

import com.github.imoliwer.cryptography.ciphers.PairCipher;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static java.util.Collections.emptySet;

final class PairTest extends CipherTest<String, Key> {
    PairTest() throws NoSuchAlgorithmException {
        super(
            String.class,
            generateCipher(),
            "hello world",
            "some large here"
        );
    }

    private static PairCipher generateCipher() throws NoSuchAlgorithmException {
        final KeyPair keys = KeyPairGenerator
            .getInstance("RSA")
            .generateKeyPair();
        return new PairCipher(
            "RSA",
            emptySet(),
            keys.getPrivate(),
            keys.getPublic()
        );
    }
}