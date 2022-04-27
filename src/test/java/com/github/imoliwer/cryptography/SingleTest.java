package com.github.imoliwer.cryptography;

import com.github.imoliwer.cryptography.ciphers.SingleCipher;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

import static java.util.Collections.emptySet;

final class SingleTest extends CipherTest<String, SecretKey> {
    SingleTest() throws NoSuchAlgorithmException {
        super(
            String.class,
            new SingleCipher(
                "AES",
                emptySet(),
                KeyGenerator
                    .getInstance("AES")
                    .generateKey()
            ),
            "hello world",
            "some large here"
        );
    }
}