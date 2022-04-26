package com.github.imoliwer.cryptography;

import com.github.imoliwer.cryptography.ciphers.SingleCipher;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;

import java.security.NoSuchAlgorithmException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.emptySet;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class SingleTest {
    private static final String ALGORITHM = "AES";
    private static final String EXPECTED_SMALL = "hello world";
    private final SingleCipher cipher;

    public SingleTest() throws NoSuchAlgorithmException {
        this.cipher = new SingleCipher(
            ALGORITHM,
            emptySet(),
            KeyGenerator
                .getInstance(ALGORITHM)
                .generateKey()
        );
    }

    @Test
    void small() {
        final byte[] encrypted = cipher.encrypt(EXPECTED_SMALL.getBytes(UTF_8));

        assertEquals(
            EXPECTED_SMALL,
            new String(cipher.decrypt(encrypted), UTF_8)
        );
    }
}