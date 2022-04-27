package com.github.imoliwer.cryptography;

import org.junit.jupiter.api.*;

import java.security.Key;

import static java.nio.charset.StandardCharsets.UTF_8;
import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;
import static org.junit.jupiter.api.Assertions.assertEquals;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
abstract class CipherTest<T, K extends Key> {
    private final Class<? extends T> typeClass;
    private final ByteCipher<K> cipher;
    private final T expectedSmall;
    private final T expectedLarge;

    protected CipherTest(Class<? extends T> typeClass, ByteCipher<K> cipher, T expectedSmall, T expectedLarge) {
        this.typeClass = typeClass;
        this.cipher = cipher;
        this.expectedSmall = expectedSmall;
        this.expectedLarge = expectedLarge;
    }

    @BeforeAll
    void notifyBeforeAll() {
        System.out.printf("---------< Test - %s >---------\n", getClass().getSimpleName());
    }

    @Test void small() {
        test("Small", this.expectedSmall);
    }

    @Test void large() {
        test("Large", this.expectedLarge);
    }

    @AfterAll
    void notifyAfterAll() {
        System.out.printf(
            "-----------------------------%s\n",
            "-".repeat(getClass().getSimpleName().length())
        );
    }

    private void test(String test, T expected) {
        final byte[] encrypted = cipher.cipher(ENCRYPT_MODE, toBytes(expected));
        final T actual = fromBytes(cipher.cipher(DECRYPT_MODE, encrypted));
        System.out.printf("%s(expected = '%s', actual = '%s')\n", test, expected, actual);
        assertEquals(expected, actual);
    }

    protected T fromBytes(byte[] handle) {
        if (isString()) {
            return (T) new String(handle, UTF_8);
        }
        throw new RuntimeException("'fromBytes(byte[])' not implemented");
    }

    protected byte[] toBytes(T handle) {
        if (isString()) {
            return ((String) handle).getBytes(UTF_8);
        }
        throw new RuntimeException("'toBytes(Object)' not implemented");
    }

    private boolean isString() {
        return String.class.isAssignableFrom(this.typeClass);
    }
}