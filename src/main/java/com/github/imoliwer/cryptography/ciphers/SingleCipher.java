package com.github.imoliwer.cryptography.ciphers;

import com.github.imoliwer.cryptography.AbstractByteCipher;
import com.github.imoliwer.cryptography.helper.Transformer;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Set;

import static com.github.imoliwer.cryptography.ciphers.MutualCipherUtil.basic;

/**
 * This implementation of {@link AbstractByteCipher} represents a 'single key' cipher.
 */
public final class SingleCipher extends AbstractByteCipher<SecretKey, SingleCipher> {
    /** {@link SecretKey} the key to cipher and decipher with. **/
    private final SecretKey key;

    /**
     * Single cipher instantiation.
     *
     * @param algorithm    {@link String} the algorithm one wish to use.
     * @param key          {@link Key} the key to cipher and decipher bytes with.
     * @param transformers {@link Set<Transformer>} initial transformers to before conversion.
     */
    public SingleCipher(
        String algorithm,
        Set<Transformer> transformers,
        SecretKey key
    ) {
        super(algorithm, transformers);
        this.key = key;
    }

    /** @see AbstractByteCipher#cipher(int, byte[], Key) **/
    @Override
    public byte[] cipher(int mode, byte[] handle) {
        return this.cipher(mode, handle, this.key);
    }

    /** @see AbstractByteCipher#cipher(int, byte[], Key) **/
    @Override
    public byte[] cipher(int mode, byte[] handle, SecretKey secretKey) {
        return basic(
            mode,
            handle,
            secretKey,
            this.algorithm,
            this.transformers
        );
    }
}