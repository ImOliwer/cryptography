package com.github.imoliwer.cryptography.ciphers;

import com.github.imoliwer.cryptography.AbstractByteCipher;
import com.github.imoliwer.cryptography.helper.Transformer;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Set;

import static com.github.imoliwer.cryptography.ciphers.MutualCipherUtil.basic;

/**
 * This implementation of {@link AbstractByteCipher} represents a 'key-pair' (private & public) cipher.
 */
public final class PairCipher extends AbstractByteCipher<Key, PairCipher> {
    /** {@link PrivateKey} the key to decrypt with. **/
    private final PrivateKey privateKey;

    /** {@link PublicKey} the key to encrypt with. **/
    private final PublicKey publicKey;

    /**
     * Single cipher instantiation.
     *
     * @param algorithm    {@link String} the algorithm one wish to use.
     * @param privateKey   {@link PrivateKey} the private key to decrypt bytes with.
     * @param publicKey    {@link PublicKey} the public key to encrypt bytes with.
     * @param transformers {@link Set<Transformer>} initial transformers to before conversion.
     */
    public PairCipher(
        String algorithm,
        Set<Transformer> transformers,
        PrivateKey privateKey,
        PublicKey publicKey
    ) {
        super(algorithm, transformers);
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /** @see AbstractByteCipher#cipher(int, byte[], Key) **/
    @Override
    public byte[] cipher(int mode, byte[] handle) {
        return basic(
            mode,
            handle,
            mode == 1 ? publicKey : privateKey,
            this.algorithm,
            this.transformers
        );
    }
}