package com.github.imoliwer.cryptography.ciphers;

import com.github.imoliwer.cryptography.ByteCipher;
import com.github.imoliwer.cryptography.helper.Converter;
import com.github.imoliwer.cryptography.helper.Transformer;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Set;

import static com.github.imoliwer.cryptography.ciphers.MutualCipherUtil.basic;

/**
 * This implementation of {@link ByteCipher} represents a 'key-pair' (private & public) cipher.
 *
 * @param <Type> the type to be converted to from bytes.
 * @param <Options> the options of said type.
 */
public final class PairCipher<Type, Options> extends
    ByteCipher<Type, Options, Key, PairCipher<Type, Options>> {
    /** {@link PrivateKey} the key to decrypt with. **/
    private final PrivateKey privateKey;

    /** {@link PublicKey} the key to encrypt with. **/
    private final PublicKey publicKey;

    /**
     * Single cipher instantiation.
     *
     * @param algorithm {@link String} the algorithm one wish to use.
     * @param privateKey {@link PrivateKey} the private key to decrypt bytes with.
     * @param publicKey {@link PublicKey} the public key to encrypt bytes with.
     * @param converter {@link Converter} the converter to handle type conversion after completion.
     * @param transformers {@link Set<Transformer>} initial transformers to before conversion.
     */
    public PairCipher(
        String algorithm,
        Converter<Type, Options> converter,
        Set<Transformer> transformers,
        PrivateKey privateKey,
        PublicKey publicKey
    ) {
        super(algorithm, converter, transformers);
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /** @see ByteCipher#cipher(int, byte[], Object, Key) **/
    @Override
    public Type cipher(int mode, byte[] handle, Options options) {
        return basic(
            mode,
            handle,
            options,
            mode == 1 ? publicKey : privateKey,
            this.algorithm,
            this.converter,
            this.transformers
        );
    }
}