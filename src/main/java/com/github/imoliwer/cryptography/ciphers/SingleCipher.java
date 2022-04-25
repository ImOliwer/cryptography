package com.github.imoliwer.cryptography.ciphers;

import com.github.imoliwer.cryptography.ByteCipher;
import com.github.imoliwer.cryptography.helper.Converter;
import com.github.imoliwer.cryptography.helper.Transformer;

import java.security.Key;
import java.util.Set;

import static com.github.imoliwer.cryptography.ciphers.MutualCipherUtil.basic;

/**
 * This implementation of {@link ByteCipher} represents a 'single key' cipher.
 *
 * @param <Type> the type to be converted to from bytes.
 * @param <Options> the options of said type.
 */
public final class SingleCipher<Type, Options> extends
    ByteCipher<Type, Options, Key, SingleCipher<Type, Options>> {
    /** {@link Key} the key to cipher and decipher with. **/
    private final Key key;

    /**
     * Single cipher instantiation.
     *
     * @param algorithm {@link String} the algorithm one wish to use.
     * @param key {@link Key} the key to cipher and decipher bytes with.
     * @param converter {@link Converter} the converter to handle type conversion after completion.
     * @param transformers {@link Set<Transformer>} initial transformers to before conversion.
     */
    public SingleCipher(
        String algorithm,
        Converter<Type, Options> converter,
        Set<Transformer> transformers,
        Key key
    ) {
        super(algorithm, converter, transformers);
        this.key = key;
    }

    /** @see ByteCipher#cipher(int, byte[], Object, Key) **/
    @Override
    public Type cipher(int mode, byte[] handle, Options options) {
        return this.cipher(mode, handle, options, this.key);
    }

    /** @see ByteCipher#cipher(int, byte[], Object, Key) **/
    @Override
    public Type cipher(int mode, byte[] handle, Options options, Key secretKey) {
        return basic(
            mode,
            handle,
            options,
            secretKey,
            this.algorithm,
            this.converter,
            this.transformers
        );
    }
}