package com.github.imoliwer.cryptography;

import com.github.imoliwer.cryptography.helper.Converter;
import com.github.imoliwer.cryptography.helper.Transformer;
import org.jetbrains.annotations.NotNull;

import java.security.Key;
import java.util.LinkedHashSet;
import java.util.Set;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

/**
 * This abstract class represents the base of a byte array cipher.
 */
public abstract class ByteCipher<Type, Options, K extends Key, Me extends ByteCipher<Type, Options, K, Me>>
    implements ByteEncryptor<Type, Options>, ByteDecryptor<Type, Options> {
    /** {@link String} the algorithm to be used in this cipher. **/
    protected final String algorithm;

    /** {@link Converter} the converter used to convert a byte array to {@link Type} accordingly. **/
    protected final Converter<Type, Options> converter;

    /** {@link Set<Transformer>} a set of transformers to handle the byte array of finalized ciphers. **/
    protected final Set<Transformer> transformers;

    /**
     * Byte cipher instantiation.
     *
     * @param algorithm {@link String} the algorithm one wish to use.
     * @param converter {@link Converter} the converter to handle type conversion after completion.
     * @param transformers {@link Set<Transformer>} initial transformers to before conversion.
     */
    protected ByteCipher(
        String algorithm,
        Converter<Type, Options> converter,
        Set<Transformer> transformers
    ) {
        this.algorithm = algorithm;
        this.converter = converter;
        this.transformers = new LinkedHashSet<>(transformers);
    }

    /**
     * Add a transformer to the existing set of transformers.
     *
     * @param transformer {@link Transformer} the instance to be added.
     * @return {@link Me} current instance.
     */
    public final @NotNull Me withTransformer(Transformer transformer) {
        if (transformer == null)
            throw new NullPointerException("Transformer must not be null");
        transformers.add(transformer);
        return (Me) this;
    }

    /** @see ByteCipher#cipher(int, byte[], Object) **/
    @Override
    public final Type encrypt(byte[] handle, Options options) {
        return this.cipher(ENCRYPT_MODE, handle, options);
    }

    /** @see ByteCipher#cipher(int, byte[], Object) **/
    @Override
    public final Type decrypt(byte[] handle, Options options) {
        return this.cipher(DECRYPT_MODE, handle, options);
    }

    /**
     * Cipher a byte array of data with corresponding operation mode & options using
     * an internal {@link Key}.
     *
     * @param mode {@link Integer} the operation mode to use (encryption=1, decryption=2).
     * @param handle {@link Byte} array of bytes to cipher.
     * @param options {@link Options} the options related to this cipher.
     * @return {@link Type} converted value after finalization of the cipher.
     */
    public abstract Type cipher(int mode, byte[] handle, Options options);

    /**
     * Cipher a byte array of data with corresponding operation mode & options
     * using passed down key ({@link K}), rather than internal.
     *
     * @param mode {@link Integer} the operation mode to use (encryption=1, decryption=2).
     * @param handle {@link Byte} array of bytes to cipher.
     * @param options {@link Options} the options related to this cipher.
     * @param key {@link K} the key to be used.
     * @return {@link Type} converted value after finalization of the cipher.
     */
    public Type cipher(int mode, byte[] handle, Options options, K key) {
        throw new UnsupportedOperationException();
    }
}