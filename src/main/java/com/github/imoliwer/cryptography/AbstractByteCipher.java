package com.github.imoliwer.cryptography;

import com.github.imoliwer.cryptography.helper.Transformer;
import org.jetbrains.annotations.NotNull;

import java.security.Key;
import java.util.LinkedHashSet;
import java.util.Set;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

/**
 * This abstract class represents the outer base of a byte array cipher.
 */
public abstract class AbstractByteCipher<K extends Key, Me extends AbstractByteCipher<K, Me>>
    implements ByteCipher<K>, ByteEncryptor, ByteDecryptor {
    /** {@link String} the algorithm to be used in this cipher. **/
    protected final String algorithm;

    /** {@link Set<Transformer>} a set of transformers to handle the byte arrays before encryption and after decryption, depending on the state of said rules. **/
    protected final Set<Transformer> transformers;

    /**
     * Byte cipher instantiation.
     *
     * @param algorithm    {@link String} the algorithm one wish to use.
     * @param transformers {@link Set<Transformer>} initial transformers.
     */
    protected AbstractByteCipher(
        String algorithm,
        Set<Transformer> transformers
    ) {
        this.algorithm = algorithm;
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

    /** @see ByteCipher#cipher(int, byte[]) **/
    @Override
    public final byte[] encrypt(byte[] handle) {
        return this.cipher(ENCRYPT_MODE, handle);
    }

    /** @see ByteCipher#cipher(int, byte[]) **/
    @Override
    public final byte[] decrypt(byte[] handle) {
        return this.cipher(DECRYPT_MODE, handle);
    }
}