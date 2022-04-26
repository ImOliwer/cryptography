package com.github.imoliwer.cryptography.ciphers;

import com.github.imoliwer.cryptography.ByteCipher;
import com.github.imoliwer.cryptography.helper.Transformer;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Set;

import static java.util.Collections.emptySet;

/**
 * This implementation of {@link ByteCipher} represents a <b><i>LARGE</i></b> pair cipher,
 * in this case the order of encryption and decryption is different to be able to
 * consist of larger bytes of data.
 */
public final class LargePairCipher implements ByteCipher<Key> {
    private final SingleCipher dataCipher;
    private final PairCipher secondaryCipher;

    /**
     * Large {@link PairCipher} instantiation.
     *
     * @param pairAlgorithm {@link String} the algorithm one wish to use for the pair cipher.
     * @param transformers  {@link Set<Transformer>} initial transformers to handle data before conversion.
     * @param privateKey    {@link PrivateKey} the private key to decrypt with.
     * @param publicKey     {@link PublicKey} the public key to encrypt with.
     * @param dataKey       {@link SecretKey} the secret key used to encrypt and decrypt all data before and after ciphering with private & public.
     */
    public LargePairCipher(
        String pairAlgorithm,
        Set<Transformer> transformers,
        PrivateKey privateKey,
        PublicKey publicKey,
        SecretKey dataKey
    ) {
        this.dataCipher = new SingleCipher("AES", emptySet(), dataKey);
        this.secondaryCipher = new PairCipher(pairAlgorithm, transformers, privateKey, publicKey);
    }

    /** @see ByteCipher#cipher(int, byte[]) **/
    @Override
    public byte[] cipher(int mode, byte[] handle) {
        final byte[] data = dataCipher.cipher(mode, handle, null);
        return secondaryCipher.cipher(mode, data);
    }
}