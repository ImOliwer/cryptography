package com.github.imoliwer.cryptography.ciphers;

import com.github.imoliwer.cryptography.helper.Converter;
import com.github.imoliwer.cryptography.helper.Transformer;

import javax.crypto.Cipher;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Set;

/**
 * This utility class holds the mutual usages of ciphers.
 */
final class MutualCipherUtil {
    /** No need for instantiation. **/
    private MutualCipherUtil() {
        throw new IllegalStateException("Mutual cannot be instantiated");
    }

    /**
     * Call the basic cipher operation.
     */
    static <Type, Options, K extends Key> Type basic(
        int mode,
        byte[] handle,
        Options options,
        K key,
        String algorithm,
        Converter<Type, Options> converter,
        Set<Transformer> transformers
    ) {
        if (mode != 1 && mode != 2) {
            throw new RuntimeException("Mode operation must be 1 (encryption) or 2 (decryption).");
        }

        try {
            final Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(mode, key);

            final Class<? extends Type> conversionType = converter == null ? null : converter.getConversionType();
            if (conversionType == null) {
                throw new RuntimeException("Missing converter");
            }

            byte[] finalized = cipher.doFinal(handle);
            if (conversionType == byte[].class || conversionType == Byte[].class) {
                return (Type) finalized;
            }

            for (Transformer transformer : transformers) {
                finalized = transformer.transform(mode, finalized);
            }

            return converter.convert(mode, finalized, options);
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException(ex);
        }
    }
}