package com.github.imoliwer.cryptography.ciphers;

import com.github.imoliwer.cryptography.helper.Transformer;

import javax.crypto.Cipher;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Set;

import static com.github.imoliwer.cryptography.helper.Transformer.DECRYPTION_RULE;
import static com.github.imoliwer.cryptography.helper.Transformer.ENCRYPTION_RULE;
import static com.github.imoliwer.cryptography.util.Checker.checkMode;

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
    static <K extends Key> byte[] basic(
        int mode,
        byte[] handle,
        K key,
        String algorithm,
        Set<Transformer> transformers
    ) {
        checkMode(mode);

        try {
            final Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(mode, key);

            if (mode == 1)
                handle = over(1, handle, transformers);

            byte[] finalized = cipher.doFinal(handle);
            if (mode == 2)
                finalized = over(2, finalized, transformers);

            return finalized;
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Loop over the transformers and handle transformations accordingly.
     */
    private static byte[] over(int mode, byte[] initial, Set<Transformer> transformers) {
        checkMode(mode);
        for (Transformer transformer : transformers) {
            if (!transformer.hasRule(mode == 1 ? ENCRYPTION_RULE : DECRYPTION_RULE)) {
                continue;
            }
            initial = transformer.transform(mode, initial);
        }
        return initial;
    }
}