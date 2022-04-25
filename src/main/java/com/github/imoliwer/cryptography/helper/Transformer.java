package com.github.imoliwer.cryptography.helper;

/**
 * This interface represents the base of data (byte array)
 * transformations before finalizing the ciphers.
 */
public interface Transformer {
    /** {@link Byte} the encryption rule. **/
    byte ENCRYPTION_RULE = 1 << 1;

    /** {@link Byte} the decryption rule. **/
    byte DECRYPTION_RULE = 1 << 2;

    /**
     * Transform a byte array of data accordingly.
     *
     * @param opmode {@link Integer} the operation mode that
     * @param handle
     * @return
     */
    byte[] transform(int opmode, byte[] handle);

    /**
     * The rules of this transformer.
     * <br/>
     * Example:
     * <br/>
     * <code>
     *     int rules() {
     *         <br/>
     *         // return DECRYPTION_RULE; <- single
     *         <br/>
     *         // return ENCRYPTION_RULE; <- single
     *         <br/>
     *         // return ENCRYPTION_RULE | DECRYPTION_RULE; <- both
     *         <br/>
     *     }
     * </code>
     *
     * @return {@link Integer}
     */
    int rules();
}