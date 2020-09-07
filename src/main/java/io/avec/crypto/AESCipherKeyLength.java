package io.avec.crypto;

/**
 *
 * Three possible options for an AES key length.
 */
public enum AESCipherKeyLength {
    BIT_128(128),
    BIT_192(192),
    BIT_256(256);

    private final int length;

    AESCipherKeyLength(int length) {
        this.length = length;
    }

    public int getLength() {
        return length;
    }

    public static AESCipherKeyLength getAESKeyLength(int encryptionStrength) {
        AESCipherKeyLength aesCipherKeyLength;
        switch (encryptionStrength) {
            case 128:
                aesCipherKeyLength = AESCipherKeyLength.BIT_128;
                break;
            case 192:
                aesCipherKeyLength = AESCipherKeyLength.BIT_192;
                break;
            default:
                aesCipherKeyLength = AESCipherKeyLength.BIT_256;
        }
        return aesCipherKeyLength;
    }
}
