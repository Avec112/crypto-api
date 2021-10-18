package io.avec.crypto.aes;

/**
 *
 * Three possible options for an AES key length.
 */
public enum EncryptionStrength {
    BIT_128(128),
    BIT_192(192),
    BIT_256(256);

    private final int length;

    EncryptionStrength(int length) {
        this.length = length;
    }

    public int getLength() {
        return length;
    }

    public static EncryptionStrength getAESKeyLength(int encryptionStrength) {
        switch (encryptionStrength) {
            case 128:
                return EncryptionStrength.BIT_128;
            case 192:
                return EncryptionStrength.BIT_192;
            default:
                return EncryptionStrength.BIT_256;
        }
    }
}
