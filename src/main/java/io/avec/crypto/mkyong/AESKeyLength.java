package io.avec.crypto.mkyong;

/**
 *
 * The only current options for an AES key length.
 */
public enum AESKeyLength {
    BIT_128(128),
    BIT_192(192),
    BIT_256(256);

    private final int length;

    AESKeyLength(int length) {
        this.length = length;
    }

    public int getLength() {
        return length;
    }
}
