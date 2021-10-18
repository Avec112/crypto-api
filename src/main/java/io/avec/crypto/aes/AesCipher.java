package io.avec.crypto.aes;

import io.avec.crypto.domain.CipherText;
import io.avec.crypto.domain.Password;
import io.avec.crypto.domain.PlainText;
import io.avec.crypto.exception.BadCipherTextException;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;

@Slf4j
@Getter
public class AesCipher {

    private static final int SALT_LENGTH_BYTE = 16;
    private final EncryptionMode algorithm;
    private final EncryptionStrength keyLength;

    public AesCipher(String encryptionMode, int encryptionStrength) {
        this.algorithm = EncryptionMode.valueOf(encryptionMode);
        this.keyLength = EncryptionStrength.getAESKeyLength(encryptionStrength);
    }

    public CipherText encrypt(PlainText plainText, Password password) throws Exception {

        log.debug("{}@{}", getAlgorithm(), getKeyLength().getLength());
        log.debug("plainText: {}", plainText.getValue());

        // 16 bytes salt
        byte[] salt = AesCipherUtils.getRandomNonce(SALT_LENGTH_BYTE);

        // 12 bytes GCM vs 16 bytes CTR
        byte[] iv = AesCipherUtils.getRandomNonce(getAlgorithm().getIvLength());

        // secret key from password
        Key key = AesCipherUtils.getAESKeyFromPassword(password.getValue().toCharArray(), salt, getKeyLength());

        Cipher cipher = Cipher.getInstance(getAlgorithm().getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, key, getAlgorithm().getAlgorithmParameterSpec(iv));
        byte [] cText = cipher.doFinal(plainText.getValue().getBytes(StandardCharsets.UTF_8));

        // Concat IV+SALT+CIPHERTEXT
        final byte[] cipherText = ByteBuffer.allocate(iv.length + salt.length + cText.length)
                .put(iv)
                .put(salt)
                .put(cText)
                .array();
        final String cipherTextEncoded = Base64.getEncoder().encodeToString(cipherText);
        log.debug("cipherText: {}", cipherTextEncoded);
        return new CipherText(cipherTextEncoded);
    }

    public PlainText decrypt(CipherText cipherText, Password password) throws Exception {
        try {
            log.debug("{}@{}", getAlgorithm(), getKeyLength().getLength());
            final String cipherTextEncoded = cipherText.getValue();
            log.debug("cipherText: {}", cipherTextEncoded);
            final byte[] cipherTextBytes = Base64.getDecoder().decode(cipherTextEncoded);

            ByteBuffer bb = ByteBuffer.wrap(cipherTextBytes); // IV+SALT+CIPHERTEXT

            // 12 bytes GCM vs 16 bytes CTR
            int IV_LENGTH_BYTE = getAlgorithm().getIvLength();
            byte[] iv = new byte[IV_LENGTH_BYTE];
            bb.get(iv);

            // 16 bytes salt
            byte[] salt = new byte[SALT_LENGTH_BYTE];
            bb.get(salt);

            byte[] cText = new byte[bb.remaining()];
            bb.get(cText);

            // secret key from password
            Key key = AesCipherUtils.getAESKeyFromPassword(password.getValue().toCharArray(), salt, getKeyLength());

            Cipher cipher = Cipher.getInstance(getAlgorithm().getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, key, getAlgorithm().getAlgorithmParameterSpec(iv));
            final byte[] bytes = cipher.doFinal(cText);
            log.debug("plainText: {}", new String(bytes));
            return new PlainText(new String(bytes));
        } catch (BufferUnderflowException e) {
            throw new BadCipherTextException("Please provide valid and correct cipher text");
        }
    }

}
