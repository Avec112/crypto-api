package io.avec.crypto;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.security.Key;

/**
 * Encryption Service
 *
 * This service supports ASE GCM (default) and AES CTR.
 * The encryption uses secure random instansiation vector (IV) 12 bytes for GCM and 16 bytes for CTR.
 * The key is generated from provided password and salt (16 bytes) generating a 256 bits key with 65000 iteration. Good luck hacking that!
 *
 * The Encrypted returned value contains IV+SALT+CIPHERTEXT
 *
 * The only thing to be held confidential is the password!
 *
 * Read more:
 * - Security Best Practices: Symmetric Encryption with AES in Java and Android by Patrick Favre-Bulle
 * - Java AES encryption and decryption - Mkyong.com
 *
 */
@Slf4j
@Service
public class AESCiperService {

    // Remember! Stored encrypted values already has its algo set!
    @Value("${algorithm:GCM}")
    private AESCipherAlgorithm algorithm;
    private static final int SALT_LENGTH_BYTE = 16;

    public byte [] decrypt128Bit(byte [] cipherText, String password) throws Exception {
        return decrypt(cipherText, password, AESCipherKeyLength.BIT_128);
    }

    public byte [] decrypt192Bit(byte [] cipherText, String password) throws Exception {
        return decrypt(cipherText, password, AESCipherKeyLength.BIT_192);
    }

    public byte [] decrypt256Bit(byte [] cipherText, String password) throws Exception {
        return decrypt(cipherText, password, AESCipherKeyLength.BIT_256);
    }

    public byte [] decrypt(byte [] cipherText, String password, AESCipherKeyLength aesCipherKeyLength) throws Exception {
        ByteBuffer bb = ByteBuffer.wrap(cipherText); // IV+SALT+CIPHERTEXT

        // 12 bytes GCM vs 16 bytes CTR
        int IV_LENGTH_BYTE = algorithm.getIvLength();
        byte [] iv = new byte[IV_LENGTH_BYTE];
        bb.get(iv);

        // 16 bytes salt
        byte[] salt = new byte[SALT_LENGTH_BYTE];
        bb.get(salt);

        byte[] cText = new byte[bb.remaining()];
        bb.get(cText);

        // secret key from password
        Key key = AESCipherUtils.getAESKeyFromPassword(password.toCharArray(), salt, aesCipherKeyLength);

        log.debug("AES algorithm: {}", algorithm.getAlgorithm());
        Cipher cipher = Cipher.getInstance(algorithm.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, key, algorithm.getAlgorithmParameterSpec(iv));
        return cipher.doFinal(cText);

    }

    public byte [] encrypt128Bit(byte [] plainText, String password) throws Exception {
        return encrypt(plainText, password, AESCipherKeyLength.BIT_128);
    }

    public byte [] encrypt192Bit(byte [] plainText, String password) throws Exception {
        return encrypt(plainText, password, AESCipherKeyLength.BIT_192);
    }

    public byte [] encrypt256Bit(byte [] plainText, String password) throws Exception {
        return encrypt(plainText, password, AESCipherKeyLength.BIT_256);
    }

    public byte [] encrypt(byte [] plainText, String password, AESCipherKeyLength aesCipherKeyLength) throws Exception {

        // 16 bytes salt
        byte[] salt = AESCipherUtils.getRandomNonce(SALT_LENGTH_BYTE);

        // 12 bytes GCM vs 16 bytes CTR
        byte[] iv = AESCipherUtils.getRandomNonce(algorithm.getIvLength());

        // secret key from password
        Key key = AESCipherUtils.getAESKeyFromPassword(password.toCharArray(), salt, aesCipherKeyLength);

        Cipher cipher = Cipher.getInstance(algorithm.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, key, algorithm.getAlgorithmParameterSpec(iv));
        byte [] cText = cipher.doFinal(plainText);

        // Concat IV+SALT+CIPHERTEXT
        return ByteBuffer.allocate(iv.length + salt.length + cText.length)
                .put(iv)
                .put(salt)
                .put(cText)
                .array();
    }



}
