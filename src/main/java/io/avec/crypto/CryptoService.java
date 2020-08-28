package io.avec.crypto;

import io.avec.crypto.mkyong.CryptoUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

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
public class CryptoService {

    // Remember! Stored encrypted values already has its aglo set!
    @Value("${algorithm:GCM}")
    private EncryptionAlgorithm algorithm;

    private static final int SALT_LENGTH_BYTE = 16;


    public String decrypt(String ciphertext, String password) throws Exception {
        if(StringUtils.isBlank(ciphertext)) {
            throw new IllegalArgumentException("Argument ciphertext must be provided");
        }
        if(StringUtils.isBlank(password)) {
            throw new IllegalArgumentException("Argument password must be provided");
        }


        byte [] cipherTextWithIvSalt = Base64.getDecoder().decode(ciphertext);
        ByteBuffer bb = ByteBuffer.wrap(cipherTextWithIvSalt); // IV+SALT+CIPHERTEXT

        int IV_LENGTH_BYTE = algorithm.getIvLength();
        byte [] iv = new byte[IV_LENGTH_BYTE];
        bb.get(iv);

        byte[] salt = new byte[SALT_LENGTH_BYTE];
        bb.get(salt);

        byte[] cText = new byte[bb.remaining()];
        bb.get(cText);

        // secret key from password
        Key key = CryptoUtils.getAESKeyFromPassword(password.toCharArray(), salt);


        Cipher cipher = Cipher.getInstance(algorithm.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, key, algorithm.getAlgorithmParameterSpec(iv));
        byte [] output = cipher.doFinal(cText);

        return new String(output, StandardCharsets.UTF_8);
    }



    public String encrypt(String plaintext, String password) throws Exception {
        if(StringUtils.isBlank(plaintext)) {
            throw new IllegalArgumentException("Argument plaintext must be provided");
        }
        if(StringUtils.isBlank(password)) {
            throw new IllegalArgumentException("Argument password must be provided");
        }

        // 16 bytes salt
        byte[] salt = CryptoUtils.getRandomNonce(SALT_LENGTH_BYTE);

        // 12 bytes GCM or 16 bytes CTR
        byte[] iv = CryptoUtils.getRandomNonce(algorithm.getIvLength());

        // secret key from password
        Key key = CryptoUtils.getAESKeyFromPassword(password.toCharArray(), salt);

        Cipher cipher = Cipher.getInstance(algorithm.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, key, algorithm.getAlgorithmParameterSpec(iv));
        byte [] cText = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // Concat IV+SALT+CIPHERTEXT
        byte [] cipherTextWithIvSalt = ByteBuffer.allocate(iv.length + salt.length + cText.length)
                .put(iv)
                .put(salt)
                .put(cText)
                .array();

        // Return as Base64
        return Base64.getEncoder().encodeToString(cipherTextWithIvSalt);
    }



}
