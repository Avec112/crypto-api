package io.avec.crypto;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

@Slf4j
@Service
public class CryptoService {

    private final String transformation = "AES/CTR/PKCS5Padding";

    /**
     * Decrypt Ciphertext encrypted value to plain text
     * @param ciphertext object containing encrypted value, key and iv
     * @return Plaintext object containing plain value
     */
    public Plaintext decode(Ciphertext ciphertext) {
        return new Plaintext(decode(ciphertext.getValue(), ciphertext.getKey(), ciphertext.getIv()), null);
    }

    public String decode(String ciphertext, String key, String iv) {
        if(StringUtils.isBlank(ciphertext)) {
            throw new IllegalArgumentException("Argument ciphertext must be provided");
        }
        if(StringUtils.isBlank(key)) {
            throw new IllegalArgumentException("Argument key must be provided");
        }
        if(key.length() != 16) {
            throw new IllegalArgumentException("Argument key must be 16 bytes long");
        }
        if(StringUtils.isBlank(iv)) {
            throw new IllegalArgumentException("Argument iv must be provided");
        }
        if(iv.length() != 16) {
            throw new IllegalArgumentException("Argument iv must be 16 bytes long");
        }

        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(getBytesAsUtf8(iv));

        byte [] input = Base64.getDecoder().decode(ciphertext);
        byte [] output = new byte[input.length];

        try {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);
            cipher.doFinal(input, 0, input.length, output, 0);
        } catch (Exception e) {
            log.debug("Feil oppstod.", e);
        }

        return new String(output);
    }

    /**
     * Encrypt Plaintext value
     * @param plaintext object containing plain value and key
     * @return Ciphertext object containing encryptet value and iv
     */
    public Ciphertext encode(Plaintext plaintext) {
        String iv = RandomStringUtils.random(16, 0, 0, true, true, null, new SecureRandom());
        String encryptedValue = encode(plaintext.getValue(), plaintext.getKey(), iv);
        return new Ciphertext(encryptedValue, null, iv);
    }

    public String encode(String plaintext, String key, String iv) {
        if(StringUtils.isBlank(plaintext)) {
            throw new IllegalArgumentException("Argument plaintext must be provided");
        }
        if(StringUtils.isBlank(key)) {
            throw new IllegalArgumentException("Argument key must be provided");
        }
        if(key.length() != 16) {
            throw new IllegalArgumentException("Argument key must be 16 bytes long");
        }
        if(StringUtils.isBlank(iv)) {
            throw new IllegalArgumentException("Argument iv must be provided");
        }
        if(iv.length() != 16) {
            throw new IllegalArgumentException("Argument iv must be 16 bytes long");
        }

        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(getBytesAsUtf8(iv));

        int length = plaintext.length();
        byte[] ciphertext = new byte[length];


        try {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8), 0, length, ciphertext, 0);
        } catch (Exception e) {
            log.debug("Feil oppstod.", e);
        }
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    private static byte[] getBytesAsUtf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

}
