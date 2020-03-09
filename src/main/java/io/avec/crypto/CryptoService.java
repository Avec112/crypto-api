package io.avec.crypto;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.utils.Utils;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Properties;

@Slf4j
@Service
public class CryptoService {

    // TODO not for production. Must be looked up from secure place like HashiCorp Vault or likewise
    private String KEY = "v9y$B&E)H@McQfTj"; // test overrides this via reflection
    private final String transformation = "AES/CTR/NoPadding";


    public String decode(String ciphertext) {

        SecretKeySpec key = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec iv = new IvParameterSpec(getBytesAsUtf8(KEY));

        byte [] input = Base64.getDecoder().decode(ciphertext);
        byte [] output = new byte[input.length];

        Properties properties = new Properties();
        try (CryptoCipher cipher = Utils.getCipherInstance(transformation, properties)) {
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            cipher.doFinal(input, 0, input.length, output, 0);
        } catch (Exception e) {
            log.error("Feil oppstod.", e);
        }
        return new String(output);
    }

    public String encode(String plaintext) {

        SecretKeySpec key = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec iv = new IvParameterSpec(getBytesAsUtf8(KEY));

        int length = plaintext.length();
        byte[] ciphertext = new byte[length];


        Properties properties = new Properties();

        try (CryptoCipher cipher = Utils.getCipherInstance(transformation, properties)) {
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8), 0, length, ciphertext, 0);
        } catch (Exception e) {
            log.error("Feil oppstod.", e);
        }
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    private static byte[] getBytesAsUtf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

}
