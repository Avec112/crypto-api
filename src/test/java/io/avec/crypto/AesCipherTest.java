package io.avec.crypto;

import io.avec.crypto.aes.AesCipher;
import io.avec.crypto.domain.CipherText;
import io.avec.crypto.domain.Password;
import io.avec.crypto.domain.PlainText;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AesCipherTest {


    @ParameterizedTest
    @CsvSource({
            "CTR, 128",
            "CTR, 192",
            "CTR, 256",
            "GCM, 128",
            "GCM, 192",
            "GCM, 256"
    })
    void testAesCipher(String encryptionMode, int encryptionStrength) throws Exception {
        final AesCipher aesCipher = new AesCipher(encryptionMode, encryptionStrength);
        final PlainText plaintextOriginal = new PlainText("Secret text");
        final Password password = new Password("password");

        // encrypt
        CipherText cipherText = aesCipher.encrypt(plaintextOriginal, password);

        // decrypt
        PlainText plainText = aesCipher.decrypt(cipherText, password);

        assertEquals(plaintextOriginal.getValue(), plainText.getValue());
    }

}