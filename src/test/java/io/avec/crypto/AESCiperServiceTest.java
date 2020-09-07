package io.avec.crypto;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AESCiperServiceTest {

    private final AESCiperService service = new AESCiperService();

    @ParameterizedTest
    @EnumSource(AESCipherAlgorithm.class)
    void testAES128(AESCipherAlgorithm algorithm) throws Exception {
        ReflectionTestUtils.setField(service, "algorithm", algorithm);
        String plaintext = "Secret text";
        byte[] ciperText = service.encrypt128Bit(plaintext.getBytes(StandardCharsets.UTF_8), "password");
        byte[] decryptetText = service.decrypt128Bit(ciperText, "password");
        assertEquals(plaintext, new String(decryptetText));
    }

    @ParameterizedTest
    @EnumSource(AESCipherAlgorithm.class)
    void testAES192(AESCipherAlgorithm algorithm) throws Exception {
        ReflectionTestUtils.setField(service, "algorithm", algorithm);
        String plaintext = "Secret text";
        byte[] ciperText = service.encrypt192Bit(plaintext.getBytes(StandardCharsets.UTF_8), "password");
        byte[] decryptetText = service.decrypt192Bit(ciperText, "password");
        assertEquals(plaintext, new String(decryptetText));
    }

    @ParameterizedTest
    @EnumSource(AESCipherAlgorithm.class)
    void testAES256(AESCipherAlgorithm algorithm) throws Exception {
        ReflectionTestUtils.setField(service, "algorithm", algorithm);
        String plaintext = "Secret text";
        byte[] ciperText = service.encrypt256Bit(plaintext.getBytes(StandardCharsets.UTF_8), "password");
        byte[] decryptetText = service.decrypt256Bit(ciperText, "password");
        assertEquals(plaintext, new String(decryptetText));
    }

    @ParameterizedTest
    @CsvSource({
            "GCM,BIT_128",
            "CTR,BIT_128",
            "GCM,BIT_192",
            "CTR,BIT_192",
            "GCM,BIT_256",
            "CTR,BIT_256"
    })
    void testAES(String algorithm, String keyLength) throws Exception {
        ReflectionTestUtils.setField(service, "algorithm", AESCipherAlgorithm.valueOf(algorithm));
        String plaintext = "Secret text";
        byte[] ciperText = service.encrypt(plaintext.getBytes(StandardCharsets.UTF_8), "password", AESCipherKeyLength.valueOf(keyLength));
        byte[] decryptetText = service.decrypt(ciperText, "password", AESCipherKeyLength.valueOf(keyLength));
        assertEquals(plaintext, new String(decryptetText));
    }
}