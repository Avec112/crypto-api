package io.avec.crypto;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;


@RestController
@Slf4j
@RequestMapping("/api/v1")
public class AESCipherController {

    private final AESCiperService service;

    public AESCipherController(AESCiperService service) {
        this.service = service;
    }

    @PostMapping(value = "/encrypt", produces = MediaType.APPLICATION_JSON_VALUE)
    public @ResponseBody CipherDTO encrypt(@RequestBody CipherDTO cipherDTO,
                                           @RequestHeader(value = "encryption-strength", defaultValue = "256") int encryptionStrength) throws Exception {
        return encrypt(cipherDTO, AESCipherKeyLength.getAESKeyLength(encryptionStrength));
    }

    @PostMapping(value = "/encrypt-128", produces = MediaType.APPLICATION_JSON_VALUE)
    public @ResponseBody CipherDTO encrypt128(@RequestBody CipherDTO cipherDTO) throws Exception {
        return encrypt(cipherDTO, AESCipherKeyLength.BIT_128);
    }

    @PostMapping(value = "/encrypt-192", produces = MediaType.APPLICATION_JSON_VALUE)
    public @ResponseBody CipherDTO encrypt192(@RequestBody CipherDTO cipherDTO) throws Exception {
        return encrypt(cipherDTO, AESCipherKeyLength.BIT_192);
    }

    @PostMapping(value = "/encrypt-256", produces = MediaType.APPLICATION_JSON_VALUE)
    public @ResponseBody CipherDTO encrypt256(@RequestBody CipherDTO cipherDTO) throws Exception {
        return encrypt(cipherDTO, AESCipherKeyLength.BIT_256);
    }

    private CipherDTO encrypt(CipherDTO cipherDTO, AESCipherKeyLength aesCipherKeyLength) throws Exception {
        verifyDTO(cipherDTO);
        byte[] cipherText = service.encrypt(cipherDTO.getValue().getBytes(StandardCharsets.UTF_8), cipherDTO.getPassword(), aesCipherKeyLength);
        String base64EncodedCipherText = Base64.getEncoder().encodeToString(cipherText); // always encode cipher
        return new CipherDTO(base64EncodedCipherText, null); // no need to return password
    }


    @PostMapping(value = "/decrypt", produces = MediaType.APPLICATION_JSON_VALUE)
    public @ResponseBody CipherDTO decrypt(@RequestBody CipherDTO cipherDTO,
                                           @RequestHeader(value = "encryption-strength", defaultValue = "256") int encryptionStrength) throws Exception {
        return decrypt(cipherDTO, AESCipherKeyLength.getAESKeyLength(encryptionStrength));
    }

    @PostMapping(value = "/decrypt-128", produces = MediaType.APPLICATION_JSON_VALUE)
    public @ResponseBody CipherDTO decrypt128(@RequestBody CipherDTO cipherDTO) throws Exception {
        return decrypt(cipherDTO, AESCipherKeyLength.BIT_128);
    }

    @PostMapping(value = "/decrypt-192", produces = MediaType.APPLICATION_JSON_VALUE)
    public @ResponseBody CipherDTO decrypt192(@RequestBody CipherDTO cipherDTO) throws Exception {
        return decrypt(cipherDTO, AESCipherKeyLength.BIT_192);
    }

    @PostMapping(value = "/decrypt-256", produces = MediaType.APPLICATION_JSON_VALUE)
    public @ResponseBody CipherDTO decrypt256(@RequestBody CipherDTO cipherDTO) throws Exception {
        return decrypt(cipherDTO, AESCipherKeyLength.BIT_256);
    }

    private CipherDTO decrypt(CipherDTO cipherDTO, AESCipherKeyLength aesCipherKeyLength) throws Exception {
        verifyDTO(cipherDTO);
        byte [] cipherTextWithIvSalt = Base64.getDecoder().decode(cipherDTO.getValue()); // always decode cipher
        byte [] plainText = service.decrypt(cipherTextWithIvSalt, cipherDTO.getPassword(), aesCipherKeyLength);
        return new CipherDTO(new String(plainText, StandardCharsets.UTF_8), null); // Do not return password!
    }


    private void verifyDTO(CipherDTO cipherDTO) {
        if(cipherDTO == null) {
            throw new IllegalArgumentException("Argument cipherDTO cannot be null.");
        }

        String plainText = cipherDTO.getValue();
        if(StringUtils.isBlank(plainText)) {
            throw new IllegalArgumentException("Argument value must be provided");
        }

        String password = cipherDTO.getPassword();
        if(StringUtils.isBlank(password)) {
            throw new IllegalArgumentException("Argument password must be provided");
        }
    }
}
