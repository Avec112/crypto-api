package io.avec.crypto;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;



@RestController
@RequestMapping("/api/v1")
public class CryptoController {

    private final CryptoService service;

    public CryptoController(CryptoService service) {
        this.service = service;
    }

    @PostMapping(value = "/encrypt", produces = MediaType.APPLICATION_JSON_VALUE)
    public @ResponseBody Ciphertext encrypt(@RequestBody Plaintext plaintext) throws Exception {
        String cipherText = service.encrypt(plaintext.getValue(), plaintext.getPassword());
        return new Ciphertext(cipherText, null);
    }

    @PostMapping(value = "/decrypt", produces = MediaType.APPLICATION_JSON_VALUE)
    public @ResponseBody Plaintext decrypt(@RequestBody Ciphertext ciphertext) throws Exception {
        String plainText = service.decrypt(ciphertext.getValue(), ciphertext.getPassword());
        return new Plaintext(plainText, null);
    }

//    /**
//     * Decrypt Ciphertext encrypted value to plain text
//     * @param ciphertext object containing encrypted value, key and iv
//     * @return Plaintext object containing plain value
//     */
//    private Plaintext decrypt(Ciphertext ciphertext) throws Exception {
//        return new Plaintext(decrypt(ciphertext.getValue(), ciphertext.getPassword()), null);
//    }
//
//    /**
//     * Encrypt Plaintext value
//     * @param plaintext object containing plain value and key
//     * @return Ciphertext object containing encryptet value and iv
//     */
//    public Ciphertext encrypt(Plaintext plaintext) throws Exception {
//
//
//
//        String encryptedValue = encrypt(plaintext.getValue(), plaintext.getPassword());
//        return new Ciphertext(encryptedValue, null);
//    }


}
