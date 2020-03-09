package io.avec.crypto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.web.bind.annotation.*;



@RestController
@RequestMapping("/api/v1")
public class CryptoController {

    private final CryptoService service;

    public CryptoController(CryptoService service) {
        this.service = service;
    }

    @PostMapping(value = "/encrypt")
    public @ResponseBody Ciphertext encrypt(@RequestBody Plaintext plaintext) {
        return new Ciphertext(service.encode(plaintext.getPlaintext()));
    }


    @PostMapping("/decrypt")
    public @ResponseBody Decryptedtext decrypt(@RequestBody Ciphertext ciphertext) {
        return new Decryptedtext(service.decode(ciphertext.getCipertext()));
    }


    @NoArgsConstructor
    @Data
    public static class Plaintext {
        private String plaintext;
    }

    @AllArgsConstructor
    @NoArgsConstructor
    @Data
    public static class Ciphertext {
        private String cipertext;
    }

    @AllArgsConstructor
    @NoArgsConstructor
    @Data
    public static class Decryptedtext {
        private String decryptedtext;
    }

}
