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
    public @ResponseBody Ciphertext encrypt(@RequestBody Plaintext plaintext){
        return service.encode(plaintext);
    }

    @PostMapping(value = "/decrypt", produces = MediaType.APPLICATION_JSON_VALUE)
    public @ResponseBody Plaintext decrypt(@RequestBody Ciphertext ciphertext) {
        return service.decode(ciphertext);
    }


}
