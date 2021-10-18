package io.avec.crypto.aes;

import io.avec.crypto.aes.schema.DecryptRequest;
import io.avec.crypto.aes.schema.DecryptResponse;
import io.avec.crypto.aes.schema.EncryptRequest;
import io.avec.crypto.aes.schema.EncryptResponse;
import io.avec.crypto.domain.CipherText;
import io.avec.crypto.domain.PlainText;
import io.avec.crypto.exception.BadCipherTextException;
import io.avec.crypto.exception.Base64Exception;
import io.avec.crypto.exception.ErrorResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.Validate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v1")
public class AESCipherController {

    @PostMapping(value = "/encrypt", produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public @ResponseBody
    EncryptResponse encrypt(@RequestBody EncryptRequest encryptRequest,
                            @RequestHeader(value = "encryption-mode", defaultValue = "CTR") String encryptionMode,
                            @RequestHeader(value = "encryption-strength", defaultValue = "256") int encryptionStrength
    ) throws Exception {
        log.debug("{}@{}, ", encryptionMode, encryptionStrength);

        Validate.notNull(encryptRequest);
        Validate.notBlank(encryptRequest.getPlainText().getValue());
        Validate.notBlank(encryptRequest.getPassword().getValue());

        AesCipher aesCipher = new AesCipher(encryptionMode, encryptionStrength);
        CipherText cipherText = aesCipher.encrypt(
                encryptRequest.getPlainText(),
                encryptRequest.getPassword());
        return new EncryptResponse(cipherText);
    }

    @PostMapping(value = "/decrypt", produces = MediaType.APPLICATION_JSON_VALUE)
    public @ResponseBody
    DecryptResponse decrypt(@RequestBody DecryptRequest decryptRequest,
                            @RequestHeader(value = "encryption-mode", defaultValue = "CTR") String encryptionMode,
                            @RequestHeader(value = "encryption-strength", defaultValue = "256") int encryptionStrength) throws Exception {
        log.debug("{}@{}", encryptionMode, encryptionStrength);

        Validate.notNull(decryptRequest);
        Validate.notBlank(decryptRequest.getCipherText().getValue());
        Validate.notBlank(decryptRequest.getPassword().getValue());

        AesCipher aesCipher = new AesCipher(encryptionMode, encryptionStrength);
        PlainText plainText = aesCipher.decrypt(decryptRequest.getCipherText(), decryptRequest.getPassword());
        return new DecryptResponse(plainText);
    }


    @ExceptionHandler(BadCipherTextException.class)
    @ResponseStatus(HttpStatus.NOT_ACCEPTABLE)
    public ResponseEntity<ErrorResponse> handleBadCipherTextException(Exception exception){
//        log.error(msg, exception);
        return buildErrorResponse(exception.getMessage(), HttpStatus.NOT_ACCEPTABLE);
    }

    @ExceptionHandler(Base64Exception.class)
    @ResponseStatus(HttpStatus.NOT_ACCEPTABLE)
    public ResponseEntity<ErrorResponse> handleDecodingException(Exception exception){
//        log.error(msg, exception);
        return buildErrorResponse(exception.getMessage(), HttpStatus.NOT_ACCEPTABLE);
    }


    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ResponseEntity<ErrorResponse> handleAllUncaughtException(Exception exception){
        final String msg = "Unknown error occurred";
        log.error(msg, exception);
        return buildErrorResponse(msg, HttpStatus.INTERNAL_SERVER_ERROR);
    }


    private ResponseEntity<ErrorResponse> buildErrorResponse(String message, HttpStatus httpStatus) {
        ErrorResponse errorResponse = new ErrorResponse(httpStatus.value(), message);
        return ResponseEntity.status(httpStatus).body(errorResponse);
    }

}
