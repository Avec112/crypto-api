package io.avec.crypto.aes.schema;

import io.avec.crypto.domain.CipherText;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Value;

@AllArgsConstructor
@NoArgsConstructor(force = true)
@Value
public class EncryptResponse {

    @Schema(required = true, accessMode = Schema.AccessMode.READ_ONLY)
    CipherText cipherText;
}
