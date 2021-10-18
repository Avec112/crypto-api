package io.avec.crypto.aes.schema;

import io.avec.crypto.domain.Password;
import io.avec.crypto.domain.PlainText;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Value;

@AllArgsConstructor
@NoArgsConstructor(force = true)
@Value
public class EncryptRequest {

    @Schema(required = true,
            example = "Password123!",
            accessMode = Schema.AccessMode.WRITE_ONLY)
    Password password;

    @Schema(required = true,
            example = "Secret text",
            accessMode = Schema.AccessMode.WRITE_ONLY)
    PlainText plainText;

}
