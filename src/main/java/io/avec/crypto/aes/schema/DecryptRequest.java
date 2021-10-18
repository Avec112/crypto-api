package io.avec.crypto.aes.schema;

import io.avec.crypto.domain.CipherText;
import io.avec.crypto.domain.Password;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Value;

@AllArgsConstructor
@NoArgsConstructor(force = true)
@Value
public class DecryptRequest {

    @Schema(required = true,
            example = "Password123!",
            accessMode = Schema.AccessMode.WRITE_ONLY)
    Password password;

    @Schema(required = true,
            example = "cKPzzkmHsjkreXG2gYhXT/qNgTC0EnWZIBu8PM+Qt6ND+Rsbh67a1ZPA6w==",
            accessMode = Schema.AccessMode.WRITE_ONLY)
    CipherText cipherText;

}
