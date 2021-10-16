package io.avec.crypto.aes;

import lombok.AllArgsConstructor;
import lombok.Data;


@AllArgsConstructor
@Data
public class CipherDTO {
    private String value;
    private String password;

}
