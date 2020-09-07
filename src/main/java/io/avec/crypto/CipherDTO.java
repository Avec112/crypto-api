package io.avec.crypto;

import lombok.AllArgsConstructor;
import lombok.Data;


@AllArgsConstructor
@Data
public class CipherDTO {
    private String value;
    private String password;

}
