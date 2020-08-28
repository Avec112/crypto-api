package io.avec.crypto;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class Ciphertext {
    private String value; // iv + salt + cipertext
    private String password;
}
