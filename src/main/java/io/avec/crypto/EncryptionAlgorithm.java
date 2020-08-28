package io.avec.crypto;

import org.apache.commons.lang3.NotImplementedException;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Created by avec112 on 28.08.2020.
 */
public enum EncryptionAlgorithm {
    GCM("AES/GCM/NoPadding", 12), // iv length 12 is recommended by NIST for GCM
    CTR("AES/CTR/PKCS5Padding", 16);

    private final String algorithm;
    private final int ivLength;

    EncryptionAlgorithm(String algorithm, int ivLength) {
        this.algorithm = algorithm;
        this.ivLength = ivLength;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public int getIvLength() {
        return ivLength;
    }

    public AlgorithmParameterSpec getAlgorithmParameterSpec(byte [] iv) {
        if(this.equals(GCM)) {
            int TAG_LENGTH_BIT = 128; // must be one of {128, 120, 112, 104, 96}
            return new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        } else if(this.equals(CTR)) {
            return new IvParameterSpec(iv);
        }
        throw new NotImplementedException(this.name() + " is not implemented.");
    }
}
