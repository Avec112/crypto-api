# Simple REST Crypto api
![Travis (.org)](https://img.shields.io/travis/avec112/crypto-api?logo=travis)
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/avec112/crypto-api/CodeQL?label=CodeQL&logo=github)
![GitHub license](https://img.shields.io/github/license/avec112/crypto-api)
![GitHub last commit](https://img.shields.io/github/last-commit/Avec112/crypto-api)

Crypto REST Api running a Spring Boot application on Tomcat. The service use Advanced Encryption Standard (AES). 
Available algorithms is `AES/CTR/NoPadding` and `AES/GCM/NoPadding`. Symmetric encryption and decryption is supported. 

![AES Encryption](https://cdn.ttgtmedia.com/rms/onlineImages/security-aes_design_desktop.jpg)

![Symmetric Encryption](https://www.ssl2buy.com/wiki/wp-content/uploads/2015/12/Symmetric-Encryption.png))

### :warning: Important!
You must configure Transport Layer Security (TLS/SSL) for this to be safe. Without transport encryption
the provided payload may be seen by any 3.party.

### Encryption Notation
`p = Plaintext` (readable) \
`c = Ciphertext` (not readable) \
`k = key` (know to user) \
`E = encryption function` \
`D = decryption function` \
Encryption `c = E(p, k)` \
Decryption `p = D(c, k)`

### Encryption `c = E(p, k)`
Use of Initialization Vector (IV) and SALT is hidden under the hood and is created automatically when user `POST` 
schema `EncryptRequest` containing `plaintext p` and a `password k` to endpoint `/encrypt E(p, k)`. A schema `EncryptResponse` will be returned 
containing a Base64 encoded `ciphertext c`. The `cipertext c` is byte concatenated like this: `IV+SALT+CIPHER`. 

### Decryption `p = D(c, k)`
The user `POST` schema `DecryptRequest` containing `ciphertext c` and a `password k` to endpoint `/decrypt D(p, k)`. 
A schema `DecryptResponse` will be returned containing a Base64 encoded `plaintext p`.

### Urls
* http://localhost:8080/api/v1/encrypt (defaults to CTR/256 bits)
* http://localhost:8080/api/v1/decrypt (defaults to CTR/256 bits)
* http://localhost:8080/swagger-ui.html (use browser)
* http://localhost:8080/v3/api-docs
 
### Headers
* `Content-Type=application/json`
* `encryption-mode=[CTR|GCM]`. Defaults to `CTR`.
* `encryption-strength=[128|192|256]`. Defaults to `256` bit. Any other value will default to 256 bits.

## Example

### Encrypt
Default values (CTR/256) for  `POST /encrypt`

#### Schema `EncryptRequest`
```
{
    "password": {
        "value": "Password123!"
    },
    "plainText": {
        "value": "Secret text"
    }
}
```

#### Schema `EncryptResponse`
```
{
    "cipherText": {
        "value": "Qyp+G89ZgOhMPg1Iu3DPxqnbPZXF6mPdXgVWLWviXzfhoRjAWg+zL3K6eg=="
    }
}
```

### Decrypt
Default values (CTR/256) for `POST /decrypt`

#### Schema `DecryptRequest`
```
{
    "password": {
        "value": "Password123!"
    },
    "cipherText": {
        "value": "Qyp+G89ZgOhMPg1Iu3DPxqnbPZXF6mPdXgVWLWviXzfhoRjAWg+zL3K6eg=="
    }
}
```

#### Schema `DecryptResponse`
```
{
    "plainText": {
        "value": "Secret text"
    }
}
```

## Todo
* Better error handling
  * encryption-mode: CTR encrypt vs GCM decrypt and visa versa
  * encryption-strength: Different bit size encrypt vs decrypt
* Make GCM default

## Some resources

- https://searchsecurity.techtarget.com/definition/Advanced-Encryption-Standard
- https://www.veracode.com/blog/research/encryption-and-decryption-java-cryptography
- https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9
- https://mkyong.com/java/java-aes-encryption-and-decryption/
- https://web.cs.ucdavis.edu/~rogaway/ocb/gcm.pdf (NIST)
- https://crypto.stackexchange.com/
