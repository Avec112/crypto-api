# Simple REST Crypto api

Crypto Service with REST api using algo AES/CTR/PKCS5Padding.
The Initialization Vector (IV) is created automatically when you encrypt by posting a `Plaintext` object. 
The returned `Ciphertext` object will contain the encrypted value and iv. 

*Important!* Never use the same `key` and `iv` more than once!  

Note! You must configure Transport Layer Security (TLS/SSL) for this to be safe

### Urls
* http://localhost:8080/api/v1/encrypt
* http://localhost:8080/api/v1/decrypt
 
#### Encrypt payload example
Object `Plaintext` contains two fields
```
{
     "value": "Hello, World!",
     "key": 1234567890123456
}
```

#### Decrypt payload example
Object `Ciphertext` contains three fields
```
{
    "value": "1EcWsxSsTEZVqSKnpA==",
    "key": "1234567890123456",
    "iv": "xlq7UcO5hhMK2zmL"
}
```

If you POST a `Ciphertext` you will recieve a `Plaintext` object containing field value (ignore key value null). 
If you POST a `Plaintext` you will recieve a `Ciphertext` object containing fields value and iv (ignore key value null). 


Some resources:
- https://www.veracode.com/blog/research/encryption-and-decryption-java-cryptography
- https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9
- https://crypto.stackexchange.com/
