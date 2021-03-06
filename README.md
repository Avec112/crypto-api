# Simple REST Crypto api

Crypto Service with REST api using algo `AES/CTR/PKCS5Padding` or `AES/GCM/NoPadding`.
The Initialization Vector (IV) and SALT is created automatically when you post. 
The returned `CipherDTO` object will contain a returned value (IV+SALT+CIPHER). 

Note! You must configure Transport Layer Security (TLS/SSL) for this to be safe

### Urls
* http://localhost:8080/api/v1/encrypt (defaults to 256 bits)
* http://localhost:8080/api/v1/encrypt-128
* http://localhost:8080/api/v1/encrypt-192
* http://localhost:8080/api/v1/encrypt-256
* http://localhost:8080/api/v1/decrypt (defaults to 256 bits)
* http://localhost:8080/api/v1/decrypt-128
* http://localhost:8080/api/v1/decrypt-192
* http://localhost:8080/api/v1/decrypt-256
 
### Header encryption-strength 
If you call `/encrypt` or `/decrypt` without header `encryption-strength=[128|192|256]` default key will be 256 bit.
Options 128, 192 and 256 will be mapped to korrect length keys. Any other value will default to 256 bits.

## Example

### Encrypt

#### Send payload to server example (256 bits)
Object `CipherDTO` contains two fields
```
{
     "value": "Hello, World!",
     "password": "1234"
}
```

#### Recieve payload from server example (256 bits)
Object `CipherDTO` contains three fields
```
{
    "value": "VjuNl31ECIUyPXTSBohEUjbKVRIIgcIVvAg7kpFqDrjn53TDhZidbnmlBRvm9VYgifBbTVxRcAMg",
    "key": null,
}
```

### Decrypt

#### Send payload to server example (256 bits)
Object `CipherDTO` contains two fields
```
{
     "value": "VjuNl31ECIUyPXTSBohEUjbKVRIIgcIVvAg7kpFqDrjn53TDhZidbnmlBRvm9VYgifBbTVxRcAMg",
     "password": "1234"
}
```

#### Recieve payload from server example (256 bits)
Object `CipherDTO` contains three fields
```
{
    "value": "Hello, World!",
    "key": null,
}
```

## Some resources

- https://www.veracode.com/blog/research/encryption-and-decryption-java-cryptography
- https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9
- https://mkyong.com/java/java-aes-encryption-and-decryption/
- https://web.cs.ucdavis.edu/~rogaway/ocb/gcm.pdf (NIST)
- https://crypto.stackexchange.com/
