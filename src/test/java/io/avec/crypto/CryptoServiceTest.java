package io.avec.crypto;

class CryptoServiceTest {

   /* private final CryptoService service = new CryptoService();
    private final String key = "1234567890123456"; // length = 16
    private final String iv = "IV for life baby"; // length = 16

    @Test
    void encode() {
        String plaintext = "Hello, World";
        String ciphertext = service.encode(plaintext, key, iv);

        assertThat(ciphertext).isEqualTo("q+0HG86WjSkD3Xpo");
    }


    @Test
    void decode() {
        String ciphertext = "q+0HG86WjSkD3Xpo";
        String decryptedtext = service.decode(ciphertext, key, iv);

        assertThat(decryptedtext).isEqualTo("Hello, World");
    }

    @Test
    void decodeWithWrongKey() {
        String ciphertext = "q+0HG86WjSkD3Xpo";
        String decryptedtext = service.decode(ciphertext, "1234567890abcdef", iv); // correct key is 1234567890123456

        assertThat(decryptedtext).isNotEqualTo("Hello, World");
    }

    @Test
    void symmetricEncryptionLargePlaintext() {

        String plaintext = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIICXAIBAAKBgQCVqGpH2S7F0CbEmQBgmbiDiOOGxhVwlG+yY/6OBQoPKcx4Jv2h\n" +
                "vLz7r54ngjaIqnqRNP7ljKjFLp5zhnAu9GsdwXbgLPtrmMSB+MVFHTJvKjQ+eY9p\n" +
                "dWA3NbQusM9uf8dArm+3VrZxNHQbVGXOIAPNHTO08cZHMSqIDQ6OvLma7wIDAQAB\n" +
                "AoGAbxKPzsNh826JV2A253svdnAibeSWBPgl7kBIrR8QWDCtkH9fvqpVmHa+6pO5\n" +
                "5bShQyQSCkxa9f2jnBorKK4+0K412TBM/SG6Zjw+DsZd6VuoZ7P027msTWQrMBxg\n" +
                "Hjgs7FSFtj76HQ0OZxFeZ8BkIYq0w+7VQYAPBWEPSqCRQAECQQDv09M4PyRVWSQM\n" +
                "S8Rmf/jBWmRnY1gPPEOZDOiSWJqIBZUBznvOPOOQSH6B+vee/q5edQA2OIaDgNmn\n" +
                "AurEtUaRAkEAn7/65w+Tewr89mOM0RKMVpFpwNfGYAj3kT1mFEYDq+iNWdcSE6xE\n" +
                "2H0w3YEbDsSayxc36efFnmr//4ljt4iJfwJAa1pOeicJhIracAaaa6dtGl/0AbOe\n" +
                "f3NibugwUxIGWkzlXmGnWbI3yyYoOta0cR9fvjhxV9QFomfTBcdwf40FgQJAH3MG\n" +
                "DBMO77w8DK2QfWBvbGN4NFTGYwWg52D1Bay68E759OPYVTMm4o/S3Oib0Q53gt/x\n" +
                "TAUq7IMYHtCHZwxkNQJBAORwE+6qVIv/ZSP2tHLYf8DGOhEBJtQcVjE7PfUjAbH5\n" +
                "lr++9qUfv0S13gXj5weio5dzgEXwWdX2YSL/asz5DhU=\n" +
                "-----END RSA PRIVATE KEY-----";

        String ciphertext = service.encode(plaintext, key, iv);
        String decryptedtext = service.decode(ciphertext, key, iv);

        assertThat(decryptedtext).isEqualTo(plaintext);
    }

    @ParameterizedTest
    @ValueSource(ints = 10000)
    void massTestingSameKeyAndIV(int count) {

        for(int i = 0; i < count; i++) {

            // ARRANGE
            String plainText = RandomStringUtils.randomAlphabetic(1,40);

            // ACT
            String cipherText = service.encode(plainText, key, iv);
            String decryptedText = service.decode(cipherText, key, iv);

            // ASSERT
            assertThat(decryptedText).isEqualTo(plainText);
        }
    }

    @ParameterizedTest
    @CsvSource(value = {
        "'Hello, World!', 1111111111AAAAAA, 1111111111BBBBBA, /lkyuU5QJXDrWnTMgw==",
        "'Hello, World!', 1111111111AAAAAB, 1111111111BBBBBB, RMCaVUamD4+4bedHUw==",
        "'Hello, World!', 1111111111AAAAAC, 1111111111BBBBBC, M6JIM3B8HUGapDhJGg==",
        "'Hello, World!', 1111111111AAAAAD, 1111111111BBBBBD, ulrfLcbhoQhqPkoCXg=="
    })
    void testDifferentKeyAndIVForSamePlaintext(String plaintext, String key, String iv, String ciphertext) {

        // ACT
        String cipherResult = service.encode(plaintext, key, iv);
        String decryptedText = service.decode(cipherResult, key, iv);

        // ASSERT
        assertThat(ciphertext).isEqualTo(cipherResult);
        assertThat(plaintext).isEqualTo(decryptedText);
    }

    @ParameterizedTest
    @ValueSource(ints = 10000)
    void testDifferentKeyAndIVForSamePlaintext(int count) {

        for(int i = 0; i < count; i++) {
            // ARRANGE
            String plainText = RandomStringUtils.randomAlphabetic(2,40);
            String key1 = RandomStringUtils.randomAlphabetic(16);
            String key2 = RandomStringUtils.randomAlphabetic(16);

            String iv1 = RandomStringUtils.randomAlphabetic(16);
            String iv2 = RandomStringUtils.randomAlphabetic(16);

            // ACT
            String cipherText = service.encode(plainText, key1, iv1);
            String cipherText2 = service.encode(plainText, key1, iv2);
            String cipherText3 = service.encode(plainText, key2, iv1);
            String cipherText4 = service.encode(plainText, key2, iv2);

            String decryptedText = service.decode(cipherText, key1, iv1);
            String decryptedText2 = service.decode(cipherText2, key1, iv2);
            String decryptedText3 = service.decode(cipherText3, key2, iv1);
            String decryptedText4 = service.decode(cipherText4, key2, iv2);


            // ASSERT
            assertThat(cipherText).isNotEqualTo(cipherText2).isNotEqualTo(cipherText3).isNotEqualTo(cipherText4);
            assertThat(decryptedText).isEqualTo(decryptedText2).isEqualTo(decryptedText3).isEqualTo(decryptedText4);
        }

    }*/

}