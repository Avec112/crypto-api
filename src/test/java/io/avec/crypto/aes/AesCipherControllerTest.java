package io.avec.crypto.aes;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.avec.crypto.aes.schema.DecryptRequest;
import io.avec.crypto.aes.schema.DecryptResponse;
import io.avec.crypto.aes.schema.EncryptRequest;
import io.avec.crypto.aes.schema.EncryptResponse;
import io.avec.crypto.domain.CipherText;
import io.avec.crypto.domain.Password;
import io.avec.crypto.domain.PlainText;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
//@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class AesCipherControllerTest {

    private final Password password = new Password("password");
    private final PlainText plainText = new PlainText("Secret text");
    private final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private WebApplicationContext context;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .build();
    }


    @ParameterizedTest
    @CsvSource({
            "CTR, 128",
            "CTR, 192",
            "CTR, 256",
            "GCM, 128",
            "GCM, 192",
            "GCM, 256"
    })
    void encrypt(String encryptionMode, int encryptionStrength) throws Exception {
        final EncryptRequest cipherSchema = new EncryptRequest(password, plainText);

        final String content = mapper.writeValueAsString(cipherSchema);
        mockMvc.perform(post("/api/v1/encrypt") // default is 256 Bit
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("encryption-mode", encryptionMode)
                        .header("encryption-strength", encryptionStrength)
                        .content(content)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(result -> {
                    final MockHttpServletResponse response = result.getResponse();

                    // assert Content-Type
                    assertEquals(MediaType.APPLICATION_JSON_VALUE, response.getContentType());

                    final String jsonSchema = response.getContentAsString();
                    final EncryptResponse encryptResponse = mapper.readValue(jsonSchema, EncryptResponse.class);
                    final CipherText cipherText = encryptResponse.getCipherText();

                    // since IV + SALT is not available for us (it's inside the cipherText value)
                    // we must reverse the process and assert the result as plainText
                    final AesCipher aesCipher = new AesCipher(encryptionMode, encryptionStrength);
                    final PlainText actualPlainText = aesCipher.decrypt(cipherText, password);

                    // assert cipherText
                    assertEquals(plainText, actualPlainText);
                });

    }


    @SuppressWarnings("SpellCheckingInspection")
    @ParameterizedTest
    @CsvSource({
            "CTR, 128, tsspzAg4uuzm/cPM0DLrP1GMwem2FdjDgsCMjFOWzTvFe/sC/xhDWQ8avw==",
            "CTR, 192, YFRCZ1oYEpZycVVCn4j/ggWks1+KV1yqse5s8lAOUf5mcsCfzOHq6hfzqQ==",
            "CTR, 256, NYEHyCkdXH//H5dRmDW2rx7D1ze1mr91IgDsrFg6hs+5U2kAqmtr1KevYQ==",
            "GCM, 128, FC5aaOTohxOCKUxWcrCsH1CgLPP5RuXOok9kvwBDwJLQtDvDLT5fWxDK8kuLAIxh437oLnooJA==",
            "GCM, 192, zoS6MBrqeu/+/TyZxLOLS1z0DVrpgj3ZAMZAyCF059FK9X1XMwDQIcM3RhQHnJWr0d0s3sMykQ==",
            "GCM, 256, brI+8dHoXV6/qi1rlIyNP4JB3zHg+IOgNAtPXrFlcndLeSxhqvuJ9Q5w1CEgvKS0BgQ30V9TnQ=="
    })
    void decrypt(String encryptionMode, int encryptionStrength, CipherText cipherText) throws Exception {
        final DecryptRequest cipherSchema = new DecryptRequest(password, cipherText);

        final String content = mapper.writeValueAsString(cipherSchema);
        mockMvc.perform(post("/api/v1/decrypt") // default is 256 Bit
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("encryption-mode", encryptionMode)
                        .header("encryption-strength", encryptionStrength)
                        .content(content)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(result -> {
                    final MockHttpServletResponse response = result.getResponse();

                    // assert Content-Type
                    assertEquals(MediaType.APPLICATION_JSON_VALUE, response.getContentType());

                    final String jsonSchema = response.getContentAsString();
                    final DecryptResponse decryptResponse = mapper.readValue(jsonSchema, DecryptResponse.class);
                    final PlainText plainText = decryptResponse.getPlainText();

                    // assert plainText
                    assertEquals(this.plainText, plainText);
                });

    }
}