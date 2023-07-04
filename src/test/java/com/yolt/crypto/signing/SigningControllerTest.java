package com.yolt.crypto.signing;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yolt.crypto.keymanagement.KeyManagementService;
import com.yolt.crypto.keymaterial.KeypairType;
import com.yolt.crypto.keymaterial.SignatureAlgorithm;
import nl.ing.lovebird.clienttokens.ClientGroupToken;
import nl.ing.lovebird.clienttokens.ClientToken;
import nl.ing.lovebird.clienttokens.constants.ClientTokenConstants;
import nl.ing.lovebird.clienttokens.test.TestClientTokens;
import org.bouncycastle.util.encoders.Base64;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import java.util.Collections;
import java.util.UUID;
import java.util.function.Consumer;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = SigningController.class)
class SigningControllerTest {

    private final UUID clientId = UUID.randomUUID();
    private final UUID clientGroupId = UUID.randomUUID();

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private KeyManagementService keyManagementService;

    @Autowired
    private TestClientTokens testClientTokens;

    private ClientGroupToken clientGroupToken;
    private ClientToken clientToken;

    @BeforeEach
    void setup() {
        Consumer<JwtClaims> mutator = claims -> claims.setClaim(ClientTokenConstants.EXTRA_CLAIM_ISSUED_FOR, "assistance-portal-yts");
        clientGroupToken = testClientTokens.createClientGroupToken(clientGroupId, mutator);
        clientToken = testClientTokens.createClientToken(clientGroupId, clientId, mutator);
    }

    @Test
    void testSignWithClientToken() throws Exception {

        // Prep the params
        String uri = "/sign";
        UUID kid = UUID.randomUUID();
        String payload = Base64.toBase64String("ABC".getBytes());
        HttpHeaders headers = getHeaders(clientToken.getSerialized());
        when(keyManagementService.sign(eq(kid), eq(KeypairType.SIGNING), eq(SignatureAlgorithm.SHA256_WITH_RSA), eq(Encoding.BASE64), any(), eq(clientGroupId))).thenReturn(payload);
        SignRequestDTO requestDTO = new SignRequestDTO(kid, SignatureAlgorithm.SHA256_WITH_RSA, payload, null);

        // Hit the controller and verify
        String body = objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL).writeValueAsString(requestDTO);
        this.mockMvc.perform(post(uri)
                .content(body)
                .headers(headers)
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.encodedSignature").value(payload));

        // verify mock
        verify(keyManagementService).sign(eq(kid), eq(KeypairType.SIGNING), eq(SignatureAlgorithm.SHA256_WITH_RSA), eq(Encoding.BASE64), any(), eq(clientGroupId));
    }

    @Test
    void testSignWithClientTokenWithoutClientIdHeaderShouldFail() throws Exception {

        // Prep the params
        String uri = "/sign";
        UUID kid = UUID.randomUUID();
        String payload = Base64.toBase64String("ABC".getBytes());
        HttpHeaders headers = getHeaders(clientToken.getSerialized());
        headers.remove("client-id");
        when(keyManagementService.sign(eq(kid), eq(KeypairType.SIGNING), eq(SignatureAlgorithm.SHA256_WITH_RSA), eq(Encoding.BASE64), any(), eq(clientGroupId))).thenReturn(payload);
        SignRequestDTO requestDTO = new SignRequestDTO(kid, SignatureAlgorithm.SHA256_WITH_RSA, payload, null);

        // Hit the controller and verify
        String body = objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL).writeValueAsString(requestDTO);
        this.mockMvc.perform(post(uri)
                .content(body)
                .headers(headers)
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("Invalid request parameters"));
    }

    @Test
    void testSignWithClientGroupToken() throws Exception {
        String uri = "/sign";
        UUID kid = UUID.randomUUID();
        String payload = Base64.toBase64String("ABC".getBytes());
        HttpHeaders headers = getHeaders(clientGroupToken.getSerialized());
        headers.remove("client-id"); // not needed for client-group-token
        when(keyManagementService.sign(eq(kid), eq(KeypairType.SIGNING), eq(SignatureAlgorithm.SHA256_WITH_RSA), eq(Encoding.BASE64), any(), eq(clientGroupId))).thenReturn(payload);

        SignRequestDTO requestDTO = new SignRequestDTO(kid, SignatureAlgorithm.SHA256_WITH_RSA, payload, null);

        // Hit the controller and verify
        String body = objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL).writeValueAsString(requestDTO);
        this.mockMvc.perform(post(uri)
                .content(body)
                .headers(headers)
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.encodedSignature").value(payload));

        // verify mock
        verify(keyManagementService).sign(eq(kid), eq(KeypairType.SIGNING), eq(SignatureAlgorithm.SHA256_WITH_RSA), eq(Encoding.BASE64), any(), eq(clientGroupId));

    }

    @Test
    void testSignWithTransportKey() throws Exception {
        // Prep the params
        String uri = "/sign";
        UUID kid = UUID.randomUUID();
        String payload = Base64.toBase64String("ABC".getBytes());
        HttpHeaders headers = getHeaders(clientToken.getSerialized());
        when(keyManagementService.sign(eq(kid), eq(KeypairType.TRANSPORT), eq(SignatureAlgorithm.SHA256_WITH_RSA), eq(Encoding.BASE64), any(), eq(clientGroupId))).thenReturn(payload);

        SignRequestDTO requestDTO = new SignRequestDTO(kid, SignatureAlgorithm.SHA256_WITH_RSA, payload, KeypairType.TRANSPORT);

        // Hit the controller and verify
        String body = objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL).writeValueAsString(requestDTO);
        this.mockMvc.perform(post(uri)
                .content(body)
                .headers(headers)
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.encodedSignature").value(payload));

        // verify mock
        verify(keyManagementService).sign(eq(kid), eq(KeypairType.TRANSPORT), eq(SignatureAlgorithm.SHA256_WITH_RSA), eq(Encoding.BASE64), any(), eq(clientGroupId));
    }

    private HttpHeaders getHeaders(String clientTokenHeader) {
        HttpHeaders headers = new HttpHeaders();
        headers.put("client-id", Collections.singletonList(clientId.toString()));
        headers.put(ClientTokenConstants.CLIENT_TOKEN_HEADER_NAME, Collections.singletonList(clientTokenHeader));

        return headers;
    }

}
