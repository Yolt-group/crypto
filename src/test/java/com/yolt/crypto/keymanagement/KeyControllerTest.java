package com.yolt.crypto.keymanagement;

import com.yolt.crypto.TestConfiguration;
import com.yolt.crypto.keymaterial.CSRRequirementsDTO;
import com.yolt.crypto.keymaterial.KeypairType;
import com.yolt.crypto.keymaterial.ServiceType;
import com.yolt.crypto.keymaterial.SignatureAlgorithm;
import nl.ing.lovebird.clienttokens.ClientGroupToken;
import nl.ing.lovebird.clienttokens.constants.ClientTokenConstants;
import nl.ing.lovebird.clienttokens.test.TestClientTokens;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import java.security.Security;
import java.util.UUID;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(KeyController.class)
@Import({TestConfiguration.class})
@ActiveProfiles("test")
class KeyControllerTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final HttpHeaders headers = new HttpHeaders();

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private KeyManagementService keyManagementService;

    @MockBean
    private CSRManagementService csrManagementService;

    @Autowired
    private TestClientTokens testClientTokens;

    @Test
    void testCreateKey() throws Exception {
        UUID clientGroupId = UUID.randomUUID();
        ClientGroupToken clientGroupToken = testClientTokens.createClientGroupToken(clientGroupId,
                claims -> claims.setClaim(ClientTokenConstants.EXTRA_CLAIM_ISSUED_FOR, "assistance-portal-yts"));
        headers.put(ClientTokenConstants.CLIENT_TOKEN_HEADER_NAME, singletonList(clientGroupToken.getSerialized()));

        // Prep the params
        String uri = "/key";
        UUID kid = UUID.randomUUID();
        when(keyManagementService.createKey(any(), any(), eq(null))).thenReturn(kid);

        // Hit the controller and verify
        this.mockMvc.perform(post(uri)
                .content("{}")
                .headers(headers)
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.kid").value(kid.toString()));

        // verify mock
        verify(keyManagementService).createKey(any(), any(), eq(null));
    }

    @Test
    void testCreateCSR() throws Exception {
        UUID clientGroupId = UUID.randomUUID();
        ClientGroupToken clientGroupToken = testClientTokens.createClientGroupToken(clientGroupId,
                claims -> claims.setClaim(ClientTokenConstants.EXTRA_CLAIM_ISSUED_FOR, "assistance-portal-yts"));
        headers.put(ClientTokenConstants.CLIENT_TOKEN_HEADER_NAME, singletonList(clientGroupToken.getSerialized()));

        // Prep the params
        String uri = "/key/%s/csr";
        UUID kid = UUID.randomUUID();
        when(csrManagementService.generateCSR(clientGroupToken, kid, new CSRRequirementsDTO(KeypairType.SIGNING, singletonList(ServiceType.AIS), SignatureAlgorithm.SHA256_WITH_RSA, emptyList(), false, null)))
                .thenReturn("CSR");

        // Hit the controller and verify
        this.mockMvc.perform(post(String.format(uri, kid))
                .content("{" +
                        "\"type\":\"SIGNING\"," +
                        "\"serviceTypes\":[\"AIS\"]," +
                        "\"signatureAlgorithm\":\"SHA256_WITH_RSA\"," +
                        "\"distinguishedNames\":[]," +
                        "\"eidasCertificate\": false" +
                        "}")
                .headers(headers)
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.certificateSigningRequest").value("CSR"));

        // verify mock
        verify(csrManagementService).generateCSR(clientGroupToken, kid, new CSRRequirementsDTO(KeypairType.SIGNING, singletonList(ServiceType.AIS), SignatureAlgorithm.SHA256_WITH_RSA, emptyList(), false, null));
    }

    @Test
    void testCreateCSRForEIDAS() throws Exception {
        UUID clientGroupId = UUID.randomUUID();
        ClientGroupToken clientGroupToken = testClientTokens.createClientGroupToken(clientGroupId,
                claims -> claims.setClaim(ClientTokenConstants.EXTRA_CLAIM_ISSUED_FOR, "assistance-portal-yts"));
        headers.put(ClientTokenConstants.CLIENT_TOKEN_HEADER_NAME, singletonList(clientGroupToken.getSerialized()));

        // Prep the params
        String uri = "/key/%s/csr";
        UUID kid = UUID.randomUUID();
        when(csrManagementService.generateCSR(clientGroupToken, kid, new CSRRequirementsDTO(KeypairType.SIGNING, singletonList(ServiceType.AIS), SignatureAlgorithm.SHA256_WITH_RSA, emptyList(), true, null)))
                .thenReturn("CSR for eidas");

        // Hit the controller and verify
        this.mockMvc.perform(post(String.format(uri, kid))
                .content("{" +
                        "\"type\":\"SIGNING\"," +
                        "\"serviceTypes\":[\"AIS\"]," +
                        "\"signatureAlgorithm\":\"SHA256_WITH_RSA\"," +
                        "\"distinguishedNames\":[]," +
                        "\"eidasCertificate\": true" +
                        "}")
                .headers(headers)
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.certificateSigningRequest").value("CSR for eidas"));

        // verify mock
        verify(csrManagementService).generateCSR(clientGroupToken, kid, new CSRRequirementsDTO(KeypairType.SIGNING, singletonList(ServiceType.AIS), SignatureAlgorithm.SHA256_WITH_RSA, emptyList(), true, null));
    }

}
