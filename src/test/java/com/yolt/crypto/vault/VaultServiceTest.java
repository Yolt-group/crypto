package com.yolt.crypto.vault;

import com.yolt.crypto.keymanagement.KeyNotFoundException;
import com.yolt.crypto.keymaterial.KeyAlgorithm;
import com.yolt.crypto.keymaterial.KeypairType;
import com.yolt.crypto.keymaterial.ProviderKey;
import nl.ing.lovebird.clienttokens.ClientGroupToken;
import nl.ing.lovebird.clienttokens.ClientToken;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponse;

import java.security.*;
import java.util.*;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("unchecked")
class VaultServiceTest {

    private static final UUID CLIENT_ID = UUID.randomUUID();
    private static final UUID CLIENT_GROUP_ID = UUID.randomUUID();
    private static final UUID KID = UUID.randomUUID();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Mock
    private VaultAuthentication vaultAuthentication;

    @Mock
    private VaultTemplate vaultTemplate;

    @Captor
    private ArgumentCaptor<Map<String, Object>> secretsCaptor;

    private ClientToken clientToken;
    private ClientGroupToken clientGroupToken;

    private VaultService vaultService;

    @BeforeEach
    public void before() {
        VaultKeyValueConfiguration config = new VaultKeyValueConfiguration("default", "test", "crypto-test");
        when(vaultAuthentication.vaultTemplate()).thenReturn(vaultTemplate);
        vaultService = new VaultService(vaultAuthentication, config, "security-dta", "default", "test", "crypto-test");

        JwtClaims claims = new JwtClaims();
        claims.setClaim("sub", CLIENT_ID.toString());
        claims.setClaim("client-group-id", CLIENT_GROUP_ID.toString());
        clientToken = new ClientToken("serialized-form", claims);
        clientGroupToken = new ClientGroupToken("serialized-group-form", claims);
    }

    @Test
    public void aKeypairCanBeStoredInVault() throws Exception {
        vaultService.createKeyPair(clientGroupToken.getClientGroupIdClaim(), KeypairType.SIGNING, KID, KeyAlgorithm.RSA2048);

        verify(vaultTemplate).write(eq("test/k8s/pods/default/kv/crypto-test/signing/data/" + KID), secretsCaptor.capture());
        Map<String, Object> actualData = (Map<String, Object>) secretsCaptor.getValue().get("data");
        assertThat(actualData.get("private-key"), not(nullValue()));
        assertThat(actualData.get("public-key"), not(nullValue()));
        assertThat(actualData.get("key-algorithm"), equalTo("RSA"));
        assertThat(actualData.get("client-group-id"), equalTo(CLIENT_GROUP_ID));
    }

    @Test
    public void retrievingAKeyWorksForAKeyFromAClient() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair generatedKeyPair = keyGen.generateKeyPair();
        Map<String, String> data = new HashMap<>();
        // encoding it to a string because internally Vault does that for you
        data.put("private-key", Base64.getEncoder().encodeToString(generatedKeyPair.getPrivate().getEncoded()));
        data.put("public-key", Base64.getEncoder().encodeToString(generatedKeyPair.getPublic().getEncoded()));
        data.put("key-algorithm", "RSA");
        data.put("client-id", CLIENT_ID.toString());
        data.put("client-group-id", CLIENT_GROUP_ID.toString());
        VaultResponse response = new VaultResponse();
        response.setData(Collections.singletonMap("data", data));
        when(vaultTemplate.read("test/k8s/pods/default/kv/crypto-test/signing/data/" + KID))
                .thenReturn(response);

        ProviderKey<PrivateKey> privateKey = vaultService.retrievePrivateKey(clientGroupToken.getClientGroupIdClaim(), KeypairType.SIGNING, KID);
        ProviderKey<PublicKey> publicKey = vaultService.retrievePublicKey(clientGroupToken.getClientGroupIdClaim(), KeypairType.SIGNING, KID);

        assertThat(privateKey.getKey(), equalTo(generatedKeyPair.getPrivate()));
        assertThat(publicKey.getKey(), equalTo(generatedKeyPair.getPublic()));
    }

    @Test
    public void retrievingAKeyWorksForAKeyFromAClientFallbackWithoutClientToken() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair generatedKeyPair = keyGen.generateKeyPair();
        Map<String, String> data = new HashMap<>();
        // encoding it to a string because internally Vault does that for you
        data.put("private-key", Base64.getEncoder().encodeToString(generatedKeyPair.getPrivate().getEncoded()));
        data.put("public-key", Base64.getEncoder().encodeToString(generatedKeyPair.getPublic().getEncoded()));
        data.put("key-algorithm", "RSA");
        data.put("client-id", CLIENT_ID.toString());
        data.put("client-group-id", CLIENT_GROUP_ID.toString());
        VaultResponse response = new VaultResponse();
        response.setData(Collections.singletonMap("data", data));
        when(vaultTemplate.read("test/k8s/pods/default/kv/crypto-test/signing/data/" + KID))
                .thenReturn(response);

        ProviderKey<PrivateKey> privateKey = vaultService.retrievePrivateKey(clientGroupToken.getClientGroupIdClaim(), KeypairType.SIGNING, KID);
        ProviderKey<PublicKey> publicKey = vaultService.retrievePublicKey(clientGroupToken.getClientGroupIdClaim(), KeypairType.SIGNING, KID);

        assertThat(privateKey.getKey(), equalTo(generatedKeyPair.getPrivate()));
        assertThat(publicKey.getKey(), equalTo(generatedKeyPair.getPublic()));
    }

    @Test
    public void retrievingAKeyWithoutPublicKeyWorksForAKeyFromAClient() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair generatedKeyPair = keyGen.generateKeyPair();
        Map<String, String> data = new HashMap<>();
        // encoding it to a string because internally Vault does that for you
        data.put("private-key", Base64.getEncoder().encodeToString(generatedKeyPair.getPrivate().getEncoded()));
        data.put("key-algorithm", "RSA");
        data.put("client-group-id", CLIENT_GROUP_ID.toString());
        VaultResponse response = new VaultResponse();
        response.setData(Collections.singletonMap("data", data));
        when(vaultTemplate.read("test/k8s/pods/default/kv/crypto-test/signing/data/" + KID))
                .thenReturn(response);

        ProviderKey<PrivateKey> privateKey = vaultService.retrievePrivateKey(clientGroupToken.getClientGroupIdClaim(), KeypairType.SIGNING, KID);

        assertThat(privateKey.getKey(), equalTo(generatedKeyPair.getPrivate()));
    }

    @Test
    public void retrievingAPrivateKeyFromAnotherClientAndClientGroupDoesNotWork() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair generatedKeyPair = keyGen.generateKeyPair();
        UUID otherClientId = UUID.randomUUID();
        UUID otherClientGroupId = UUID.randomUUID();

        Map<String, String> data = new HashMap<>();
        data.put("private-key", Base64.getEncoder().encodeToString(generatedKeyPair.getPrivate().getEncoded()));
        data.put("public-key", Base64.getEncoder().encodeToString(generatedKeyPair.getPublic().getEncoded()));
        data.put("key-algorithm", "RSA");
        data.put("client-id", otherClientId.toString());
        data.put("client-group-id", otherClientGroupId.toString());
        VaultResponse response = new VaultResponse();
        response.setData(Collections.singletonMap("data", data));
        when(vaultTemplate.read("test/k8s/pods/default/kv/crypto-test/signing/data/" + KID))
                .thenReturn(response);

        assertThrows(KeyNotFoundException.class, () -> vaultService.retrievePrivateKey(clientGroupToken.getClientGroupIdClaim(), KeypairType.SIGNING, KID));
    }

    @Test
    public void retrievingAPrivateKeyFromAnotherClientGroupDoesNotWork() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair generatedKeyPair = keyGen.generateKeyPair();
        UUID otherClientGroupId = UUID.randomUUID();

        Map<String, String> data = new HashMap<>();
        data.put("private-key", Base64.getEncoder().encodeToString(generatedKeyPair.getPrivate().getEncoded()));
        data.put("public-key", Base64.getEncoder().encodeToString(generatedKeyPair.getPublic().getEncoded()));
        data.put("key-algorithm", "RSA");
        data.put("client-group-id", otherClientGroupId.toString());
        VaultResponse response = new VaultResponse();
        response.setData(Collections.singletonMap("data", data));
        when(vaultTemplate.read("test/k8s/pods/default/kv/crypto-test/signing/data/" + KID))
                .thenReturn(response);

        assertThrows(KeyNotFoundException.class, () -> vaultService.retrievePrivateKey(clientGroupToken.getClientGroupIdClaim(), KeypairType.SIGNING, KID));
    }

    @Test
    public void retrievingAPrivateKeyFromWithinClientGroupDoesWork() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair generatedKeyPair = keyGen.generateKeyPair();
        UUID otherClientId = UUID.randomUUID();

        Map<String, String> data = new HashMap<>();
        data.put("private-key", Base64.getEncoder().encodeToString(generatedKeyPair.getPrivate().getEncoded()));
        data.put("public-key", Base64.getEncoder().encodeToString(generatedKeyPair.getPublic().getEncoded()));
        data.put("key-algorithm", "RSA");
        data.put("client-id", otherClientId.toString());
        data.put("client-group-id", CLIENT_GROUP_ID.toString());
        VaultResponse response = new VaultResponse();
        response.setData(Collections.singletonMap("data", data));
        when(vaultTemplate.read("test/k8s/pods/default/kv/crypto-test/signing/data/" + KID))
                .thenReturn(response);

        ProviderKey<PrivateKey> privateKey = vaultService.retrievePrivateKey(clientGroupToken.getClientGroupIdClaim(), KeypairType.SIGNING, KID);

        assertThat(privateKey.getKey(), equalTo(generatedKeyPair.getPrivate()));
    }

    @Test
    public void retrievingAPrivateKeyFromAnotherClientWithinClientGroupDoesWork() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair generatedKeyPair = keyGen.generateKeyPair();
        UUID otherClientId = UUID.randomUUID();

        Map<String, String> data = new HashMap<>();
        data.put("private-key", Base64.getEncoder().encodeToString(generatedKeyPair.getPrivate().getEncoded()));
        data.put("public-key", Base64.getEncoder().encodeToString(generatedKeyPair.getPublic().getEncoded()));
        data.put("key-algorithm", "RSA");
        data.put("client-id", otherClientId.toString());
        data.put("client-group-id", CLIENT_GROUP_ID.toString());
        VaultResponse response = new VaultResponse();
        response.setData(Collections.singletonMap("data", data));
        when(vaultTemplate.read("test/k8s/pods/default/kv/crypto-test/signing/data/" + KID))
                .thenReturn(response);

        ProviderKey<PrivateKey> privateKey = vaultService.retrievePrivateKey(clientGroupToken.getClientGroupIdClaim(), KeypairType.SIGNING, KID);

        assertThat(privateKey.getKey(), equalTo(generatedKeyPair.getPrivate()));
    }

    @Test
    public void retrievingAnInvalidPrivateKeyFails() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair generatedKeyPair = keyGen.generateKeyPair();
        Map<String, String> data = new HashMap<>();
        data.put("private-key", "non-encoded");
        data.put("public-key", Base64.getEncoder().encodeToString(generatedKeyPair.getPublic().getEncoded()));
        data.put("key-algorithm", "RSA");
        data.put("client-id", CLIENT_ID.toString());
        VaultResponse response = new VaultResponse();
        response.setData(Collections.singletonMap("data", data));
        when(vaultTemplate.read("test/k8s/pods/default/kv/crypto-test/signing/data/" + KID))
                .thenReturn(response);

        assertThrows(KeyNotFoundException.class, () -> vaultService.retrievePrivateKey(clientGroupToken.getClientGroupIdClaim(), KeypairType.SIGNING, KID));
    }


    @Test
    public void retrievingAPublicKeyFromAnotherClientDoesNotWork() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair generatedKeyPair = keyGen.generateKeyPair();
        UUID otherClientId = UUID.randomUUID();

        Map<String, String> data = new HashMap<>();
        data.put("private-key", Base64.getEncoder().encodeToString(generatedKeyPair.getPrivate().getEncoded()));
        data.put("public-key", Base64.getEncoder().encodeToString(generatedKeyPair.getPublic().getEncoded()));
        data.put("key-algorithm", "RSA");
        data.put("client-id", otherClientId.toString());
        VaultResponse response = new VaultResponse();
        response.setData(Collections.singletonMap("data", data));
        when(vaultTemplate.read("test/k8s/pods/default/kv/crypto-test/signing/data/" + KID))
                .thenReturn(response);

        assertThrows(KeyNotFoundException.class, () -> vaultService.retrievePublicKey(clientGroupToken.getClientGroupIdClaim(), KeypairType.SIGNING, KID));
    }

    @Test
    public void retrievingAnNonExistingPublicKeyFails() {
        Map<String, String> data = new HashMap<>();
        data.put("private-key", "non-encoded");
        data.put("key-algorithm", "RSA");
        data.put("client-id", CLIENT_ID.toString());
        VaultResponse response = new VaultResponse();
        response.setData(Collections.singletonMap("data", data));
        when(vaultTemplate.read("test/k8s/pods/default/kv/crypto-test/signing/data/" + KID))
                .thenReturn(response);

        assertThrows(KeyNotFoundException.class, () -> vaultService.retrievePublicKey(clientGroupToken.getClientGroupIdClaim(), KeypairType.SIGNING, KID));
    }
}
