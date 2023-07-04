package com.yolt.crypto.keymanagement;

import com.yolt.crypto.configuration.CryptoConfiguration;
import com.yolt.crypto.keymaterial.KeyAlgorithm;
import com.yolt.crypto.keymaterial.KeypairType;
import com.yolt.crypto.keymaterial.ProviderKey;
import com.yolt.crypto.keymaterial.SignatureAlgorithm;
import com.yolt.crypto.signing.Encoding;
import com.yolt.crypto.signing.SigningException;
import com.yolt.crypto.vault.VaultService;
import nl.ing.lovebird.clienttokens.ClientGroupToken;
import nl.ing.lovebird.clienttokens.ClientToken;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.jose4j.base64url.Base64Url;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwx.CompactSerializer;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.lang.StringUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class KeyManagementServiceTest {

    private static final UUID CLIENT_GROUP_ID = UUID.randomUUID();
    private static final UUID CLIENT_ID = UUID.randomUUID();
    private static final ClientToken CLIENT_TOKEN;
    private static final ClientGroupToken CLIENT_GROUP_TOKEN;

    static {
        JwtClaims claims = new JwtClaims();
        claims.setClaim("client-group-id", CLIENT_GROUP_ID.toString());
        claims.setClaim("sub", CLIENT_ID.toString());
        CLIENT_TOKEN = new ClientToken("serialized-form", claims);
        CLIENT_GROUP_TOKEN = new ClientGroupToken("group-serialized-from", claims);
        Security.addProvider(new BouncyCastleProvider());
    }

    private KeyManagementService keyManagementService;

    @Mock
    private VaultService vaultService;

    @Mock
    private CryptoConfiguration configuration;

    private KeyPair keyPair;

    @BeforeEach
    public void setup() throws Exception {
        KeyAlgorithm keyAlgorithm = KeyAlgorithm.RSA2048;
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyAlgorithm.getAlgorithm());
        keyGen.initialize(keyAlgorithm.getKeysize());
        keyPair = keyGen.generateKeyPair();

        keyManagementService = new KeyManagementService(configuration, vaultService);
    }

    @Test
    public void signJWS() throws Exception {
        //given
        UUID kid = UUID.randomUUID();
        when(vaultService.retrievePrivateKey(CLIENT_GROUP_TOKEN.getClientGroupIdClaim(), KeypairType.SIGNING, kid)).thenReturn(new ProviderKey<>(keyPair.getPrivate(), "BC"));

        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        String payload = createUserRequestTokenClaims(UUID.randomUUID().toString(), "secretState", "http://redirect").toJson();
        jws.setPayload(payload);
        jws.getHeaders().setObjectHeaderValue(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD, false);

        // ----
        String signingInput = CompactSerializer.serialize(jws.getHeaders().getEncodedHeader(), payload);
        byte[] bytesToSign = StringUtil.getBytesAscii(signingInput);
        String encodedSigningInput = new String(Base64.encode(bytesToSign));


        String signature = keyManagementService.sign(kid, KeypairType.SIGNING, SignatureAlgorithm.SHA256_WITH_RSA, Encoding.BASE64URL, Base64.decode(encodedSigningInput), CLIENT_GROUP_TOKEN.getClientGroupIdClaim());

        String compactSerialization = CompactSerializer.serialize(jws.getHeaders().getEncodedHeader(), payload, signature);
        // ----

        JsonWebSignature result = new JsonWebSignature();

        result.setCompactSerialization(compactSerialization);

        result.setKey(keyPair.getPublic());
        result.setKnownCriticalHeaders(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD, "http://openbanking.org.uk/iat", "http://openbanking.org.uk/iss");

        assertTrue(result.verifySignature());
    }

    @Test
    public void signWithBase64AndBase64URL() throws Exception {
        //given
        UUID kid = UUID.randomUUID();
        when(vaultService.retrievePrivateKey(CLIENT_GROUP_TOKEN.getClientGroupIdClaim(), KeypairType.SIGNING, kid)).thenReturn(new ProviderKey<>(keyPair.getPrivate(), "BC"));

        String signingInput = "ThisIsSomeVerySensitiveStuff";
        byte[] bytesToSign = StringUtil.getBytesAscii(signingInput);

        String signatureBase64encoded = keyManagementService.sign(kid, KeypairType.SIGNING, SignatureAlgorithm.SHA256_WITH_RSA, Encoding.BASE64, bytesToSign, CLIENT_GROUP_TOKEN.getClientGroupIdClaim());
        String signatureBase64Urlencoded = keyManagementService.sign(kid, KeypairType.SIGNING, SignatureAlgorithm.SHA256_WITH_RSA, Encoding.BASE64URL, bytesToSign, CLIENT_GROUP_TOKEN.getClientGroupIdClaim());

        assertNotEquals(signatureBase64encoded, signatureBase64Urlencoded);
        byte[] decoded = Base64.decode(signatureBase64encoded);
        byte[] decodedUrl = Base64Url.decode(signatureBase64Urlencoded);

        AlgorithmIdentifier algorithmIdentifier = new DefaultSignatureAlgorithmIdentifierFinder().find(SignatureAlgorithm.SHA256_WITH_RSA.getAlgorithm());
        ContentVerifier verifier = new JcaContentVerifierProviderBuilder().setProvider("BC").build(keyPair.getPublic()).get(algorithmIdentifier);

        try (OutputStream output = verifier.getOutputStream()) {
            output.write(bytesToSign);
        }
        assertTrue(verifier.verify(decoded));

        try (OutputStream output = verifier.getOutputStream()) {
            output.write(bytesToSign);
        }
        assertTrue(verifier.verify(decodedUrl));
    }

    @Test
    public void signJWSFailsBecauseOfFaultyPrivateKey() throws Exception {
        //given
        UUID kid = UUID.randomUUID();
        when(vaultService.retrievePrivateKey(CLIENT_GROUP_TOKEN.getClientGroupIdClaim(), KeypairType.SIGNING, kid)).thenReturn(new ProviderKey<>(null, "BC"));

        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        String payload = createUserRequestTokenClaims(UUID.randomUUID().toString(), "secretState", "http://redirect").toJson();
        jws.setPayload(payload);
        jws.getHeaders().setObjectHeaderValue(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD, false);

        // ----
        String signingInput = CompactSerializer.serialize(jws.getHeaders().getEncodedHeader(), payload);
        byte[] bytesToSign = StringUtil.getBytesAscii(signingInput);
        String encodedSigningInput = new String(Base64.encode(bytesToSign));

        assertThrows(SigningException.class, () -> keyManagementService.sign(kid, KeypairType.SIGNING, SignatureAlgorithm.SHA256_WITH_RSA, Encoding.BASE64URL, Base64.decode(encodedSigningInput), CLIENT_GROUP_TOKEN.getClientGroupIdClaim()));
    }

    @Test
    public void createSigningKey() throws Exception {
        //when
        UUID kid = keyManagementService.createKey(CLIENT_GROUP_TOKEN, KeyAlgorithm.RSA4096, KeypairType.SIGNING);

        //then
        assertNotNull(kid);

        verify(vaultService).createKeyPair(CLIENT_GROUP_TOKEN.getClientGroupIdClaim(), KeypairType.SIGNING, kid, KeyAlgorithm.RSA4096);
    }

    @Test
    public void deleteNotAllowedOnPrd() throws Exception {
        when(configuration.getEnvironment()).thenReturn("test-prd");
        try {
            assertThrows(KeyPairDeletionException.class, () -> keyManagementService.deleteKey(CLIENT_GROUP_TOKEN, UUID.randomUUID()));
        } finally {
            verify(configuration, never()).getDeletableKeyEnvironments();
        }
    }

    @Test
    public void deleteNotAllowedNotWhitelisted() throws Exception {
        when(configuration.getEnvironment()).thenReturn("test");
        when(configuration.getDeletableKeyEnvironments()).thenReturn(Collections.singletonList("acc"));
        assertThrows(KeyPairDeletionException.class, () -> keyManagementService.deleteKey(CLIENT_GROUP_TOKEN, UUID.randomUUID()));
    }

    private JwtClaims createUserRequestTokenClaims(final String accountRequestId, final String secretState, final String redirectUrl) {
        String clientId = UUID.randomUUID().toString();
        JwtClaims claims = new JwtClaims();

        claims.setIssuer(clientId);
        claims.setSubject(clientId);
        claims.setExpirationTimeMinutesInTheFuture(10);
        claims.setIssuedAtToNow();
        claims.setGeneratedJwtId();
        claims.setAudience("yolt");

        claims.setClaim("client_id", clientId);
        claims.setClaim("response_type", "code id_token");
        claims.setClaim("redirect_uri", redirectUrl);
        claims.setClaim("nonce", secretState);
        claims.setClaim("state", secretState);
        claims.setClaim("max_age", 86400);

        // Unfortunately, it seems that the library does not give much support to add custom serializers for claims.
        // See JwtClaims.toJson()
        // However, a nested Json object can be serialized by using nested maps..
        Map<String, Object> claimsObject = new HashMap<>();
        Map<String, Object> userInfo = new HashMap<>();
        Map<String, Object> idToken = new HashMap<>();
        Map<String, Object> openBankingIntentId = new HashMap<>();
        Map<String, Object> acr = new HashMap<>();
        acr.put("essential", true);
        acr.put("values", new String[]{"urn:openbanking:psd2:sca", "urn:openbanking:psd2:ca"});
        openBankingIntentId.put("value", accountRequestId);
        openBankingIntentId.put("essential", true);
        userInfo.put("openbanking_intent_id", openBankingIntentId);
        idToken.put("openbanking_intent_id", openBankingIntentId);
        idToken.put("acr", acr);
        claimsObject.put("userinfo", userInfo);
        claimsObject.put("id_token", idToken);
        claims.setClaim("claims", claimsObject);
        return claims;
    }
}
