package com.yolt.crypto.keymanagement;

import com.yolt.crypto.keymaterial.KeypairType;
import com.yolt.securityutils.crypto.KeyPair;
import com.yolt.securityutils.crypto.RSA;
import nl.ing.lovebird.clienttokens.ClientToken;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.Key;
import java.security.Security;
import java.util.UUID;

import static org.assertj.core.api.Java6Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class DecryptionServiceTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private Key decryptionKey;

    private Key encryptionKey;

    @BeforeEach
    public void init() {
        KeyPair keyPair = RSA.Builder.generateKeys(2048);
        this.encryptionKey = keyPair.getPublicKey().getKey();
        this.decryptionKey = keyPair.getPrivateKey().getKey();
    }

    @Test
    public void testDecryption() throws Exception {
        DecryptionService decryptionService = new DecryptionService(decryptionKey);

        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512);
        jwe.setKey(encryptionKey);
        String expectedSecret = "This is top-secret!";
        jwe.setPayload(expectedSecret);
        String compactSerialization = jwe.getCompactSerialization();

        JwtClaims claims = new JwtClaims();
        claims.setClaim("sub", UUID.randomUUID().toString());
        ClientToken clientToken = new ClientToken("serialized-form", claims);

        String secret = decryptionService.decrypt(clientToken, compactSerialization, KeypairType.SIGNING);

        assertThat(secret).isEqualTo(expectedSecret);
    }

    @Test
    public void testDecryptionFailsWithUnsupportedAlgorithm() throws Exception {
        DecryptionService decryptionService = new DecryptionService(decryptionKey);

        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_GCM);
        jwe.setKey(encryptionKey);
        String expectedSecret = "This is top-secret!";
        jwe.setPayload(expectedSecret);
        String compactSerialization = jwe.getCompactSerialization();

        JwtClaims claims = new JwtClaims();
        claims.setClaim("client-group-id", UUID.randomUUID().toString());
        claims.setClaim("sub", UUID.randomUUID().toString());
        ClientToken clientToken = new ClientToken("serialized-form", claims);

        assertThrows(KeyPairImportException.class, () -> decryptionService.decrypt(clientToken, compactSerialization, KeypairType.SIGNING));
    }
}
