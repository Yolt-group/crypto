package com.yolt.crypto.keymanagement;

import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyPairAttributesMap;
import com.yolt.crypto.cloudhsm.HSMCredentials;
import com.yolt.crypto.keymanagement.AWSCloudHSM.ApplicationCallBackHandler;
import com.yolt.crypto.keymaterial.KeyAlgorithm;
import com.yolt.crypto.keymaterial.KeypairType;
import com.yolt.crypto.keymaterial.ProviderKey;
import nl.ing.lovebird.clienttokens.ClientGroupToken;
import nl.ing.lovebird.clienttokens.ClientToken;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.security.auth.Destroyable;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.AuthProvider;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.UUID;

import static com.yolt.crypto.keymanagement.AWSCloudHSM.PUBLIC_TAG;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AWSCloudHSMTest {

    private static final UUID CLIENT_GROUP_ID = UUID.randomUUID();
    private static final UUID SIGNING_KID = UUID.randomUUID();
    private static final UUID ING_NV_GROUP_ID = UUID.fromString("141f08f5-cc7a-483e-beeb-3e28244404b1");
    private static final UUID YOLT_APP_ID = UUID.fromString("297ecda4-fd60-4999-8575-b25ad23b249c");
    private static final UUID YOLT_GROUP_ID = UUID.fromString("0005291f-68bb-4d5f-9a3f-7aa330fb7641");
    private static final UUID YTS_GROUP_ID = UUID.fromString("f767b2f9-5c90-4a4e-b728-9c9c8dadce4f");

    final HSMCredentials credentials = new HSMCredentials("partition", "username", "password");

    @Mock
    AuthProvider authProvider;
    @Mock
    KeyStoreSpi keyStore;

    @Mock
    PrivateKey privateKey;
    @Mock(extraInterfaces = Destroyable.class)
    PublicKey publicKey;

    @Mock
    KeyPairGenerator keyPairGenerator;

    AWSCloudHSM awsCloudHSM;

    @BeforeEach
    void setUp() throws CertificateException, IOException, NoSuchAlgorithmException {
        KeyStore stubKeyStore = new KeyStore(this.keyStore, null, "junit") {

        };
        stubKeyStore.load(null);
        awsCloudHSM = new AWSCloudHSM(credentials, authProvider, stubKeyStore, () -> keyPairGenerator);
    }

    @Test
    void login() throws LoginException {
        awsCloudHSM.login();
        verify(authProvider).login(null, new ApplicationCallBackHandler("username:password"));
        awsCloudHSM.logout();
    }

    @Test
    void logout() throws LoginException {
        awsCloudHSM.logout();
        verify(authProvider).logout();
    }

    @Test
    void retrievePrivateKey() throws Exception {
        when(keyStore.engineGetKey(CLIENT_GROUP_ID + "_" + SIGNING_KID, null)).thenReturn(privateKey);

        ProviderKey<PrivateKey> providerKey = awsCloudHSM.retrievePrivateKey(CLIENT_GROUP_ID, KeypairType.SIGNING, SIGNING_KID);

        assertThat(providerKey.getProvider()).isEqualTo("CloudHSM");
        assertThat(providerKey.getKey()).isSameAs(privateKey);
    }

    @Test
    void retrievePrivateKeyNotFound() throws Exception {
        when(keyStore.engineGetKey(CLIENT_GROUP_ID + "_" + SIGNING_KID, null)).thenReturn(null);

        assertThrows(KeyNotFoundException.class, () -> awsCloudHSM.retrievePrivateKey(CLIENT_GROUP_ID, KeypairType.SIGNING, SIGNING_KID));
    }

    @Test
    void retrievePublicKey() throws Exception {
        when(keyStore.engineGetKey(CLIENT_GROUP_ID + "_" + SIGNING_KID + PUBLIC_TAG, null)).thenReturn(publicKey);

        ProviderKey<PublicKey> providerKey = awsCloudHSM.retrievePublicKey(CLIENT_GROUP_ID, KeypairType.SIGNING, SIGNING_KID);

        assertThat(providerKey.getProvider()).isEqualTo("CloudHSM");
        assertThat(providerKey.getKey()).isSameAs(publicKey);
    }

    @Test
    void retrievePublicKeyNotFound() throws Exception {
        when(keyStore.engineGetKey(CLIENT_GROUP_ID + "_" + SIGNING_KID + PUBLIC_TAG, null)).thenReturn(null);

        assertThrows(KeyNotFoundException.class, () -> awsCloudHSM.retrievePublicKey(CLIENT_GROUP_ID, KeypairType.SIGNING, SIGNING_KID));
    }

    @Test
    void aKeypairCanBeStoredInCloudHSM() throws Exception {
        ArgumentCaptor<KeyPairAttributesMap> captureSpec = ArgumentCaptor.forClass(KeyPairAttributesMap.class);
        awsCloudHSM.createKeyPair(CLIENT_GROUP_ID, KeypairType.SIGNING, SIGNING_KID, KeyAlgorithm.RSA2048);
        verify(keyPairGenerator).initialize(captureSpec.capture());

        KeyPairAttributesMap spec = captureSpec.getValue();

        assertThat(spec.getPrivate(KeyAttribute.LABEL)).isEqualTo(CLIENT_GROUP_ID + "_" + SIGNING_KID);
        assertThat(spec.getPrivate(KeyAttribute.EXTRACTABLE)).isEqualTo(false);
        assertThat(spec.getPrivate(KeyAttribute.TOKEN)).isEqualTo(true);

        assertThat(spec.getPublic(KeyAttribute.LABEL)).isEqualTo(CLIENT_GROUP_ID + "_" + SIGNING_KID + PUBLIC_TAG);
        assertThat(spec.getPublic(KeyAttribute.MODULUS_BITS)).isEqualTo(2048);
        assertThat(spec.getPublic(KeyAttribute.PUBLIC_EXPONENT)).isEqualTo(BigInteger.valueOf(65537).toByteArray());
    }

    @Test
    void aKeypairCanBeDeletedFromCloudHSM() throws Exception {
        when(keyStore.engineGetKey(CLIENT_GROUP_ID + "_" + SIGNING_KID, null)).thenReturn(privateKey);
        when(keyStore.engineGetKey(CLIENT_GROUP_ID + "_" + SIGNING_KID + PUBLIC_TAG, null)).thenReturn(publicKey);

        awsCloudHSM.deleteKeyPair(CLIENT_GROUP_ID, SIGNING_KID);

        verify(privateKey).destroy();
        verify((Destroyable)publicKey).destroy();
    }

    @Test
    void retrievePrivateKeyFallbackHackForYoltApp() throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setClaim("client-group-id", YOLT_GROUP_ID.toString());
        claims.setClaim("sub", YOLT_APP_ID.toString());
        ClientToken yoltAppToken = new ClientToken("serialized-form", claims);

        when(keyStore.engineGetKey(YOLT_GROUP_ID + "_" + SIGNING_KID, null)).thenReturn(null);
        when(keyStore.engineGetKey(ING_NV_GROUP_ID + "_" + SIGNING_KID, null)).thenReturn(privateKey);

        ProviderKey<PrivateKey> providerKey = awsCloudHSM.retrievePrivateKey(yoltAppToken.getClientGroupIdClaim(), KeypairType.SIGNING, SIGNING_KID);

        assertThat(providerKey.getProvider()).isEqualTo("CloudHSM");
        assertThat(providerKey.getKey()).isSameAs(privateKey);
    }

    @Test
    void retrievePrivateKeyFallbackHackForYoltGroup() throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setClaim("client-group-id", YOLT_GROUP_ID.toString());
        ClientGroupToken yoltGroupToken = new ClientGroupToken("serialized-form", claims);

        when(keyStore.engineGetKey(YOLT_GROUP_ID + "_" + SIGNING_KID, null)).thenReturn(null);
        when(keyStore.engineGetKey(ING_NV_GROUP_ID + "_" + SIGNING_KID, null)).thenReturn(privateKey);

        ProviderKey<PrivateKey> providerKey = awsCloudHSM.retrievePrivateKey(yoltGroupToken.getClientGroupIdClaim(), KeypairType.SIGNING, SIGNING_KID);

        assertThat(providerKey.getProvider()).isEqualTo("CloudHSM");
        assertThat(providerKey.getKey()).isSameAs(privateKey);
    }

    @Test
    void retrievePrivateKeyFallbackHackForYTSGroup() throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setClaim("client-group-id", YTS_GROUP_ID.toString());
        ClientGroupToken ytsGroupToken = new ClientGroupToken("serialized-form", claims);

        when(keyStore.engineGetKey(YTS_GROUP_ID + "_" + SIGNING_KID, null)).thenReturn(null);
        when(keyStore.engineGetKey(YOLT_GROUP_ID + "_" + SIGNING_KID, null)).thenReturn(privateKey);

        ProviderKey<PrivateKey> providerKey = awsCloudHSM.retrievePrivateKey(ytsGroupToken.getClientGroupIdClaim(), KeypairType.SIGNING, SIGNING_KID);

        assertThat(providerKey.getProvider()).isEqualTo("CloudHSM");
        assertThat(providerKey.getKey()).isSameAs(privateKey);
    }
}
