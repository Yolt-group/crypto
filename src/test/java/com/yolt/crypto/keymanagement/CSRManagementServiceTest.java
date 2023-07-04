package com.yolt.crypto.keymanagement;

import com.yolt.crypto.keymaterial.*;
import com.yolt.crypto.vault.VaultService;
import nl.ing.lovebird.clienttokens.ClientGroupToken;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemReader;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.StringReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.*;

import static java.util.Arrays.asList;
import static java.util.Collections.*;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class CSRManagementServiceTest {

    private static final UUID CLIENT_GROUP_ID = UUID.randomUUID();
    private static final ClientGroupToken CLIENT_TOKEN;

    static {
        JwtClaims claims = new JwtClaims();
        claims.setClaim("client-group-id", CLIENT_GROUP_ID.toString());
        claims.setClaim("sub", "group: " + CLIENT_GROUP_ID);
        CLIENT_TOKEN = new ClientGroupToken("serialized-form", claims);
        Security.addProvider(new BouncyCastleProvider());
    }

    private CSRManagementService csrManagementService;

    @Mock
    private VaultService vaultService;

    private KeyPair keyPair;

    @BeforeEach
    public void setup() throws Exception {
        KeyAlgorithm keyAlgorithm = KeyAlgorithm.RSA2048;
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyAlgorithm.getAlgorithm());
        keyGen.initialize(keyAlgorithm.getKeysize());
        keyPair = keyGen.generateKeyPair();

        csrManagementService = new CSRManagementService(vaultService);
    }

    @Test
    public void generateCSR() throws Exception {
        //given
        UUID kid = UUID.randomUUID();

        when(vaultService.retrievePrivateKey(CLIENT_TOKEN.getClientGroupIdClaim(), KeypairType.TRANSPORT, kid)).thenReturn(new ProviderKey<>(keyPair.getPrivate(), "BC"));
        when(vaultService.retrievePublicKey(CLIENT_TOKEN.getClientGroupIdClaim(), KeypairType.TRANSPORT, kid)).thenReturn(new ProviderKey<>(keyPair.getPublic(), "BC"));

        //when
        List<DistinguishedNameElement> distinguishedNames = asList(new DistinguishedNameElement("CN", "duke.com"),
                new DistinguishedNameElement("OU", "Java,Soft"),
                new DistinguishedNameElement("O", "Sun Microsystems+Test"),
                new DistinguishedNameElement("C", "US"));
        Set<String> sans = new HashSet<>();
        sans.add("*.test.com");
        String csr = csrManagementService.generateCSR(CLIENT_TOKEN, kid, new CSRRequirementsDTO(KeypairType.TRANSPORT, singletonList(ServiceType.AIS), SignatureAlgorithm.SHA256_WITH_RSA, distinguishedNames, false, sans));

        //then
        assertNotNull(csr);

        PemReader pemReader = new PemReader(new StringReader(csr));
        JcaPKCS10CertificationRequest certificationRequest = new JcaPKCS10CertificationRequest(pemReader.readPemObject().getContent());
        assertThat(certificationRequest.getPublicKey(), is(keyPair.getPublic()));
        assertThat(certificationRequest.getSubject().toString(), is("CN=duke.com,OU=Java\\,Soft,O=Sun Microsystems\\+Test,C=US"));
        Extensions certificateExtensions = Extensions.getInstance(certificationRequest.getAttributes(pkcs_9_at_extensionRequest)[0].getAttrValues().getObjectAt(0));
        assertThat(certificateExtensions.getExtension(Extension.subjectKeyIdentifier).getParsedValue(), equalTo(((new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic())))));
        assertThat(certificateExtensions.getExtension(Extension.keyUsage).getParsedValue(), equalTo(((new KeyUsage(KeyUsage.digitalSignature).toASN1Primitive()))));
        assertThat(certificateExtensions.getExtension(Extension.extendedKeyUsage).getParsedValue(), equalTo((new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth}).toASN1Primitive())));
        assertThat(certificateExtensions.getExtension(Extension.subjectAlternativeName).getParsedValue().toString(), equalTo("[[CONTEXT 2]#2a2e746573742e636f6d]"));
    }

    @Test
    public void generateCSRForEIDAS() throws Exception {
        //given
        UUID kid = UUID.randomUUID();
        when(vaultService.retrievePrivateKey(CLIENT_TOKEN.getClientGroupIdClaim(), KeypairType.TRANSPORT, kid)).thenReturn(new ProviderKey<>(keyPair.getPrivate(), "BC"));
        when(vaultService.retrievePublicKey(CLIENT_TOKEN.getClientGroupIdClaim(), KeypairType.TRANSPORT, kid)).thenReturn(new ProviderKey<>(keyPair.getPublic(), "BC"));
        Set<String> sans = new HashSet<>();
        sans.add("*.test.com");

        //when
        List<DistinguishedNameElement> distinguishedNames = Arrays.asList(new DistinguishedNameElement("C", "NL"), new DistinguishedNameElement("CN", "test.com"));
        String csr = csrManagementService.generateCSR(CLIENT_TOKEN, kid, new CSRRequirementsDTO(KeypairType.TRANSPORT, asList(ServiceType.AIS, ServiceType.PIS), SignatureAlgorithm.SHA256_WITH_RSA, distinguishedNames, true, sans));

        //then
        assertNotNull(csr);

        PemReader pemReader = new PemReader(new StringReader(csr));
        JcaPKCS10CertificationRequest certificationRequest = new JcaPKCS10CertificationRequest(pemReader.readPemObject().getContent());
        Extensions certificateExtensions = Extensions.getInstance(certificationRequest.getAttributes(pkcs_9_at_extensionRequest)[0].getAttrValues().getObjectAt(0));
        assertThat(certificateExtensions.getExtension(Extension.qCStatements).getParsedValue().toString(), equalTo("[[0.4.0.1862.1.6, [0.4.0.1862.1.6.3]], [0.4.0.19495.2, [[[0.4.0.19495.1.3, PSP_AI], [0.4.0.19495.1.2, PSP_PI]], The Netherlands Bank, NL-DNB]]]"));
    }

    @Test
    public void generateCSRForEIDASWithoutSans() throws Exception {
        //given
        UUID kid = UUID.randomUUID();
        when(vaultService.retrievePrivateKey(CLIENT_TOKEN.getClientGroupIdClaim(), KeypairType.TRANSPORT, kid)).thenReturn(new ProviderKey<>(keyPair.getPrivate(), "BC"));
        when(vaultService.retrievePublicKey(CLIENT_TOKEN.getClientGroupIdClaim(), KeypairType.TRANSPORT, kid)).thenReturn(new ProviderKey<>(keyPair.getPublic(), "BC"));
        Set<String> sans = new HashSet<>();

        //when
        List<DistinguishedNameElement> distinguishedNames = Arrays.asList(new DistinguishedNameElement("C", "NL"), new DistinguishedNameElement("CN", "test.com"));
        String csr = csrManagementService.generateCSR(CLIENT_TOKEN, kid, new CSRRequirementsDTO(KeypairType.TRANSPORT, asList(ServiceType.AIS, ServiceType.PIS), SignatureAlgorithm.SHA256_WITH_RSA, distinguishedNames, true, sans));

        //then
        assertNotNull(csr);
    }

    @Test
    public void generateCSRWithIncorrectDNs() throws Exception {
        //given
        UUID kid = UUID.randomUUID();

        when(vaultService.retrievePrivateKey(CLIENT_TOKEN.getClientGroupIdClaim(), KeypairType.TRANSPORT, kid)).thenReturn(new ProviderKey<>(keyPair.getPrivate(), "BC"));
        when(vaultService.retrievePublicKey(CLIENT_TOKEN.getClientGroupIdClaim(), KeypairType.TRANSPORT, kid)).thenReturn(new ProviderKey<>(keyPair.getPublic(), "BC"));

        //when
        List<DistinguishedNameElement> distinguishedNames = singletonList(new DistinguishedNameElement("DN", "incorrect@DN"));
        assertThrows(IllegalArgumentException.class, () -> csrManagementService.generateCSR(CLIENT_TOKEN, kid, new CSRRequirementsDTO(KeypairType.TRANSPORT, singletonList(ServiceType.AIS), SignatureAlgorithm.SHA256_WITH_RSA, distinguishedNames, false, new HashSet<>())));
    }

    @Test
    public void generateCSRForEIDASFailsForIncorrectCountryCode() throws Exception {
        //given
        UUID kid = UUID.randomUUID();
        when(vaultService.retrievePrivateKey(CLIENT_TOKEN.getClientGroupIdClaim(), KeypairType.TRANSPORT, kid)).thenReturn(new ProviderKey<>(keyPair.getPrivate(), "BC"));
        when(vaultService.retrievePublicKey(CLIENT_TOKEN.getClientGroupIdClaim(), KeypairType.TRANSPORT, kid)).thenReturn(new ProviderKey<>(keyPair.getPublic(), "BC"));

        //when
        List<DistinguishedNameElement> distinguishedNames = singletonList(new DistinguishedNameElement("C", "US"));
        assertThrows(IllegalArgumentException.class, () -> csrManagementService.generateCSR(CLIENT_TOKEN, kid, new CSRRequirementsDTO(KeypairType.TRANSPORT, singletonList(ServiceType.AIS), SignatureAlgorithm.SHA256_WITH_RSA, distinguishedNames, true, new HashSet<>())));
    }

    @Test
    public void generateCSRForEIDASFailsForMissingCountryCode() throws Exception {
        //given
        UUID kid = UUID.randomUUID();
        when(vaultService.retrievePrivateKey(CLIENT_TOKEN.getClientGroupIdClaim(), KeypairType.TRANSPORT, kid)).thenReturn(new ProviderKey<>(keyPair.getPrivate(), "BC"));
        when(vaultService.retrievePublicKey(CLIENT_TOKEN.getClientGroupIdClaim(), KeypairType.TRANSPORT, kid)).thenReturn(new ProviderKey<>(keyPair.getPublic(), "BC"));

        //when
        List<DistinguishedNameElement> distinguishedNames = emptyList();
        assertThrows(IllegalArgumentException.class, () -> csrManagementService.generateCSR(CLIENT_TOKEN, kid, new CSRRequirementsDTO(KeypairType.TRANSPORT, singletonList(ServiceType.AIS), SignatureAlgorithm.SHA256_WITH_RSA, distinguishedNames, true, new HashSet<>())));
    }

    @Test
    public void generateCSRForEIDASFailsForEmptyServiceTypes() throws Exception {
        //given
        UUID kid = UUID.randomUUID();
        when(vaultService.retrievePrivateKey(CLIENT_TOKEN.getClientGroupIdClaim(), KeypairType.TRANSPORT, kid)).thenReturn(new ProviderKey<>(keyPair.getPrivate(), "BC"));
        when(vaultService.retrievePublicKey(CLIENT_TOKEN.getClientGroupIdClaim(), KeypairType.TRANSPORT, kid)).thenReturn(new ProviderKey<>(keyPair.getPublic(), "BC"));
        List<ServiceType> serviceTypes = emptyList();

        //when
        List<DistinguishedNameElement> distinguishedNames = singletonList(new DistinguishedNameElement("C", "NL"));
        assertThrows(IllegalArgumentException.class, () -> csrManagementService.generateCSR(CLIENT_TOKEN, kid, new CSRRequirementsDTO(KeypairType.TRANSPORT, serviceTypes, SignatureAlgorithm.SHA256_WITH_RSA, distinguishedNames, true, null)));
    }

    @Test
    public void subjectIsGeneratedInOrderOfList() throws Exception {
        //given
        UUID kid = UUID.randomUUID();
        when(vaultService.retrievePrivateKey(CLIENT_TOKEN.getClientGroupIdClaim(), KeypairType.SIGNING, kid)).thenReturn(new ProviderKey<>(keyPair.getPrivate(), "BC"));
        when(vaultService.retrievePublicKey(CLIENT_TOKEN.getClientGroupIdClaim(), KeypairType.SIGNING, kid)).thenReturn(new ProviderKey<>(keyPair.getPublic(), "BC"));

        //when
        DistinguishedNameElement cn = new DistinguishedNameElement("CN", "duke.com");
        DistinguishedNameElement ou = new DistinguishedNameElement("OU", "Java,Soft");
        List<DistinguishedNameElement> distinguishedNames = asList(cn, ou);
        List<DistinguishedNameElement> distinguishedNames2 = asList(ou, cn);
        String csr1 = csrManagementService.generateCSR(CLIENT_TOKEN, kid, new CSRRequirementsDTO(KeypairType.SIGNING, singletonList(ServiceType.AIS), SignatureAlgorithm.SHA256_WITH_RSA, distinguishedNames, false, emptySet()));
        String csr2 = csrManagementService.generateCSR(CLIENT_TOKEN, kid, new CSRRequirementsDTO(KeypairType.SIGNING, singletonList(ServiceType.AIS), SignatureAlgorithm.SHA256_WITH_RSA, distinguishedNames2, false, emptySet()));

        //then
        JcaPKCS10CertificationRequest certificationRequest1 = new JcaPKCS10CertificationRequest(new PemReader(new StringReader(csr1)).readPemObject().getContent());
        JcaPKCS10CertificationRequest certificationRequest2 = new JcaPKCS10CertificationRequest(new PemReader(new StringReader(csr2)).readPemObject().getContent());
        assertThat(certificationRequest1.getSubject().toString(), is("CN=duke.com,OU=Java\\,Soft"));
        assertThat(certificationRequest2.getSubject().toString(), is("OU=Java\\,Soft,CN=duke.com"));
    }
}
