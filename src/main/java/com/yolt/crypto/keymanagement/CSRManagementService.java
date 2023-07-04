package com.yolt.crypto.keymanagement;

import com.yolt.crypto.keymaterial.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nl.ing.lovebird.clienttokens.ClientGroupToken;
import nl.ing.lovebird.logging.AuditLogger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.springframework.stereotype.Service;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.StringWriter;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest;

@Service
@Slf4j
@RequiredArgsConstructor
public class CSRManagementService {

    private static final KeyUsage SIGNING_KEY_USAGE = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation);
    private static final KeyUsage TRANSPORT_KEY_USAGE = new KeyUsage(KeyUsage.digitalSignature);
    private static final ExtendedKeyUsage TRANSPORT_EXTENDED_KEY_USAGE = new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth});

    private final KeyService keyService;

    String generateCSR(ClientGroupToken clientGroupToken, UUID kid, CSRRequirementsDTO csrRequirements) throws KeyNotFoundException, CSRGenerationException {
        KeypairType keyType = csrRequirements.getType();
        List<DistinguishedNameElement> distinguishedNames = csrRequirements.getDistinguishedNames();
        SignatureAlgorithm signatureAlgorithm = csrRequirements.getSignatureAlgorithm();
        List<ServiceType> serviceTypes = csrRequirements.getServiceTypes();
        boolean isEIDASCertificate = csrRequirements.isEidasCertificate();
        Set<String> sans = csrRequirements.getSubjectAlternativeNames();

        ProviderKey<PrivateKey> privateKey = keyService.retrievePrivateKey(clientGroupToken.getClientGroupIdClaim(), keyType, kid);
        ProviderKey<PublicKey> publicKey = getPublicKey(clientGroupToken, kid, keyType);
        try {
            X500Principal csrSubject = getSubject(distinguishedNames);
            Extensions csrExtensions = getExtensions(keyType, publicKey.getKey(), serviceTypes, distinguishedNames, isEIDASCertificate, sans);

            String csr = signCSR(publicKey, privateKey, signatureAlgorithm, csrExtensions, csrSubject);
            String message = String.format("Successfully created CSR for clientGroupId: %s, kid: %s, keyType: %s, algorithm: %s, dns: %s, eidas: %s",
                    clientGroupToken.getClientGroupIdClaim(), kid, keyType, signatureAlgorithm.getAlgorithm(), distinguishedNames, isEIDASCertificate);
            AuditLogger.logSuccess(message, csr);
            return csr;
        } catch (IOException | OperatorCreationException | InvalidNameException ex) {
            String message = String.format("Failed creating CSR for clientGroupId: %s, kid: %s, keyType: %s, algorithm: %s, dns: %s, eidas: %s",
                    clientGroupToken.getClientGroupIdClaim(), kid, keyType, signatureAlgorithm.getAlgorithm(), distinguishedNames, isEIDASCertificate);
            AuditLogger.logError(message, null, ex);
            throw new CSRGenerationException(message);
        }
    }

    private ProviderKey<PublicKey> getPublicKey(ClientGroupToken clientGroupToken, UUID kid, KeypairType keyType) {
        ProviderKey<PublicKey> publicKey;
        try {
            publicKey = keyService.retrievePublicKey(clientGroupToken.getClientGroupIdClaim(), keyType, kid);
        } catch (KeyNotFoundException ex) {
            throw new IllegalStateException("Cannot generate a CSR for a keypair without a public key. This key is probably imported, so the public key information is lost.");
        }
        return publicKey;
    }

    private X500Principal getSubject(List<DistinguishedNameElement> distinguishedNames) throws InvalidNameException {
        List<Rdn> rdns = new LinkedList<>();
        for (DistinguishedNameElement dn : distinguishedNames) {
            Rdn parsed = new Rdn(dn.getType(), dn.getValue());
            rdns.add(parsed);
        }

        LdapName principalName = new LdapName(rdns);

        return new X500Principal(principalName.toString());
    }

    private Extensions getExtensions(KeypairType keypairType, PublicKey publicKey, List<ServiceType> serviceTypes, List<DistinguishedNameElement> distinguishedNames, boolean isEIDASCertificate, Set<String> sans) throws IOException {
        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();

        try {
            JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
            extensionsGenerator.addExtension(Extension.subjectKeyIdentifier, false, extensionUtils.createSubjectKeyIdentifier(publicKey));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Could not get the Subject Key Identifier for the Public Key", e);
        }

        if (keypairType == KeypairType.SIGNING) {
            extensionsGenerator.addExtension(Extension.keyUsage, true, SIGNING_KEY_USAGE);
        } else if (keypairType == KeypairType.TRANSPORT) {
            if (sans != null && !sans.isEmpty()) {
                extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, getSubjectAlternativeNames(sans));
            }
            extensionsGenerator.addExtension(Extension.keyUsage, true, TRANSPORT_KEY_USAGE);
            extensionsGenerator.addExtension(Extension.extendedKeyUsage, false, TRANSPORT_EXTENDED_KEY_USAGE);
        } else {
            throw new IllegalStateException("KeypairType: " + keypairType + " not supported");
        }

        if (isEIDASCertificate) {
            ASN1Encodable qcStatementInfo = EIDASQCStatementUtils.getQCStatementInfo(keypairType, serviceTypes, distinguishedNames);
            extensionsGenerator.addExtension(Extension.qCStatements, false, qcStatementInfo);
        }

        return extensionsGenerator.generate();
    }

    private GeneralNames getSubjectAlternativeNames(Set<String> sans) {
        if (sans == null || sans.isEmpty()) {
            throw new IllegalArgumentException("SAN list is empty for transport certificate");
        }

        return new GeneralNames(sans.stream()
                .map(domain -> new GeneralName(GeneralName.dNSName, domain))
                .toArray(GeneralName[]::new));
    }

    private String signCSR(ProviderKey<PublicKey> publicKey, ProviderKey<PrivateKey> privateKey, SignatureAlgorithm signatureAlgorithm, Extensions extensions, X500Principal subject) throws OperatorCreationException, IOException, InvalidNameException {
        if (!publicKey.getProvider().equals(privateKey.getProvider())) {
            log.error("PublicKey and PrivateKey are from different providers.");
        }

        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey.getKey());

        builder.addAttribute(pkcs_9_at_extensionRequest, extensions);

        ContentSigner signGen = new JcaContentSignerBuilder(signatureAlgorithm.getAlgorithm())
                .setProvider(privateKey.getProvider())
                .build(privateKey.getKey());
        PKCS10CertificationRequest csr = builder.build(signGen);

        StringWriter output = new StringWriter();
        try (JcaPEMWriter pem = new JcaPEMWriter(output)) {
            pem.writeObject(csr);
        }
        return output.toString();
    }
}
