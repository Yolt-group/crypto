package com.yolt.crypto.keymanagement;

import com.yolt.crypto.configuration.CryptoConfiguration;
import com.yolt.crypto.keymaterial.KeyAlgorithm;
import com.yolt.crypto.keymaterial.KeypairType;
import com.yolt.crypto.keymaterial.ProviderKey;
import com.yolt.crypto.keymaterial.SignatureAlgorithm;
import com.yolt.crypto.signing.Encoding;
import com.yolt.crypto.signing.SigningException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nl.ing.lovebird.clienttokens.ClientGroupToken;
import nl.ing.lovebird.clienttokens.ClientToken;
import nl.ing.lovebird.logging.AuditLogger;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.jose4j.base64url.Base64Url;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

@Service
@Slf4j
@RequiredArgsConstructor
public class KeyManagementService {

    // List of names that can never become extractable key environments.
    // List of environment names that can never allow deletion of keys.
    // Currently `environment` should resolve to 'prd', but we want to make sure that we shield ourselves against accidents.
    static final List<String> PRODUCTION_ENVIRONMENT_KEYWORDS = Arrays.asList("prd", "prod", "production");

    private final Base64Url base64Url = new Base64Url();
    private final CryptoConfiguration cryptoConfiguration;
    private final KeyService keyService;

    public String sign(UUID privateKid, KeypairType keyType, SignatureAlgorithm algorithm, Encoding encoding, byte[] payload, UUID clientGroupId) throws SigningException, KeyNotFoundException {
        try {
            ProviderKey<PrivateKey> providerPrivateKey = keyService.retrievePrivateKey(clientGroupId, keyType, privateKid);
            PrivateKey privateKey = providerPrivateKey.getKey();
            String provider = providerPrivateKey.getProvider();
            ContentSigner signGen = new JcaContentSignerBuilder(algorithm.getAlgorithm()).setProvider(provider).build(privateKey);

            try (OutputStream output = signGen.getOutputStream()) {
                output.write(payload);
            }

            String encodedSignature;
            String message;
            switch (encoding) {
                case BASE64URL:
                    encodedSignature = base64Url.base64UrlEncode(signGen.getSignature());
                    message = String.format("Successfully signed payload for client group: %s, kid: %s and algorithm: %s, resulting url encoded signature: %s",
                            clientGroupId, privateKid, algorithm.getAlgorithm(), encodedSignature);
                    break;
                case BASE64:
                default:
                    encodedSignature = Base64.toBase64String(signGen.getSignature());
                    message = String.format("Successfully signed payload for client group: %s, kid: %s and algorithm: %s, resulting encoded signature: %s",
                            clientGroupId, privateKid, algorithm.getAlgorithm(), encodedSignature);
                    break;
            }

            AuditLogger.logSuccess(message, payload);
            return encodedSignature;
        } catch (IOException | OperatorCreationException ex) {
            String message = String.format("Failed creating signature for payload for clientId: %s, kid: %s and algorithm: %s",
                    clientGroupId, privateKid, algorithm.getAlgorithm());
            AuditLogger.logError(message, payload, ex);
            throw new SigningException(message);
        }
    }

    UUID createKey(ClientGroupToken clientGroupToken, KeyAlgorithm keyAlgorithm, KeypairType keyType) throws KeyPairCreationException {
        try {
            UUID kid = UUID.randomUUID();
            keyService.createKeyPair(clientGroupToken.getClientGroupIdClaim(), keyType, kid, keyAlgorithm);
            String message = String.format("Successfully created and stored keypair for clientGroupId: %s, keyAlgorithm: %s, keyType: %s. Resulting kid: %s",
                    clientGroupToken.getClientGroupIdClaim(), keyAlgorithm, keyType, kid);
            AuditLogger.logSuccess(message, null);
            return kid;
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException ex) {
            String message = String.format("Failed to create keypair for clientGroupId: %s, keyAlgorithm: %s, keyType: %s",
                    clientGroupToken.getClientGroupIdClaim(), keyAlgorithm, keyType);
            AuditLogger.logError(message, null, ex);

            throw new KeyPairCreationException(message);
        }
    }

    void deleteKey(ClientGroupToken clientGroupToken, UUID kid) throws KeyPairDeletionException {
        if (!isDeleteAllowed()) {
            throw new KeyPairDeletionException("Deletion not allowed");
        }
        try {
            keyService.deleteKeyPair(clientGroupToken.getClientGroupIdClaim(), kid);
            String message = String.format("Successfully deleted keypair for clientGroupId: %s, kid: %s",
                    clientGroupToken.getClientGroupIdClaim(), kid);
            AuditLogger.logSuccess(message, null);
        } catch (Exception ex) {
            String message = String.format("Failed to delete keypair for clientGroupId: %s, kid: %s",
                    clientGroupToken.getClientGroupIdClaim(), kid);
            AuditLogger.logError(message, null, ex);

            throw new KeyPairDeletionException(message);
        }
    }

    /**
     * We want keys to be deleteable from the HSM when we are not on production.
     * The reason for this is that there is a limit of 3500 keys in an HSM cluster, but we want to test creation of keys.
     *
     * @return Whether the key can be deleted from the HSM or not.
     */
    private boolean isDeleteAllowed() {
        String environment = cryptoConfiguration.getEnvironment();

        if (PRODUCTION_ENVIRONMENT_KEYWORDS.stream().anyMatch(environment::contains)) {
            return false;
        }

        if (!cryptoConfiguration.getDeletableKeyEnvironments().contains(environment)) {
            return false;
        }

        log.info("Delete is allowed for environment: " + environment);
        return true;
    }
}
