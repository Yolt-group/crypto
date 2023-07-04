package com.yolt.crypto.vault;

import com.yolt.crypto.cloudhsm.HSMCredentials;
import com.yolt.crypto.keymanagement.KeyNotFoundException;
import com.yolt.crypto.keymanagement.KeyService;
import com.yolt.crypto.keymanagement.PrivateKeyImportException;
import com.yolt.crypto.keymaterial.KeyAlgorithm;
import com.yolt.crypto.keymaterial.KeypairType;
import com.yolt.crypto.keymaterial.ProviderKey;
import lombok.extern.slf4j.Slf4j;
import nl.ing.lovebird.clienttokens.ClientToken;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
@Slf4j
public class VaultService implements KeyService {

    private static final String SECRETS_PATH = "%s/%s/data/%s";
    private static final String SECRET_MAP_CLIENT_GROUP_ID = "client-group-id";
    private static final String SECRET_MAP_KEY_ALGORITHM = "key-algorithm";
    private static final String SECRET_MAP_PRIVATE_KEY = "private-key";
    private static final String SECRET_MAP_PUBLIC_KEY = "public-key";
    private static final String SECRETS_OPTIONS_CAS = "cas";
    private static final String SECRETS_OPTIONS = "options";
    private static final String SECRETS_DATA = "data";
    private static final String PROVIDER = "BC";
    private static final String CLOUDHSM_CREDENTIALS_PATH = "%s/k8s/pods/cloudhsm/kv/cloudhsm-users/%s/data/%s/%s";
    private static final String HSM_PARTITION = "HSM_PARTITION";
    private static final String HSM_USER = "HSM_USER";
    @SuppressWarnings("squid:S2068")
    private static final String HSM_PASSWORD = "HSM_PASSWORD";
    private static final String KEY_NOT_FOUND_MSG = "Key not found for clientGroupId: %s and kid: %s";
    private static final String FAILED_TO_DESERIALIZE_KEY_PAIR_MSG = "Failed to deserialize keypair from Vault";

    private final VaultAuthentication vaultAuthentication;
    private final VaultKeyValueConfiguration configuration;

    private final String cloudHSMLocation;
    private final String namespace;
    private final String environment;
    private final String applicationName;

    public VaultService(VaultAuthentication vaultAuthentication, VaultKeyValueConfiguration configuration,
                        @Value("${cluster.cloudhsm.location}") String cloudHSMLocation,
                        @Value("${namespace}") String namespace,
                        @Value("${environment}") String environment,
                        @Value("${spring.application.name}") String applicationName) {
        this.vaultAuthentication = vaultAuthentication;
        this.configuration = configuration;
        this.cloudHSMLocation = cloudHSMLocation;
        this.namespace = namespace;
        this.environment = environment;
        this.applicationName = applicationName;
    }

    @Override
    public void createKeyPair(UUID clientGroupId, KeypairType keypairType, UUID kid, KeyAlgorithm keyAlgorithm) throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPair keyPair = generateKeyPair(keyAlgorithm);
        String secretsPath = String.format(SECRETS_PATH, configuration.getSecretsBasePath(), keypairType.name().toLowerCase(), kid.toString());
        log.info("Writing a secret into path {}", secretsPath);

        Map<String, Object> data = createSecretsDataMap(keyPair.getPrivate(), clientGroupId);
        data.put(SECRET_MAP_PUBLIC_KEY, keyPair.getPublic().getEncoded());

        Map<String, Object> secrets = createSecretsMap(data);
        vaultAuthentication.vaultTemplate().write(secretsPath, secrets);
    }

    @Override
    public void deleteKeyPair(UUID clientGroupId, UUID kid) throws KeyNotFoundException {
        KeypairType keypairType;
        try {
            retrievePrivateKey(clientGroupId, KeypairType.SIGNING, kid);
            keypairType = KeypairType.SIGNING;
        } catch (KeyNotFoundException ex) {
            retrievePrivateKey(clientGroupId, KeypairType.TRANSPORT, kid);
            keypairType = KeypairType.TRANSPORT;
        }
        String secretsPath = String.format(SECRETS_PATH, configuration.getSecretsBasePath(), keypairType.name().toLowerCase(), kid.toString());
        log.info("Deleting a secret from path {}", secretsPath);
        vaultAuthentication.vaultTemplate().delete(secretsPath);
    }

    private KeyPair generateKeyPair(KeyAlgorithm keyAlgorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyAlgorithm.getAlgorithm(), PROVIDER);
        keyGen.initialize(keyAlgorithm.getKeysize());
        return keyGen.generateKeyPair();
    }

    public ProviderKey<PrivateKey> retrievePrivateKey(UUID clientGroupId, KeypairType keypairType, UUID kid) throws KeyNotFoundException {
        String secretsPath = String.format(SECRETS_PATH, configuration.getSecretsBasePath(), keypairType.name().toLowerCase(), kid.toString());
        Map<String, String> data = safeGetData(secretsPath);

        PrivateKey privateKey;
        try {
            if (hasNoPermission(data, clientGroupId)) {
                String error = String.format(KEY_NOT_FOUND_MSG, clientGroupId, kid);
                throw new KeyNotFoundException(error);
            }
            KeyFactory keyFactory = KeyFactory.getInstance(data.get(SECRET_MAP_KEY_ALGORITHM));
            privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(data.get(SECRET_MAP_PRIVATE_KEY))));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | IllegalArgumentException ex) {
            log.error(FAILED_TO_DESERIALIZE_KEY_PAIR_MSG, ex);
            String error = String.format(KEY_NOT_FOUND_MSG, clientGroupId, kid);
            throw new KeyNotFoundException(error);
        }

        return new ProviderKey<>(privateKey, PROVIDER);
    }

    public ProviderKey<PublicKey> retrievePublicKey(UUID clientGroupId, KeypairType keypairType, UUID kid) throws KeyNotFoundException {
        String secretsPath = String.format(SECRETS_PATH, configuration.getSecretsBasePath(), keypairType.name().toLowerCase(), kid.toString());
        Map<String, String> data = safeGetData(secretsPath);

        PublicKey publicKey;
        try {
            if (hasNoPermission(data, clientGroupId)) {
                String error = String.format(KEY_NOT_FOUND_MSG, clientGroupId, kid);
                throw new KeyNotFoundException(error);
            }

            KeyFactory keyFactory = KeyFactory.getInstance(data.get(SECRET_MAP_KEY_ALGORITHM));
            // When a private key has been imported, the public key is not imported along with it.
            String publicKeyEncoded = data.get(SECRET_MAP_PUBLIC_KEY);
            if (publicKeyEncoded != null) {
                publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyEncoded)));
            } else {
                String error = String.format("PublicKey not found for clientGroupId: %s and kid: %s", clientGroupId, kid);
                throw new KeyNotFoundException(error);
            }
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | IllegalArgumentException ex) {
            log.error("Failed to deserialize keypair from Vault.", ex);
            String error = String.format(KEY_NOT_FOUND_MSG, clientGroupId, kid);
            throw new KeyNotFoundException(error);
        }

        return new ProviderKey<>(publicKey, PROVIDER);
    }

    @SuppressWarnings("unchecked")
    private Map<String, String> safeGetData(String secretsPath) {
        Map<String, Object> data = vaultAuthentication.vaultTemplate().read(secretsPath).getData();
        if (data != null) {
            return (Map<String, String>) data.get("data");
        } else {
            return Collections.emptyMap();
        }
    }

    private boolean hasNoPermission(Map<String, String> data, UUID clientGroupId) {
        return !clientGroupId.toString().equals(data.get(SECRET_MAP_CLIENT_GROUP_ID));
    }

    private Map<String, Object> createSecretsDataMap(PrivateKey privateKey, UUID clientGroupId) {
        String keyAlgorithm = privateKey.getAlgorithm();
        Map<String, Object> data = new HashMap<>();
        data.put(SECRET_MAP_PRIVATE_KEY, privateKey.getEncoded());
        data.put(SECRET_MAP_KEY_ALGORITHM, keyAlgorithm);
        data.put(SECRET_MAP_CLIENT_GROUP_ID, clientGroupId);

        return data;
    }

    private Map<String, Object> createSecretsMap(Map<String, Object> data) {
        Map<Object, Object> options = new HashMap<>();
        Map<String, Object> secrets = new HashMap<>();
        options.put(SECRETS_OPTIONS_CAS, "0"); // do not allow to overwrite existing one.
        secrets.put(SECRETS_OPTIONS, options);
        secrets.put(SECRETS_DATA, data);
        return secrets;
    }

    public HSMCredentials getHSMCredentials() {
        String secretsPath = String.format(CLOUDHSM_CREDENTIALS_PATH, cloudHSMLocation, applicationName, environment, namespace);
        Map<String, String> data = safeGetData(secretsPath);

        return new HSMCredentials(data.get(HSM_PARTITION), data.get(HSM_USER), data.get(HSM_PASSWORD));
    }
}
