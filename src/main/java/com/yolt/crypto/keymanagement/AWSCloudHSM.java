package com.yolt.crypto.keymanagement;

import com.amazonaws.cloudhsm.jce.jni.exception.AddAttributeException;
import com.amazonaws.cloudhsm.jce.jni.exception.ProviderInitializationException;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.KeyStoreWithAttributes;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMapBuilder;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyPairAttributesMap;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyPairAttributesMapBuilder;
import com.yolt.crypto.cloudhsm.HSMCredentials;
import com.yolt.crypto.keymaterial.KeyAlgorithm;
import com.yolt.crypto.keymaterial.KeypairType;
import com.yolt.crypto.keymaterial.ProviderKey;
import com.yolt.crypto.vault.VaultService;
import lombok.EqualsAndHashCode;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.AuthProvider;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * This service communicates with CloudHSM to fetch private keys and to sign data. It uses Vault for retrieving CloudHSM
 * login credentials and to fallback to Vault for fetching private keys and signing data.
 */
@Slf4j
@Service
@Primary
@ConditionalOnProperty(prefix = "yolt.crypto", name = "cloudHSM.enabled")
public class AWSCloudHSM implements KeyService {

    static final String PUBLIC_TAG = ":public";
    private static final UUID ING_NV_GROUP_ID = UUID.fromString("141f08f5-cc7a-483e-beeb-3e28244404b1");
    private static final UUID YOLT_GROUP_ID = UUID.fromString("0005291f-68bb-4d5f-9a3f-7aa330fb7641");
    private static final UUID YTS_CLIENT_GROUP_ID = UUID.fromString("f767b2f9-5c90-4a4e-b728-9c9c8dadce4f");
    private static final String EXCEPTION_OCCURRED_WHILE_LOOKING_UP_KEY_IN_CLOUD_HSM_KEYSTORE = "Exception occurred while looking up key in AWS Cloud HSM keystore";
    private static final String UNABLE_TO_RETRIEVE_KEY_PAIR_MSG = "Unable to retrieve key from AWS Cloud HSM";
    private final HSMCredentials hsmCredentials;
    private final AuthProvider provider;
    private final KeyStore keystore;
    private final KeyPairGeneratorSupplier keyPairGeneratorSupplier;

    AWSCloudHSM(HSMCredentials hsmCredentials, AuthProvider provider, KeyStore keystore, KeyPairGeneratorSupplier keyPairGeneratorSupplier) {
        this.hsmCredentials = hsmCredentials;
        this.provider = provider;
        this.keystore = keystore;
        this.keyPairGeneratorSupplier = keyPairGeneratorSupplier;
    }

    @Autowired
    public AWSCloudHSM(VaultService vaultService) throws ProviderInitializationException, LoginException, IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        this(
                vaultService.getHSMCredentials(),
                cloudHsmProviderInstance(),
                cloudHsmKeyStoreInstance(),
                cloudHsmKeyPairGeneratorProviderInstance()
        );
    }

    private static AuthProvider cloudHsmProviderInstance() throws IOException, ProviderInitializationException, LoginException {
        AuthProvider provider = (AuthProvider) Security.getProvider(CloudHsmProvider.PROVIDER_NAME);
        if (provider == null) {
            provider = new CloudHsmProvider();
        }
        Security.addProvider(provider);
        return provider;
    }

    private static KeyStore cloudHsmKeyStoreInstance() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStoreWithAttributes keystore = KeyStoreWithAttributes.getInstance(CloudHsmProvider.PROVIDER_NAME);
        keystore.load(null, null);
        return keystore;
    }

    private static KeyPairGeneratorSupplier cloudHsmKeyPairGeneratorProviderInstance() {
        return () -> KeyPairGenerator.getInstance("RSA", CloudHsmProvider.PROVIDER_NAME);
    }

    @PostConstruct
    void login() throws LoginException {
        String userName = hsmCredentials.getUsername();
        String password = hsmCredentials.getPassword();
        ApplicationCallBackHandler loginHandler = new ApplicationCallBackHandler(userName + ":" + password);
        // This can throw an LoginException which will block the app from starting up. This is wanted behavior, because once we
        // rollover credentials for CloudHSM we can keep old instances, with old credentials, running until the new credentials work fine.
        provider.login(null, loginHandler);
        logKeysAfterLogin();
    }

    private void logKeysAfterLogin() {
        try {
            Set<String> allKeys = StreamSupport.stream(Spliterators.spliteratorUnknownSize(keystore.aliases().asIterator(), 0), false)
                    .collect(Collectors.toSet());
            Set<String> danglingPubKeys = allKeys
                    .stream()
                    .filter(it -> it.endsWith(PUBLIC_TAG))
                    .filter(it -> !allKeys.contains(it.substring(0, it.length() - PUBLIC_TAG.length())))
                    .collect(Collectors.toSet());
            log.info("We have {} key aliases: {}", allKeys.size(), String.join(System.lineSeparator(), allKeys));
            log.info("We have {} dangling pub keys aliases: {}", danglingPubKeys.size(), String.join(System.lineSeparator(), danglingPubKeys));

        } catch (KeyStoreException e) {
            log.warn("This keystore type {} does not support enumeration", keystore.getProvider(), e); //NOSHERIFF
        } catch (RuntimeException e) {
            log.error("Unexpected error while logging key information at startup", e);
        }
    }

    @RequiredArgsConstructor
    @EqualsAndHashCode
    static class ApplicationCallBackHandler implements CallbackHandler {

        private final String cloudhsmPin;

        @Override
        public void handle(Callback[] callbacks) {
            for (Callback callback : callbacks) {
                if (callback instanceof PasswordCallback pc) {
                    pc.setPassword(cloudhsmPin.toCharArray());
                }
            }
        }
    }

    @PreDestroy
    void logout() {
        try {
            provider.logout();
        } catch (LoginException e) {
            // Logout of the HSM when the pod is destroyed.
            // As a session with the HSM has a TTL of 10min, it is likely that our session was already closed making logging as info enough.
            log.info("Logout of HSM failed.", e);
        }
    }

    private Optional<Key> getKeyFromHSM(UUID clientGroupId, UUID kid, String tag) {
        String alias = keyAlias(clientGroupId, kid);
        Key key = null;
        try {
            key = getKeyByLabel(alias + tag);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
            log.warn(EXCEPTION_OCCURRED_WHILE_LOOKING_UP_KEY_IN_CLOUD_HSM_KEYSTORE, ex);
        }
        if (key == null && YOLT_GROUP_ID.equals(clientGroupId)) {
            log.info("Retrying to find key using the ING N.V. Client Group instead of the Yolt Client Group Id");
            try {
                key = getKeyByLabel(ING_NV_GROUP_ID + "_" + kid + tag);
            } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
                log.warn(EXCEPTION_OCCURRED_WHILE_LOOKING_UP_KEY_IN_CLOUD_HSM_KEYSTORE, ex);
            }
        }

        if (key == null && YTS_CLIENT_GROUP_ID.equals(clientGroupId)) {
            log.info("Retrying to find key using the Yolt Client Group ID instead of the YTS Client Group ID");
            try {
                key = getKeyByLabel(YOLT_GROUP_ID + "_" + kid + tag);
            } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
                log.warn(EXCEPTION_OCCURRED_WHILE_LOOKING_UP_KEY_IN_CLOUD_HSM_KEYSTORE, ex);
            }
        }
        return Optional.ofNullable(key);
    }

    private void deleteKeyByAlias(String alias) throws KeyNotFoundException {
        try {
            deleteKey(alias);
            log.info("Deleted key for alias: {}", alias);
        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | DestroyFailedException ex) {
            throw new KeyNotFoundException("Unable to delete the key", ex);
        }

        try {
            deleteKey(alias + PUBLIC_TAG);
            log.info("Deleted public key for alias: {}", alias);
        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | DestroyFailedException ex) {
            /* Failing to delete a public-key should not block deleting the record in tokens. As the private-key is
               already gone, the keypair is not usable anymore. Dangling public-key need to be removed by a cleanup job. */
            // TODO: clean-up YCL-112
            log.error("Failed to delete public-key with alias: {}", alias, ex);
        }
    }

    /**
     * Delete a key by handle. The Util.deleteKey method takes a CaviumKey object, so we have to lookup the key handle
     * before deletion.
     *
     * @param label The key label in the HSM.
     */
    private void deleteKey(String label) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, DestroyFailedException {
        Key keyByLabel = getKeyByLabel(label);
        if (keyByLabel instanceof Destroyable keyToBeDeleted) {
            keyToBeDeleted.destroy();
        } else {
            String className = keyByLabel != null ? keyByLabel.getClass().toString() : "null";
            throw new DestroyFailedException("Key " + label + " " + className + " was not a destroyable key");
        }
    }

    @Override
    public void createKeyPair(UUID clientGroupId, KeypairType keypairType, UUID kid, KeyAlgorithm keyAlgorithm) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        String alias = keyAlias(clientGroupId, kid);
        switch (keyAlgorithm) {
            case RSA2048, RSA4096 -> createRsaKeyPair(keyAlgorithm, alias);
            default -> throw new IllegalArgumentException("Only RSA keys are supported at the moment.");
        }
    }

    @SneakyThrows(AddAttributeException.class)
    private void createRsaKeyPair(KeyAlgorithm keyAlgorithm, String alias) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        // Set attributes for RSA public key
        // See: https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-attributes_5.html#java-attributes_5
        KeyAttributesMap publicKeyAttrsMap = new KeyAttributesMapBuilder()
                .put(KeyAttribute.LABEL, alias + PUBLIC_TAG)
                .put(KeyAttribute.MODULUS_BITS, keyAlgorithm.getKeysize())
                .put(KeyAttribute.PUBLIC_EXPONENT, BigInteger.valueOf(65537).toByteArray())
                .build();

        // Set attributes for RSA private key
        // See: https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-attributes_5.html#java-attributes_5
        KeyAttributesMap privateKeyAttrsMap = new KeyAttributesMapBuilder()
                .put(KeyAttribute.LABEL, alias)
                .put(KeyAttribute.EXTRACTABLE, false)
                .put(KeyAttribute.TOKEN, true)
                .build();

        // Create KeyPairAttributesMap and use that to initialize the keyPair generator
        KeyPairAttributesMap keyPairSpec = new KeyPairAttributesMapBuilder()
                .withPublic(publicKeyAttrsMap)
                .withPrivate(privateKeyAttrsMap)
                .build();

        KeyPairGenerator keyPairGenerator = keyPairGeneratorSupplier.get();
        keyPairGenerator.initialize(keyPairSpec);
        keyPairGenerator.generateKeyPair();
    }

    @Override
    public void deleteKeyPair(UUID clientGroupId, UUID kid) throws KeyNotFoundException {
        String alias = keyAlias(clientGroupId, kid);
        deleteKeyByAlias(alias);
    }

    @Override
    public ProviderKey<PrivateKey> retrievePrivateKey(UUID clientGroupId, KeypairType keypairType, UUID kid) throws KeyNotFoundException {
        return getKeyFromHSM(clientGroupId, kid, "")
                .map(key -> (PrivateKey) key)
                .map(privateKey -> new ProviderKey<>(privateKey, CloudHsmProvider.PROVIDER_NAME))
                .orElseThrow(() -> new KeyNotFoundException(UNABLE_TO_RETRIEVE_KEY_PAIR_MSG));
    }

    @Override
    public ProviderKey<PublicKey> retrievePublicKey(UUID clientGroupId, KeypairType keypairType, UUID kid) throws KeyNotFoundException {
        return getKeyFromHSM(clientGroupId, kid, PUBLIC_TAG)
                .map(key -> (PublicKey) key)
                .map(publicKey -> new ProviderKey<>(publicKey, CloudHsmProvider.PROVIDER_NAME))
                .orElseThrow(() -> new KeyNotFoundException(UNABLE_TO_RETRIEVE_KEY_PAIR_MSG));
    }

    Key getKeyByLabel(String label) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return keystore.getKey(label, null);
    }

    @SuppressWarnings("deprecated")
    List<String> findAllKeyLabels() throws KeyStoreException {
        List<String> labels = new ArrayList<>();
        keystore.aliases().asIterator().forEachRemaining(labels::add);
        return labels;
    }

    private String keyAlias(UUID prefix, UUID kid) {
        return prefix + "_" + kid;
    }

    @FunctionalInterface
    interface KeyPairGeneratorSupplier {
        KeyPairGenerator get() throws NoSuchAlgorithmException, NoSuchProviderException;
    }

}
