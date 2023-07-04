package com.yolt.crypto.vault;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * This configuration is meant as a convenience service for getting the base path to the key value store.
 * It will abstract away the templating of variables for the vault paths.
 */
@Configuration
public class VaultKeyValueConfiguration {

    private final String secretsBasePath;
    private final String ownKeyStoreName;

    public VaultKeyValueConfiguration(@Value("${namespace}") final String namespace,
                                      @Value("${environment}") final String environment,
                                      @Value("${spring.application.name}") final String applicationName) {
        this.secretsBasePath = String.format("%s/k8s/pods/%s/kv", environment, namespace);
        this.ownKeyStoreName = applicationName;
    }

    /**
     * @return The secrets path for the keystore with the same name as the application.
     */
    public String getSecretsBasePath() {
        return secretsBasePath + "/" + ownKeyStoreName;
    }

    /**
     * @return The secrets path for the keystore with another name. Useful for example for providers reading from the crypto keystore.
     */
    public String getSecretsBasePath(final String keystoreName) {
        return secretsBasePath + "/" + keystoreName;
    }
}
