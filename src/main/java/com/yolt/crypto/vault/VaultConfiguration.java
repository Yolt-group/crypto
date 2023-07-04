package com.yolt.crypto.vault;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import java.net.URI;

@Getter
@ToString
@EqualsAndHashCode
@Slf4j
@Configuration
public class VaultConfiguration {

    private final URI address;
    private final boolean enabled;
    private final String namespace;
    private final String authenticationPath;
    private final String authenticationRole;
    private final String serviceAccountTokenFile;
    private final int maxRefreshBeforeTokenExpiryHours;

    public VaultConfiguration(@Value("${yolt.vault.address}") final URI address,   //NOSONAR
                              @Value("${yolt.vault.enabled:false}") final boolean enabled,
                              @Value("${yolt.vault.auth.path:}") final String authenticationPath,
                              @Value("${yolt.vault.auth.role:}") final String authenticationRole,
                              @Value("${yolt.vault.auth.service-account-token-file:/var/run/secrets/kubernetes.io/serviceaccount/token}") final String serviceAccountTokenFile,
                              @Value("${namespace}") final String namespace,
                              @Value("${environment}") final String environment,
                              @Value("${spring.application.name}") final String applicationName,
                              @Value("${yolt.vault.auth.max-refresh-before-token-expiry-hours:24}") final int maxRefreshBeforeTokenExpiryHours
    ) {
        this.address = address;
        this.enabled = enabled;
        this.namespace = namespace;
        // Example: team5/k8s/eks/pods/<namespace>
        this.authenticationPath = !authenticationPath.isEmpty() ?
                authenticationPath :
                String.format("%s/k8s/eks/pods/%s", environment, namespace);
        this.authenticationRole = !authenticationRole.isEmpty() ?
                authenticationRole : applicationName;
        this.serviceAccountTokenFile = serviceAccountTokenFile;
        if (maxRefreshBeforeTokenExpiryHours <= 1) {
            throw new IllegalArgumentException("maxRefreshBeforeTokenExpiryHours must be > 1");
        }
        this.maxRefreshBeforeTokenExpiryHours = maxRefreshBeforeTokenExpiryHours;

        log.info("Set vault configuration to: {}", this); //NOSHERIFF
    }

    /**
     * This private constructor is used for making internal copies of the object.
     */
    private VaultConfiguration(URI address, boolean enabled, String namespace, String authenticationPath, String authenticationRole, String serviceAccountTokenFile, int maxRefreshBeforeTokenExpiryHours) {
        this.address = address;
        this.enabled = enabled;
        this.namespace = namespace;
        this.authenticationPath = authenticationPath;
        this.authenticationRole = authenticationRole;
        this.serviceAccountTokenFile = serviceAccountTokenFile;
        this.maxRefreshBeforeTokenExpiryHours = maxRefreshBeforeTokenExpiryHours;

        log.info("Set vault configuration to: {}", this); //NOSHERIFF
    }

    /**
     * This method is used for creating copies of VaultConfiguration with only the address changed.
     * It is used in crypto, because it writes (in a transaction fashion) to all vault instances, since we do not have Vault Enterprise for synchronization.
     * @param newAddress The Vault address
     * @return A copy of the original VaultConfiguration with the other address.
     */
    public VaultConfiguration copyWithDifferentAddress(final URI newAddress) {
        return new VaultConfiguration(newAddress, enabled, namespace, authenticationPath, authenticationRole, serviceAccountTokenFile, maxRefreshBeforeTokenExpiryHours);
    }
}
