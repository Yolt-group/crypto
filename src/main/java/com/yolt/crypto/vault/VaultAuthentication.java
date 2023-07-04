package com.yolt.crypto.vault;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomUtils;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.Assert;
import org.springframework.vault.authentication.*;
import org.springframework.vault.authentication.event.AfterLoginTokenRenewedEvent;
import org.springframework.vault.authentication.event.BeforeLoginTokenRenewedEvent;
import org.springframework.vault.authentication.event.LoginTokenRenewalFailedEvent;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.config.AbstractVaultConfiguration;

import java.util.concurrent.TimeUnit;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class VaultAuthentication extends AbstractVaultConfiguration {

    private final VaultConfiguration config;
    private final ApplicationContext applicationContext;

    @Override
    public VaultEndpoint vaultEndpoint() {
        return VaultEndpoint.from(config.getAddress());
    }

    @Override
    public ClientAuthentication clientAuthentication() {

        KubernetesAuthenticationOptions options = KubernetesAuthenticationOptions.builder()
                .role(config.getAuthenticationRole())
                .path(config.getAuthenticationPath())
                .jwtSupplier(new KubernetesServiceAccountTokenFile(config.getServiceAccountTokenFile()))
                .build();

        return new KubernetesAuthentication(options, restOperations());
    }

    @Bean
    @Override
    public SessionManager sessionManager() {
        ClientAuthentication clientAuthentication = clientAuthentication();
        Assert.notNull(clientAuthentication, "ClientAuthentication must not be null");

        // We instruct the session manager to try to refresh the token between 1 and N hours before it expires.
        // This is to introduce some randomness in case all services fail to get the token renewal so they don't
        // restart altogether causing downtime. The default token expiry time is 3 days, the default for N is 24.
        int beforeExpireTimeAmount = RandomUtils.nextInt(1, config.getMaxRefreshBeforeTokenExpiryHours());
        log.info("The service will renew the vault token {} hours before it expires", beforeExpireTimeAmount);

        LifecycleAwareSessionManagerSupport.FixedTimeoutRefreshTrigger refreshTrigger =
                new LifecycleAwareSessionManagerSupport.FixedTimeoutRefreshTrigger(beforeExpireTimeAmount, TimeUnit.HOURS);

        LifecycleAwareSessionManager lifecycleAwareSessionManager =
                new LifecycleAwareSessionManager(clientAuthentication, getVaultThreadPoolTaskScheduler(), restOperations(), refreshTrigger);

        // If the token can not be renewed, we (try to) shutdown gracefully and just hope the next restart will fix the problem.
        // Ideally we should keep retrying until the token expires but this is good enough to start with.
        lifecycleAwareSessionManager.addErrorListener(authenticationErrorEvent -> {
            if (authenticationErrorEvent instanceof LoginTokenRenewalFailedEvent) {
                log.error("Error while renewing the Vault session token. Shutting down the service...",
                        authenticationErrorEvent.getException());
                if (applicationContext != null) {
                    SpringApplication.exit(applicationContext, () -> 1);
                } else {
                    log.error("This Vault Authentication instance was constructed without a Spring application context. " +
                            "Will terminate the application abruptly.");
                    System.exit(1);
                }
            } else {
                log.error(String.format("Unhandled vault authentication error %s", authenticationErrorEvent.getClass().getSimpleName()), authenticationErrorEvent.getException()); // NOSHERIFF
                System.exit(1);
            }
        });

        // This is just for logging purposes, to get some extra info when the pods try to renew Vault tokens.
        lifecycleAwareSessionManager.addAuthenticationListener(authenticationEvent -> {
            if (authenticationEvent instanceof BeforeLoginTokenRenewedEvent) {
                log.info("Service will renew now the Vault session token");
            } else if (authenticationEvent instanceof AfterLoginTokenRenewedEvent) {
                log.info("Vault session token successfully renewed.");
            }
        });

        return lifecycleAwareSessionManager;
    }
}
