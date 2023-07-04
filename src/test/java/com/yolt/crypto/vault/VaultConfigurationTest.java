package com.yolt.crypto.vault;

import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.*;

public class VaultConfigurationTest {

    private static final VaultConfiguration EXAMPLE_VAULT_CONFIG = new VaultConfiguration(
            URI.create("https://vault.io"),
            true,
            "",
            "",
            "my-service-acc-token.txt",
            "ycs",
            "team4",
            "crypto",
            24
    );

    @Test
    public void fieldsAreCreatedCorrectly() {
        assertThat(EXAMPLE_VAULT_CONFIG.getAuthenticationPath(), is("team4/k8s/eks/pods/ycs"));
        assertThat(EXAMPLE_VAULT_CONFIG.getAuthenticationRole(), is("crypto"));
    }

    @Test
    public void copyWithDifferentAddressWorksCorrectly() {
        URI newAddress = URI.create("http://vault2.io");
        URI originalAddress = EXAMPLE_VAULT_CONFIG.getAddress();

        VaultConfiguration newVaultConfig = EXAMPLE_VAULT_CONFIG.copyWithDifferentAddress(newAddress);

        assertNotSame(newVaultConfig, EXAMPLE_VAULT_CONFIG);
        assertNotEquals(newVaultConfig, EXAMPLE_VAULT_CONFIG);
        assertThat(newVaultConfig.getAddress(), is(newAddress));

        VaultConfiguration originalVaultConfiguration = newVaultConfig.copyWithDifferentAddress(originalAddress);

        assertNotSame(originalVaultConfiguration, EXAMPLE_VAULT_CONFIG);
        assertEquals(originalVaultConfiguration, EXAMPLE_VAULT_CONFIG);
    }

}
