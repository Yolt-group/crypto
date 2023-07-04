package com.yolt.crypto;

import com.yolt.securityutils.crypto.KeyPair;
import com.yolt.securityutils.crypto.PrivateKey;
import com.yolt.securityutils.crypto.PublicKey;
import com.yolt.securityutils.crypto.RSA;
import nl.ing.lovebird.secretspipeline.VaultKeys;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

@Configuration
public class TestConfiguration {

    @Bean
    @Primary
    public VaultKeys vaultKeys() {
        VaultKeys vaultKeys = new VaultKeys();
        KeyPair keyPair = RSA.Builder.generateKeys(2048);
        vaultKeys.addPrivate("key-import", PrivateKey.from(keyPair.getPrivateKey().getKey()));
        vaultKeys.addPublic("key-import-encryption", PublicKey.from(keyPair.getPublicKey().getKey()));
        return vaultKeys;
    }
}
