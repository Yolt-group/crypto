package com.yolt.crypto.configuration;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.security.Security;
import java.util.ArrayList;
import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "yolt.crypto")
@RequiredArgsConstructor
@Slf4j
@Getter
public class CryptoConfiguration {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Value("${environment}")
    private String environment;

    private List<String> deletableKeyEnvironments = new ArrayList<>();
}
