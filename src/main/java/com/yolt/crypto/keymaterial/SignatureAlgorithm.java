package com.yolt.crypto.keymaterial;

import lombok.Getter;

@Getter
public enum SignatureAlgorithm {
    SHA256_WITH_RSA("SHA256withRSA"),
    SHA384_WITH_RSA("SHA384withRSA"),
    SHA512_WITH_RSA("SHA512withRSA");

    private final String algorithm;

    SignatureAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

}
