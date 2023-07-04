package com.yolt.crypto.keymaterial;

import lombok.Getter;

@Getter
public enum KeyAlgorithm {
    RSA2048("RSA", 2048),
    RSA4096("RSA", 4096);

    private final String algorithm;
    private final int keysize;

    KeyAlgorithm(String algorithm, int keysize) {
        this.algorithm = algorithm;
        this.keysize = keysize;
    }
}
