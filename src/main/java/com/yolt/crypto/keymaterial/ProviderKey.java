package com.yolt.crypto.keymaterial;

import lombok.Getter;

import javax.validation.constraints.NotNull;
import java.security.Key;

@Getter
public class ProviderKey<T extends Key> {
    @NotNull
    private final T key;
    @NotNull
    private final String provider;

    public ProviderKey(T key, String provider) {
        this.key = key;
        this.provider = provider;
    }
}
