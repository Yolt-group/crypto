package com.yolt.crypto.keymaterial;

import lombok.Value;

@Value
public class ExistingKeyDTO {
    private final KeypairType type;
    private final String encryptedKey;
}
