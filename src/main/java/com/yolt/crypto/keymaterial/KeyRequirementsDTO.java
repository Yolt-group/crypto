package com.yolt.crypto.keymaterial;

import lombok.Value;

@Value
public class KeyRequirementsDTO {
    private final KeypairType type;
    private final KeyAlgorithm keyAlgorithm;
}
