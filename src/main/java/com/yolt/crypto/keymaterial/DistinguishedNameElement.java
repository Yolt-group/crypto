package com.yolt.crypto.keymaterial;

import lombok.AllArgsConstructor;
import lombok.Value;

@Value
@AllArgsConstructor
public class DistinguishedNameElement {
    private final String type;
    private final String value;
}
