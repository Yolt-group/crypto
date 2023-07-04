package com.yolt.crypto.signing;

import com.yolt.crypto.keymaterial.KeypairType;
import com.yolt.crypto.keymaterial.SignatureAlgorithm;
import lombok.Value;
import org.springframework.lang.Nullable;

import java.util.UUID;

@Value
public class SignRequestDTO {
    private final UUID privateKid;
    private final SignatureAlgorithm algorithm;
    private final String payload;
    /**
     * To verify a certificate has been created for a private-key, we create a
     * signature and validate this with the public-key from the certificate.
     * This is done for both TRANSPORT and SIGNING keypairTypes.
     */
    @Nullable
    private final KeypairType keyType;
}