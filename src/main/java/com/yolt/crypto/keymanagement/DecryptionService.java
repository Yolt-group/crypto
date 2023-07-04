package com.yolt.crypto.keymanagement;

import com.yolt.crypto.keymaterial.KeypairType;
import nl.ing.lovebird.clienttokens.ClientToken;
import nl.ing.lovebird.logging.AuditLogger;
import nl.ing.lovebird.secretspipeline.VaultKeys;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.lang.JoseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.security.Key;

@Service
@ConditionalOnProperty(prefix = "yolt.crypto.import", name = "enabled")
class DecryptionService {

    private Key privateKey;

    @Autowired
    DecryptionService(VaultKeys vaultKeys) {
        this(vaultKeys.getPrivateKey("key-import").getKey());
    }

    DecryptionService(Key privateKey) {
        this.privateKey = privateKey;
    }

    String decrypt(ClientToken clientToken, String compactSerialization, KeypairType keyType) throws KeyPairImportException {
        try {
            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setContentEncryptionAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST,
                    ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512));
            jwe.setKey(privateKey);
            jwe.setCompactSerialization(compactSerialization);
            return jwe.getPayload();
        } catch (JoseException ex) {
            String message = String.format("Failed to decrypt key for clientGroupId: %s, keyType: %s", clientToken.getClientGroupIdClaim(), keyType);
            AuditLogger.logError(message, null, ex);

            throw new KeyPairImportException(message);
        }
    }
}
