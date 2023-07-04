package com.yolt.crypto.keymanagement;

import com.yolt.crypto.keymaterial.KeyAlgorithm;
import com.yolt.crypto.keymaterial.KeypairType;
import com.yolt.crypto.keymaterial.ProviderKey;
import nl.ing.lovebird.clienttokens.ClientToken;

import java.security.*;
import java.util.UUID;

public interface KeyService {
    void createKeyPair(UUID clientGroupId, KeypairType keypairType, UUID kid, KeyAlgorithm keyAlgorithm) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException;
    void deleteKeyPair(UUID clientGroupId, UUID kid) throws KeyNotFoundException;

    ProviderKey<PrivateKey> retrievePrivateKey(UUID clientGroupId, KeypairType keypairType, UUID kid) throws KeyNotFoundException;
    ProviderKey<PublicKey> retrievePublicKey(UUID clientGroupId, KeypairType keypairType, UUID kid) throws KeyNotFoundException;

}
