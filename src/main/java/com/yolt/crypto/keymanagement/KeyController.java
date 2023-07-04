package com.yolt.crypto.keymanagement;

import com.yolt.crypto.keymaterial.*;
import lombok.RequiredArgsConstructor;
import nl.ing.lovebird.clienttokens.ClientGroupToken;
import nl.ing.lovebird.clienttokens.annotations.VerifiedClientToken;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.UUID;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequiredArgsConstructor
@RequestMapping("/key")
@Validated
public class KeyController {

    private static final String DEV_PORTAL = "dev-portal";
    private static final String ASSISTANCE_PORTAL_YTS = "assistance-portal-yts";

    private final KeyManagementService keyManagementService;
    private final CSRManagementService csrManagementService;

    @PostMapping(produces = APPLICATION_JSON_VALUE)
    public ResponseEntity<KidDTO> generateKey(@Valid @RequestBody KeyRequirementsDTO keyRequirements,
                                              @VerifiedClientToken(restrictedTo = {DEV_PORTAL, ASSISTANCE_PORTAL_YTS} ) ClientGroupToken clientGroupToken) throws KeyPairCreationException {
        UUID kid = keyManagementService.createKey(clientGroupToken, keyRequirements.getKeyAlgorithm(), keyRequirements.getType());
        return ResponseEntity.ok(new KidDTO(kid));
    }

    @DeleteMapping(value = "/{kid}", produces = APPLICATION_JSON_VALUE)
    public void deleteKey(@PathVariable UUID kid,
                          @VerifiedClientToken(restrictedTo = {DEV_PORTAL, ASSISTANCE_PORTAL_YTS}) ClientGroupToken clientGroupToken) throws KeyPairDeletionException {
        keyManagementService.deleteKey(clientGroupToken, kid);
    }

    @PostMapping(value = "/{kid}/csr", produces = APPLICATION_JSON_VALUE)
    public ResponseEntity<CSRDTO> generateCSR(@PathVariable UUID kid,
                                              @Valid @RequestBody CSRRequirementsDTO csrRequirements,
                                              @VerifiedClientToken(restrictedTo = {DEV_PORTAL, ASSISTANCE_PORTAL_YTS}) ClientGroupToken clientGroupToken) throws CSRGenerationException, KeyNotFoundException {
        String csr = csrManagementService.generateCSR(clientGroupToken, kid, csrRequirements);
        return ResponseEntity.ok(new CSRDTO(csr));
    }
}
