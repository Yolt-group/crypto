package com.yolt.crypto.signing;

import com.yolt.crypto.keymanagement.KeyManagementService;
import com.yolt.crypto.keymanagement.KeyNotFoundException;
import com.yolt.crypto.keymaterial.KeypairType;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import lombok.RequiredArgsConstructor;
import nl.ing.lovebird.clienttokens.AbstractClientToken;
import nl.ing.lovebird.clienttokens.ClientToken;
import nl.ing.lovebird.clienttokens.constants.ClientTokenConstants;
import nl.ing.lovebird.clienttokens.verification.ClientIdVerificationService;
import nl.ing.lovebird.clienttokens.verification.ClientTokenParser;
import nl.ing.lovebird.clienttokens.verification.exception.MissingHeaderException;
import nl.ing.lovebird.clienttokens.verification.exception.UnauthorizedClientTokenRequesterException;
import nl.ing.lovebird.logging.MDCContextCreator;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequiredArgsConstructor
@RequestMapping("/sign")
@Validated
public class SigningController {

    private static final List<String> RESTRICTED_TO = Arrays.asList("dev-portal", "yolt-assistance-portal", "assistance-portal-yts");

    private final KeyManagementService keyManagementService;
    private final ClientTokenParser parser;
    private final ClientIdVerificationService clientIdVerificationService = new ClientIdVerificationService();

    @ApiOperation(value = "Sign the payload")
    @ApiResponses(
            {
                    @ApiResponse(code = 200, message = "Successful")
            }
    )
    @PostMapping(produces = APPLICATION_JSON_VALUE)
    // TODO YCL-1060 - Remove possibility to sign with a client-token, once the connection between providers and tokens is removed.
    public ResponseEntity<SignatureDTO> sign(@Valid @RequestBody SignRequestDTO signRequestDTO,
                                             @RequestParam(required = false, defaultValue = "BASE64") Encoding encoding,
                                             @RequestHeader(ClientTokenConstants.CLIENT_TOKEN_HEADER_NAME) String clientTokenHeader,
                                             @RequestHeader(value = MDCContextCreator.CLIENT_ID_HEADER_NAME, required = false) String clientIdHeader)
            throws KeyNotFoundException, SigningException {
        /*
         * To verify a certificate has been created for a private-key, we create a
         * signature and validate this with the public-key from the certificate.
         * This is done for both TRANSPORT and SIGNING keypairTypes.
         * Normal sign operations are done with KeypairType SIGNING.
         */
        KeypairType keyType = signRequestDTO.getKeyType() == null ? KeypairType.SIGNING : signRequestDTO.getKeyType();

        if (clientTokenHeader == null) {
            throw new MissingHeaderException("client-token header required");
        }

        AbstractClientToken token = this.parser.parseClientToken(clientTokenHeader);
        String issuedFor = token.getIssuedForClaim();
        if (!RESTRICTED_TO.contains(issuedFor)) {
            String message = String.format("client-token with isf='%s' is not authorized, expected one of %s for endpoint /sign",
                    token.getIssuedForClaim(), RESTRICTED_TO);
            throw new UnauthorizedClientTokenRequesterException(message);
        }

        if (token instanceof ClientToken) {
            ClientToken clientToken = (ClientToken) token;
            if (clientIdHeader == null) {
                throw new IllegalArgumentException("Expected a client id when calling /sign with a client-token.");
            }
            this.clientIdVerificationService.verify(clientToken, UUID.fromString(clientIdHeader));
        }

        String signature = keyManagementService.sign(signRequestDTO.getPrivateKid(), keyType,
                signRequestDTO.getAlgorithm(), encoding, Base64.decode(signRequestDTO.getPayload()), token.getClientGroupIdClaim());
        return ResponseEntity.ok(new SignatureDTO(signature));
    }

}
