package com.yolt.crypto.keymanagement;

import com.yolt.crypto.keymaterial.DistinguishedNameElement;
import com.yolt.crypto.keymaterial.KeypairType;
import com.yolt.crypto.keymaterial.ServiceType;
import com.yolt.crypto.psd2.CompetentAuthority;
import lombok.experimental.UtilityClass;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;

import java.util.List;

import static com.yolt.crypto.psd2.PSD2_OID.PSD_2_QCSTATEMENT;
import static org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers.id_etsi_qcs_QcType;

/**
 * Create the ASN1 typed information for the qcStatements extension, described by:
 * https://www.etsi.org/deliver/etsi_ts/119400_119499/119495/01.02.01_60/ts_119495v010201p.pdf
 * Used the following golang application as reference implementation:
 * https://github.com/creditkudos/eidas
 */
@UtilityClass
class EIDASQCStatementUtils {

    private static final String COUNTRY_CODE_DN = "C";

    /**
     * The format of the qcStatement should be as described in the etsi document in the class javadoc.
     * It could be something like this:
     * base64 encoded: MGUwEwYGBACORgEGMAkGBwQAjkYBBgMwTgYGBACBmCcCMEQwJDAiBgcEAIGYJwEDDAZQU1BfQUkGBwQAgZgnAQIMBlBTUF9QSQwUVGhlIE5ldGhlcmxhbmRzIEJhbmsMBk5MLUROQg==
     * It can be tested here: https://lapo.it/asn1js/#MGUwEwYGBACORgEGMAkGBwQAjkYBBgMwTgYGBACBmCcCMEQwJDAiBgcEAIGYJwEDDAZQU1BfQUkGBwQAgZgnAQIMBlBTUF9QSQwUVGhlIE5ldGhlcmxhbmRzIEJhbmsMBk5MLUROQg
     */
    static ASN1Encodable getQCStatementInfo(KeypairType keypairType, List<ServiceType> serviceTypes, List<DistinguishedNameElement> distinguishedNames) {
        String countryCode = resolveCountryCode(distinguishedNames);
        CompetentAuthority competentAuthority = getCompetentAuthorityByCountryCode(countryCode);
        ASN1Encodable[] pspRoles = getPSPRoles(serviceTypes);
        ASN1ObjectIdentifier qcTypeOID = getQCType(keypairType);

        return createASN1Sequence(
                createASN1Sequence(
                        id_etsi_qcs_QcType,
                        createASN1Sequence(
                                qcTypeOID
                        )
                ),
                createASN1Sequence(
                        new ASN1ObjectIdentifier(PSD_2_QCSTATEMENT.getOid()),
                        createASN1Sequence(
                                createASN1Sequence(
                                        pspRoles
                                ),
                                new DERUTF8String(competentAuthority.getName()),
                                new DERUTF8String(competentAuthority.getId())
                        )
                )
        );
    }

    private static CompetentAuthority getCompetentAuthorityByCountryCode(String countryCode) {
        try {
            return CompetentAuthority.valueOf(countryCode);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Cannot generate eIDAS certificate for country: '" + countryCode + "'", e);
        }
    }

    private static ASN1ObjectIdentifier getQCType(KeypairType keypairType) {
        if (keypairType == KeypairType.SIGNING) {
            return ETSIQCObjectIdentifiers.id_etsi_qct_eseal;
        } else if (keypairType == KeypairType.TRANSPORT) {
            return ETSIQCObjectIdentifiers.id_etsi_qct_web;
        }

        throw new IllegalStateException("KeypairType: " + keypairType + " not supported");
    }

    private static ASN1Encodable[] getPSPRoles(List<ServiceType> serviceTypes) {
        if (serviceTypes.isEmpty()) {
            throw new IllegalArgumentException("Expected at least one serviceType");
        }

        ASN1Encodable[] pspRoles = new ASN1Encodable[serviceTypes.size()];
        for (int i = 0; i < serviceTypes.size(); i++) {
            pspRoles[i] = createASN1Sequence(new ASN1ObjectIdentifier(serviceTypes.get(i).getPsd2OID().getOid()),
                                             new DERUTF8String(serviceTypes.get(i).getPsd2OID().name()));
        }
        return pspRoles;
    }

    private static String resolveCountryCode(List<DistinguishedNameElement> distinguishedNames) {
        return distinguishedNames.stream()
                .filter(dn -> COUNTRY_CODE_DN.equals(dn.getType()))
                .map(DistinguishedNameElement::getValue)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Required Country Code distinguished name entry (C) not found"));
    }

    private static DERSequence createASN1Sequence(ASN1Encodable... encodables) {
        return new DERSequence(encodables);
    }
}
