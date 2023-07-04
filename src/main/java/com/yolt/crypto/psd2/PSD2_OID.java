package com.yolt.crypto.psd2;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * List of PSD2 related OIDs, useful for creating the qcStatement extension in the csr.
 * Source: https://github.com/Crypt32/Asn1Editor.WPF/blob/master/Asn1Editor/OID.txt
 */
@RequiredArgsConstructor
@Getter
public enum PSD2_OID {
    PSP_AS("0.4.0.19495.1.1"),
    PSP_PI("0.4.0.19495.1.2"),
    PSP_AI("0.4.0.19495.1.3"),
    PSP_IC("0.4.0.19495.1.4"),
    PSD_2_QCSTATEMENT("0.4.0.19495.2");

    private final String oid;
}
