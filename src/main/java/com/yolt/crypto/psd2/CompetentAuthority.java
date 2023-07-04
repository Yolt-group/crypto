package com.yolt.crypto.psd2;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * List of competent authorities based on country code.
 * Source: https://www.etsi.org/deliver/etsi_ts/119400_119499/119495/01.02.01_60/ts_119495v010201p.pdf
 */
@RequiredArgsConstructor
@Getter
public enum CompetentAuthority {
    AT("AT-FMA", "Austria Financial Market Authority"),
    BE("BE-NBB", "National Bank of Belgium"),
    BG("BG-BNB", "Bulgarian National Bank"),
    HR("HR-CNB", "Croatian National Bank"),
    CY("CY-CBC", "Central Bank of Cyprus"),
    CZ("CZ-CNB", "Czech National Bank"),
    DK("DK-DFSA", "Danish Financial Supervisory Authority"),
    EE("EE-FI", "Estonia Financial Supervisory Authority"),
    FI("FI-FINFSA", "Finnish Financial Supervisory Authority"),
    FR("FR-ACPR", "Prudential Supervisory and Resolution Authority"),
    DE("DE-BAFIN", "Federal Financial Supervisory Authority"),
    GR("GR-BOG", "Bank of Greece"),
    HU("HU-CBH", "Central Bank of Hungary"),
    IS("IS-FME", "Financial Supervisory Authority"),
    IE("IE-CBI", "Central Bank of Ireland"),
    IT("IT-BI", "Bank of Italy"),
    LI("LI-FMA", "Financial Market Authority Liechtenstein"),
    LV("LV-FCMC", "Financial and Capital Markets Commission"),
    LT("LT-BL", "Bank of Lithuania"),
    LU("LU-CSSF", "Commission for the Supervision of Financial Sector"),
    NO("NO-FSA", "The Financial Supervisory Authority of Norway"),
    MT("MT-MFSA", "Malta Financial Services Authority"),
    NL("NL-DNB", "The Netherlands Bank"),
    PL("PL-PFSA", "Polish Financial Supervision Authority"),
    PT("PT-BP", "Bank of Portugal"),
    RO("RO-NBR", "National bank of Romania"),
    SK("SK-NBS", "National Bank of Slovakia"),
    SI("SI-BS", "Bank of Slovenia"),
    ES("ES-BE", "Bank of Spain"),
    SE("SE-FINA", "Swedish Financial Supervision Authority"),
    GB("GB-FCA", "Financial Conduct Authority");

    private final String id;
    private final String name;
}
