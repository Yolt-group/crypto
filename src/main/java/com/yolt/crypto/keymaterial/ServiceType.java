package com.yolt.crypto.keymaterial;

import com.yolt.crypto.psd2.PSD2_OID;
import lombok.AllArgsConstructor;
import lombok.Getter;

import static com.yolt.crypto.psd2.PSD2_OID.*;

@AllArgsConstructor
@Getter
public enum ServiceType {
    AS(PSP_AS),
    PIS(PSP_PI),
    AIS(PSP_AI),
    IC(PSP_IC);

    private final PSD2_OID psd2OID;
}