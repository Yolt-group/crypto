package com.yolt.crypto.keymaterial;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CSRRequirementsDTO {
    private KeypairType type;
    private List<ServiceType> serviceTypes;
    private SignatureAlgorithm signatureAlgorithm;
    private List<DistinguishedNameElement> distinguishedNames;
    private boolean eidasCertificate;
    private Set<String> subjectAlternativeNames;
}
