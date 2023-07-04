package com.yolt.crypto.cloudhsm;

import lombok.Value;

@Value
public class HSMCredentials {
    private String partition;
    private String username;
    private String password;
}
