package com.yolt.crypto.configuration;

import nl.ing.lovebird.errorhandling.ErrorInfo;

public enum ErrorConstants implements ErrorInfo {

    CLIENT_UNKNOWN("001", "Unknown client identifier"),
    GENERATE_CSR_FAILED("002", "Server error while generating csr"),
    INVALID_CONTENT_TYPE("003", "Unsupported Content-Type"),
    INVALID_REQUEST_PARAMETERS("004", "Invalid request parameters"),
    NO_KEYPAIR("005", "No keypair found"),
    SIGNING_FAILED("006", "Server error while signing");

    private final String code;
    private final String message;

    ErrorConstants(String code, String message) {
        this.code = code;
        this.message = message;
    }

    @Override
    public String getCode() {
        return code;
    }

    @Override
    public String getMessage() {
        return message;
    }
}
