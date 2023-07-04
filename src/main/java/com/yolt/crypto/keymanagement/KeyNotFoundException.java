package com.yolt.crypto.keymanagement;

public class KeyNotFoundException extends Exception {
    public KeyNotFoundException(String msg) {
        super(msg);
    }

    public KeyNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
