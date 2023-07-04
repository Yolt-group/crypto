package com.yolt.crypto.configuration;

import com.yolt.crypto.keymanagement.CSRGenerationException;
import com.yolt.crypto.keymanagement.KeyNotFoundException;
import com.yolt.crypto.signing.SigningException;
import lombok.RequiredArgsConstructor;
import nl.ing.lovebird.errorhandling.ErrorDTO;
import nl.ing.lovebird.errorhandling.ExceptionHandlingService;
import org.springframework.http.HttpStatus;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import javax.validation.ConstraintViolationException;

import static com.yolt.crypto.configuration.ErrorConstants.*;

@ControllerAdvice
@RequiredArgsConstructor
public class ExceptionHandlers {

    private final ExceptionHandlingService service;

    @ExceptionHandler
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ResponseBody
    protected ErrorDTO handle(CSRGenerationException ex) {
        return service.logAndConstruct(GENERATE_CSR_FAILED, ex);
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ResponseBody
    protected ErrorDTO handle(SigningException ex) {
        return service.logAndConstruct(SIGNING_FAILED, ex);
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ResponseBody
    protected ErrorDTO handle(IllegalArgumentException ex) {
        return service.logAndConstruct(INVALID_REQUEST_PARAMETERS, ex);
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ResponseBody
    protected ErrorDTO handle(KeyNotFoundException ex) {
        return service.logAndConstruct(NO_KEYPAIR, ex);
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ResponseBody
    protected ErrorDTO handle(HttpMediaTypeNotSupportedException ex) {
        return service.logAndConstruct(INVALID_CONTENT_TYPE, ex);
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ResponseBody
    public ErrorDTO handle(ConstraintViolationException ex) {
        return service.logAndConstruct(INVALID_REQUEST_PARAMETERS, ex);
    }
}
