package com.zimra.fdms.exception;

/**
 * Validation exception class
 */
public class ValidationException extends FdmsException {
    private final String field;

    public ValidationException(String message) {
        this(message, "VALIDATION_ERROR", null);
    }

    public ValidationException(String message, String field) {
        this(message, "VALIDATION_ERROR", field);
    }
    
    public ValidationException(String message, String code, String field) {
        super(message, code);
        this.field = field;
    }

    public String getField() {
        return field;
    }
}
