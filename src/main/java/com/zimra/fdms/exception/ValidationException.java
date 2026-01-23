package com.zimra.fdms.exception;

/**
 * Validation exception class
 */
public class ValidationException extends FdmsException {
    private final String field;

    public ValidationException(String message) {
        this(message, null);
    }

    public ValidationException(String message, String field) {
        super(message, "VALIDATION_ERROR");
        this.field = field;
    }

    public String getField() {
        return field;
    }
}
