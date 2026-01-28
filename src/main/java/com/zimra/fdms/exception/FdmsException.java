package com.zimra.fdms.exception;

/**
 * Base FDMS exception class
 * 
 * This is an unchecked exception (RuntimeException) to allow clean API design
 * while still providing meaningful error codes for FDMS-specific errors.
 */
public class FdmsException extends RuntimeException {
    private final String code;
    private final Integer statusCode;

    public FdmsException(String message) {
        this(message, null, null, null);
    }

    public FdmsException(String message, String code) {
        this(message, code, null, null);
    }

    public FdmsException(String message, String code, Integer statusCode) {
        this(message, code, statusCode, null);
    }

    public FdmsException(String message, String code, Throwable cause) {
        this(message, code, null, cause);
    }

    public FdmsException(String message, String code, Integer statusCode, Throwable cause) {
        super(message, cause);
        this.code = code;
        this.statusCode = statusCode;
    }

    public String getCode() {
        return code;
    }

    public Integer getStatusCode() {
        return statusCode;
    }
}
