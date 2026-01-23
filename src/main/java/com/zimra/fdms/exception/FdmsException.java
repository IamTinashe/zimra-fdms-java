package com.zimra.fdms.exception;

/**
 * Base FDMS exception class
 */
public class FdmsException extends Exception {
    private final String code;
    private final Integer statusCode;

    public FdmsException(String message) {
        this(message, null, null);
    }

    public FdmsException(String message, String code) {
        this(message, code, null);
    }

    public FdmsException(String message, String code, Integer statusCode) {
        super(message);
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
