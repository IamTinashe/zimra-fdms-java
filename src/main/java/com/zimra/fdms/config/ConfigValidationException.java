package com.zimra.fdms.config;

import com.zimra.fdms.exception.ValidationException;

/**
 * Configuration validation exception
 */
public class ConfigValidationException extends ValidationException {
    
    private static final String CODE = "CONFIG_VALIDATION_ERROR";
    
    public ConfigValidationException(String message) {
        super(message, CODE);
    }
    
    public ConfigValidationException(String message, String field) {
        super(message, CODE, field);
    }
}
