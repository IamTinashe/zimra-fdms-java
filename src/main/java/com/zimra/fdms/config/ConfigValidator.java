package com.zimra.fdms.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * FDMS Configuration Validator
 * Provides comprehensive validation for FDMS configuration
 */
public class ConfigValidator {
    
    private static final Pattern NUMERIC_PATTERN = Pattern.compile("^\\d+$");
    private static final Pattern URL_PATTERN = Pattern.compile("^https?://.*$");
    private static final Set<String> VALID_CERT_EXTENSIONS = Set.of(".pem", ".crt", ".cer", ".der");
    private static final Set<String> VALID_KEY_EXTENSIONS = Set.of(".pem", ".key", ".der");
    
    /**
     * Validation error detail
     */
    public static class ValidationError {
        private final String field;
        private final String message;
        private final Object value;
        
        public ValidationError(String field, String message) {
            this(field, message, null);
        }
        
        public ValidationError(String field, String message, Object value) {
            this.field = field;
            this.message = message;
            this.value = value;
        }
        
        public String getField() { return field; }
        public String getMessage() { return message; }
        public Object getValue() { return value; }
        
        @Override
        public String toString() {
            return field + ": " + message;
        }
    }
    
    /**
     * Validation result
     */
    public static class ValidationResult {
        private final boolean valid;
        private final List<ValidationError> errors;
        
        public ValidationResult(boolean valid, List<ValidationError> errors) {
            this.valid = valid;
            this.errors = Collections.unmodifiableList(errors);
        }
        
        public boolean isValid() { return valid; }
        public List<ValidationError> getErrors() { return errors; }
    }
    
    /**
     * Validate the configuration
     * 
     * @param config the configuration to validate
     * @return the validation result
     */
    public ValidationResult validate(FdmsConfig config) {
        List<ValidationError> errors = new ArrayList<>();
        
        // Validate required fields
        validateRequired(config, errors);
        
        // Validate field formats
        validateFormats(config, errors);
        
        // Validate numeric ranges
        validateRanges(config, errors);
        
        // Validate certificate configuration
        validateCertificateConfig(config, errors);
        
        return new ValidationResult(errors.isEmpty(), errors);
    }
    
    /**
     * Validate and throw exception if invalid
     * 
     * @param config the configuration to validate
     * @throws ConfigValidationException if validation fails
     */
    public void validateOrThrow(FdmsConfig config) {
        ValidationResult result = validate(config);
        if (!result.isValid()) {
            StringBuilder sb = new StringBuilder("Configuration validation failed: ");
            List<ValidationError> errors = result.getErrors();
            for (int i = 0; i < errors.size(); i++) {
                if (i > 0) sb.append("; ");
                sb.append(errors.get(i));
            }
            throw new ConfigValidationException(sb.toString());
        }
    }
    
    private void validateRequired(FdmsConfig config, List<ValidationError> errors) {
        if (isNullOrEmpty(config.getDeviceId())) {
            errors.add(new ValidationError("deviceId", "deviceId is required"));
        }
        if (isNullOrEmpty(config.getDeviceSerialNo())) {
            errors.add(new ValidationError("deviceSerialNo", "deviceSerialNo is required"));
        }
        if (isNullOrEmpty(config.getActivationKey())) {
            errors.add(new ValidationError("activationKey", "activationKey is required"));
        }
        if (isNullOrEmpty(config.getDeviceModelName())) {
            errors.add(new ValidationError("deviceModelName", "deviceModelName is required"));
        }
        if (isNullOrEmpty(config.getDeviceModelVersion())) {
            errors.add(new ValidationError("deviceModelVersion", "deviceModelVersion is required"));
        }
        if (isNullOrEmpty(config.getCertificate())) {
            errors.add(new ValidationError("certificate", "certificate is required"));
        }
        if (isNullOrEmpty(config.getPrivateKey())) {
            errors.add(new ValidationError("privateKey", "privateKey is required"));
        }
    }
    
    private void validateFormats(FdmsConfig config, List<ValidationError> errors) {
        // Device ID should be numeric
        String deviceId = config.getDeviceId();
        if (deviceId != null && !deviceId.isEmpty() && !NUMERIC_PATTERN.matcher(deviceId).matches()) {
            errors.add(new ValidationError("deviceId", "deviceId must be a numeric value", deviceId));
        }
        
        // Validate URL format if base_url is provided
        String baseUrl = config.getBaseUrl();
        if (baseUrl != null && !baseUrl.isEmpty() && !URL_PATTERN.matcher(baseUrl).matches()) {
            errors.add(new ValidationError("baseUrl", "baseUrl must be a valid HTTP/HTTPS URL", baseUrl));
        }
    }
    
    private void validateRanges(FdmsConfig config, List<ValidationError> errors) {
        int timeout = config.getTimeout();
        if (timeout <= 0) {
            errors.add(new ValidationError("timeout", "timeout must be a positive number (milliseconds)", timeout));
        } else if (timeout < FdmsConfigConstants.MIN_TIMEOUT) {
            errors.add(new ValidationError("timeout", 
                "timeout should be at least " + FdmsConfigConstants.MIN_TIMEOUT + "ms for reliable operation", timeout));
        } else if (timeout > FdmsConfigConstants.MAX_TIMEOUT) {
            errors.add(new ValidationError("timeout", 
                "timeout should not exceed " + FdmsConfigConstants.MAX_TIMEOUT + "ms (5 minutes)", timeout));
        }
        
        int retryAttempts = config.getRetryAttempts();
        if (retryAttempts < FdmsConfigConstants.MIN_RETRY_ATTEMPTS) {
            errors.add(new ValidationError("retryAttempts", "retryAttempts must be a non-negative integer", retryAttempts));
        } else if (retryAttempts > FdmsConfigConstants.MAX_RETRY_ATTEMPTS) {
            errors.add(new ValidationError("retryAttempts", 
                "retryAttempts should not exceed " + FdmsConfigConstants.MAX_RETRY_ATTEMPTS, retryAttempts));
        }
        
        int retryDelay = config.getRetryDelay();
        if (retryDelay <= 0) {
            errors.add(new ValidationError("retryDelay", "retryDelay must be a positive number (milliseconds)", retryDelay));
        } else if (retryDelay > FdmsConfigConstants.MAX_RETRY_DELAY) {
            errors.add(new ValidationError("retryDelay", 
                "retryDelay should not exceed " + FdmsConfigConstants.MAX_RETRY_DELAY + "ms (1 minute)", retryDelay));
        }
    }
    
    private void validateCertificateConfig(FdmsConfig config, List<ValidationError> errors) {
        // Validate certificate format
        String certificate = config.getCertificate();
        if (certificate != null && !certificate.isEmpty()) {
            if (!isPemContent(certificate) && !isValidCertPath(certificate) && certificate.length() < 100) {
                errors.add(new ValidationError("certificate", 
                    "certificate must be a valid file path (.pem, .crt, .cer, .der) or PEM-encoded content",
                    truncate(certificate, 50)));
            }
        }
        
        // Validate private key format
        String privateKey = config.getPrivateKey();
        if (privateKey != null && !privateKey.isEmpty()) {
            if (!isPemContent(privateKey) && !isValidKeyPath(privateKey) && privateKey.length() < 100) {
                errors.add(new ValidationError("privateKey", 
                    "privateKey must be a valid file path (.pem, .key, .der) or PEM-encoded content",
                    "[REDACTED]"));
            }
        }
    }
    
    private boolean isNullOrEmpty(String value) {
        return value == null || value.trim().isEmpty();
    }
    
    private boolean isPemContent(String content) {
        return content.contains("-----BEGIN");
    }
    
    private boolean isValidCertPath(String path) {
        String lowerPath = path.toLowerCase();
        return VALID_CERT_EXTENSIONS.stream().anyMatch(lowerPath::endsWith);
    }
    
    private boolean isValidKeyPath(String path) {
        String lowerPath = path.toLowerCase();
        return VALID_KEY_EXTENSIONS.stream().anyMatch(lowerPath::endsWith);
    }
    
    private String truncate(String value, int maxLength) {
        if (value == null) return null;
        if (value.length() <= maxLength) return value;
        return value.substring(0, maxLength) + "...";
    }
}
