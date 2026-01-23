package com.zimra.fdms.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for ConfigValidator
 */
class ConfigValidatorTest {
    
    private ConfigValidator validator;
    
    @BeforeEach
    void setUp() {
        validator = new ConfigValidator();
    }
    
    private FdmsConfig.Builder validConfigBuilder() {
        return FdmsConfig.builder()
            .deviceId("12345")
            .deviceSerialNo("SN-001")
            .activationKey("test-key")
            .deviceModelName("TestModel")
            .deviceModelVersion("1.0.0")
            .certificate("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
            .privateKey("-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----");
    }
    
    @Nested
    @DisplayName("validate")
    class Validate {
        
        @Test
        @DisplayName("should pass with valid configuration")
        void shouldPassWithValidConfig() {
            FdmsConfig config = validConfigBuilder().buildUnchecked();
            
            ConfigValidator.ValidationResult result = validator.validate(config);
            
            assertTrue(result.isValid());
            assertTrue(result.getErrors().isEmpty());
        }
        
        @Test
        @DisplayName("should fail when deviceId is missing")
        void shouldFailWhenDeviceIdMissing() {
            FdmsConfig config = FdmsConfig.builder()
                .deviceSerialNo("SN-001")
                .activationKey("test-key")
                .deviceModelName("TestModel")
                .deviceModelVersion("1.0.0")
                .certificate("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
                .privateKey("-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----")
                .buildUnchecked();
            
            ConfigValidator.ValidationResult result = validator.validate(config);
            
            assertFalse(result.isValid());
            assertTrue(result.getErrors().stream()
                .anyMatch(e -> e.getField().equals("deviceId")));
        }
        
        @Test
        @DisplayName("should fail when deviceId is not numeric")
        void shouldFailWhenDeviceIdNotNumeric() {
            FdmsConfig config = validConfigBuilder()
                .deviceId("abc123")
                .buildUnchecked();
            
            ConfigValidator.ValidationResult result = validator.validate(config);
            
            assertFalse(result.isValid());
            assertTrue(result.getErrors().stream()
                .anyMatch(e -> e.getField().equals("deviceId") && e.getMessage().contains("numeric")));
        }
        
        @Test
        @DisplayName("should fail with invalid environment")
        void shouldFailWithInvalidBaseUrl() {
            FdmsConfig config = validConfigBuilder()
                .baseUrl("not-a-url")
                .buildUnchecked();
            
            ConfigValidator.ValidationResult result = validator.validate(config);
            
            assertFalse(result.isValid());
            assertTrue(result.getErrors().stream()
                .anyMatch(e -> e.getField().equals("baseUrl")));
        }
        
        @Test
        @DisplayName("should fail with negative timeout")
        void shouldFailWithNegativeTimeout() {
            FdmsConfig config = validConfigBuilder()
                .timeout(-1000)
                .buildUnchecked();
            
            ConfigValidator.ValidationResult result = validator.validate(config);
            
            assertFalse(result.isValid());
            assertTrue(result.getErrors().stream()
                .anyMatch(e -> e.getField().equals("timeout")));
        }
        
        @Test
        @DisplayName("should fail with timeout too low")
        void shouldFailWithTimeoutTooLow() {
            FdmsConfig config = validConfigBuilder()
                .timeout(100)
                .buildUnchecked();
            
            ConfigValidator.ValidationResult result = validator.validate(config);
            
            assertFalse(result.isValid());
            assertTrue(result.getErrors().stream()
                .anyMatch(e -> e.getField().equals("timeout") && e.getMessage().contains("1000ms")));
        }
        
        @Test
        @DisplayName("should accept valid base URL")
        void shouldAcceptValidBaseUrl() {
            FdmsConfig config = validConfigBuilder()
                .baseUrl("https://example.com")
                .buildUnchecked();
            
            ConfigValidator.ValidationResult result = validator.validate(config);
            
            assertTrue(result.isValid());
        }
        
        @Test
        @DisplayName("should accept certificate as file path")
        void shouldAcceptCertificateAsFilePath() {
            FdmsConfig config = validConfigBuilder()
                .certificate("/path/to/cert.pem")
                .buildUnchecked();
            
            ConfigValidator.ValidationResult result = validator.validate(config);
            
            assertTrue(result.isValid());
        }
    }
    
    @Nested
    @DisplayName("validateOrThrow")
    class ValidateOrThrow {
        
        @Test
        @DisplayName("should throw with invalid configuration")
        void shouldThrowWithInvalidConfig() {
            FdmsConfig config = FdmsConfig.builder()
                .deviceId("abc") // Invalid - not numeric
                .buildUnchecked();
            
            assertThrows(ConfigValidationException.class, () -> {
                validator.validateOrThrow(config);
            });
        }
        
        @Test
        @DisplayName("should not throw with valid configuration")
        void shouldNotThrowWithValidConfig() {
            FdmsConfig config = validConfigBuilder().buildUnchecked();
            
            assertDoesNotThrow(() -> {
                validator.validateOrThrow(config);
            });
        }
    }
}
