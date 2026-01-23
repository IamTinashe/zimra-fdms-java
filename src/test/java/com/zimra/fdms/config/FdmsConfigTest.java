package com.zimra.fdms.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for FdmsConfig
 */
class FdmsConfigTest {
    
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
    @DisplayName("Builder")
    class BuilderTests {
        
        @Test
        @DisplayName("should create config with valid data")
        void shouldCreateConfigWithValidData() {
            FdmsConfig config = validConfigBuilder().build();
            
            assertEquals("12345", config.getDeviceId());
            assertEquals("SN-001", config.getDeviceSerialNo());
            assertEquals(FdmsEnvironment.TEST, config.getEnvironment());
        }
        
        @Test
        @DisplayName("should set default base URL from environment")
        void shouldSetDefaultBaseUrl() {
            FdmsConfig config = validConfigBuilder().build();
            
            assertEquals(FdmsConfigConstants.FDMS_TEST_URL, config.getBaseUrl());
        }
        
        @Test
        @DisplayName("should allow custom base URL")
        void shouldAllowCustomBaseUrl() {
            FdmsConfig config = validConfigBuilder()
                .baseUrl("https://custom.example.com")
                .build();
            
            assertEquals("https://custom.example.com", config.getBaseUrl());
        }
        
        @Test
        @DisplayName("should throw on invalid config with build()")
        void shouldThrowOnInvalidConfig() {
            assertThrows(ConfigValidationException.class, () -> {
                FdmsConfig.builder()
                    .deviceId("abc")  // Invalid - not numeric
                    .build();
            });
        }
        
        @Test
        @DisplayName("should not throw on invalid config with buildUnchecked()")
        void shouldNotThrowWithBuildUnchecked() {
            assertDoesNotThrow(() -> {
                FdmsConfig.builder()
                    .deviceId("abc")  // Invalid - but no validation
                    .buildUnchecked();
            });
        }
        
        @Test
        @DisplayName("should apply default values")
        void shouldApplyDefaultValues() {
            FdmsConfig config = validConfigBuilder().build();
            
            assertEquals(FdmsConfigConstants.DEFAULT_TIMEOUT, config.getTimeout());
            assertEquals(FdmsConfigConstants.DEFAULT_RETRY_ATTEMPTS, config.getRetryAttempts());
            assertEquals(FdmsConfigConstants.DEFAULT_RETRY_DELAY, config.getRetryDelay());
            assertEquals(FdmsConfigConstants.DEFAULT_ENABLE_AUDIT_LOG, config.isEnableAuditLog());
        }
    }
    
    @Nested
    @DisplayName("toBuilder")
    class ToBuilderTests {
        
        @Test
        @DisplayName("should create builder with current values")
        void shouldCreateBuilderWithCurrentValues() {
            FdmsConfig original = validConfigBuilder()
                .timeout(60000)
                .enableAuditLog(false)
                .build();
            
            FdmsConfig copied = original.toBuilder()
                .timeout(90000)
                .build();
            
            assertEquals(60000, original.getTimeout());
            assertEquals(90000, copied.getTimeout());
            assertEquals(original.getDeviceId(), copied.getDeviceId());
            assertFalse(copied.isEnableAuditLog());
        }
    }
    
    @Nested
    @DisplayName("equals and hashCode")
    class EqualsAndHashCode {
        
        @Test
        @DisplayName("should be equal for same values")
        void shouldBeEqualForSameValues() {
            FdmsConfig config1 = validConfigBuilder().build();
            FdmsConfig config2 = validConfigBuilder().build();
            
            assertEquals(config1, config2);
            assertEquals(config1.hashCode(), config2.hashCode());
        }
        
        @Test
        @DisplayName("should not be equal for different values")
        void shouldNotBeEqualForDifferentValues() {
            FdmsConfig config1 = validConfigBuilder().build();
            FdmsConfig config2 = validConfigBuilder().timeout(60000).build();
            
            assertNotEquals(config1, config2);
        }
    }
}
