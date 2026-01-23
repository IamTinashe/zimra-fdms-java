package com.zimra.fdms.config;

import com.zimra.fdms.exception.FdmsException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for ConfigLoader
 */
class ConfigLoaderTest {
    
    private ConfigLoader loader;
    
    @BeforeEach
    void setUp() {
        loader = new ConfigLoader();
    }
    
    private Map<String, Object> validConfigMap() {
        Map<String, Object> config = new HashMap<>();
        config.put("deviceId", "12345");
        config.put("deviceSerialNo", "SN-001");
        config.put("activationKey", "test-key");
        config.put("deviceModelName", "TestModel");
        config.put("deviceModelVersion", "1.0.0");
        config.put("certificate", "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----");
        config.put("privateKey", "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----");
        return config;
    }
    
    @Nested
    @DisplayName("merge")
    class Merge {
        
        @Test
        @DisplayName("should merge multiple configurations with priority")
        void shouldMergeWithPriority() {
            Map<String, Object> base = new HashMap<>();
            base.put("deviceId", "111");
            base.put("deviceSerialNo", "SN-BASE");
            
            Map<String, Object> override = new HashMap<>();
            override.put("deviceId", "222");
            override.put("timeout", 5000);
            
            Map<String, Object> result = loader.merge(base, override);
            
            assertEquals("222", result.get("deviceId"));
            assertEquals("SN-BASE", result.get("deviceSerialNo"));
            assertEquals(5000, result.get("timeout"));
        }
        
        @Test
        @DisplayName("should not include null values from overrides")
        void shouldFilterNullValues() {
            Map<String, Object> base = new HashMap<>();
            base.put("deviceId", "111");
            base.put("timeout", 30000);
            
            Map<String, Object> override = new HashMap<>();
            override.put("deviceId", "222");
            override.put("timeout", null);
            
            Map<String, Object> result = loader.merge(base, override);
            
            assertEquals("222", result.get("deviceId"));
            assertEquals(30000, result.get("timeout"));
        }
    }
    
    @Nested
    @DisplayName("resolve")
    class Resolve {
        
        @Test
        @DisplayName("should apply default values")
        void shouldApplyDefaults() {
            FdmsConfig config = loader.resolve(validConfigMap());
            
            assertEquals(FdmsEnvironment.TEST, config.getEnvironment());
            assertEquals(FdmsConfigConstants.DEFAULT_TIMEOUT, config.getTimeout());
            assertEquals(FdmsConfigConstants.DEFAULT_RETRY_ATTEMPTS, config.getRetryAttempts());
            assertEquals(FdmsConfigConstants.DEFAULT_RETRY_DELAY, config.getRetryDelay());
            assertEquals(FdmsConfigConstants.DEFAULT_ENABLE_AUDIT_LOG, config.isEnableAuditLog());
        }
        
        @Test
        @DisplayName("should set base URL from environment")
        void shouldSetBaseUrlFromEnvironment() {
            Map<String, Object> configMap = validConfigMap();
            configMap.put("environment", FdmsEnvironment.TEST);
            FdmsConfig config = loader.resolve(configMap);
            assertEquals(FdmsConfigConstants.FDMS_TEST_URL, config.getBaseUrl());
            
            configMap.put("environment", FdmsEnvironment.PRODUCTION);
            config = loader.resolve(configMap);
            assertEquals(FdmsConfigConstants.FDMS_PRODUCTION_URL, config.getBaseUrl());
        }
        
        @Test
        @DisplayName("should allow custom base URL")
        void shouldAllowCustomBaseUrl() {
            Map<String, Object> configMap = validConfigMap();
            configMap.put("baseUrl", "https://custom.example.com");
            
            FdmsConfig config = loader.resolve(configMap);
            
            assertEquals("https://custom.example.com", config.getBaseUrl());
        }
    }
    
    @Nested
    @DisplayName("fromFile")
    class FromFile {
        
        @TempDir
        Path tempDir;
        
        @Test
        @DisplayName("should load configuration from JSON file")
        void shouldLoadFromJsonFile() throws IOException {
            String json = """
                {
                    "deviceId": "67890",
                    "deviceSerialNo": "SN-FILE",
                    "activationKey": "file-key",
                    "deviceModelName": "FileModel",
                    "deviceModelVersion": "2.0.0",
                    "certificate": "-----BEGIN CERTIFICATE-----\\ntest\\n-----END CERTIFICATE-----",
                    "privateKey": "-----BEGIN RSA PRIVATE KEY-----\\ntest\\n-----END RSA PRIVATE KEY-----"
                }
                """;
            
            Path configFile = tempDir.resolve("config.json");
            Files.writeString(configFile, json);
            
            Map<String, Object> result = loader.fromFile(configFile.toString());
            
            assertEquals("67890", result.get("deviceId"));
            assertEquals("SN-FILE", result.get("deviceSerialNo"));
        }
        
        @Test
        @DisplayName("should throw for missing file")
        void shouldThrowForMissingFile() {
            assertThrows(FdmsException.class, () -> {
                loader.fromFile("/nonexistent/path.json");
            });
        }
    }
    
    @Nested
    @DisplayName("createTemplate")
    class CreateTemplate {
        
        @TempDir
        Path tempDir;
        
        @Test
        @DisplayName("should create template configuration file")
        void shouldCreateTemplateFile() throws FdmsException, IOException {
            Path templatePath = tempDir.resolve("config/template.json");
            
            loader.createTemplate(templatePath.toString());
            
            assertTrue(Files.exists(templatePath));
            String content = Files.readString(templatePath);
            assertTrue(content.contains("deviceId"));
            assertTrue(content.contains("certificate"));
            assertTrue(content.contains("environment"));
        }
    }
}
