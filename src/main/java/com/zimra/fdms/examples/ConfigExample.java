package com.zimra.fdms.examples;

import com.zimra.fdms.config.*;

import java.util.HashMap;
import java.util.Map;

/**
 * Configuration Examples for ZIMRA FDMS SDK
 * Demonstrates various ways to configure the SDK
 */
public class ConfigExample {
    
    // =============================================================================
    // Example 1: Programmatic Configuration with Builder
    // =============================================================================
    
    public static FdmsConfig programmaticConfigExample() {
        // Using the Builder pattern for type-safe configuration
        return FdmsConfig.builder()
            // Required device information
            .deviceId("12345")
            .deviceSerialNo("SN-2024-001")
            .activationKey("your-activation-key-from-zimra")
            .deviceModelName("MyPOS-Terminal")
            .deviceModelVersion("1.0.0")
            
            // Certificate configuration
            .certificate("/path/to/device-certificate.pem")
            .privateKey("/path/to/private-key.pem")
            .privateKeyPassword("optional-key-password")
            
            // Environment settings
            .environment(FdmsEnvironment.TEST)  // Use PRODUCTION for live
            .timeout(30000)
            .retryAttempts(3)
            .retryDelay(1000)
            
            // Audit logging
            .enableAuditLog(true)
            .auditLogPath("./logs/fdms-audit.log")
            
            // State persistence
            .stateStorePath("./data/fiscal-state.json")
            
            .build();
    }
    
    // =============================================================================
    // Example 2: File-based Configuration
    // =============================================================================
    
    public static FdmsConfig fileConfigExample() {
        ConfigLoader loader = new ConfigLoader();
        
        // Load from JSON file (see fdms-config.example.json)
        return loader.loadFromFile("./config/fdms-config.json");
    }
    
    // =============================================================================
    // Example 3: Environment Variables Configuration
    // =============================================================================
    
    public static FdmsConfig envConfigExample() {
        /**
         * Set these environment variables before running:
         *
         * export FDMS_DEVICE_ID="12345"
         * export FDMS_DEVICE_SERIAL_NO="SN-2024-001"
         * export FDMS_ACTIVATION_KEY="your-activation-key"
         * export FDMS_DEVICE_MODEL_NAME="MyPOS-Terminal"
         * export FDMS_DEVICE_MODEL_VERSION="1.0.0"
         * export FDMS_CERTIFICATE="/path/to/cert.pem"
         * export FDMS_PRIVATE_KEY="/path/to/key.pem"
         * export FDMS_ENVIRONMENT="test"
         * export FDMS_ENABLE_AUDIT_LOG="true"
         */
        ConfigLoader loader = new ConfigLoader();
        return loader.loadFromEnvironment(null);
    }
    
    // =============================================================================
    // Example 4: Merged Configuration (File + Environment + Programmatic)
    // =============================================================================
    
    public static FdmsConfig mergedConfigExample() {
        ConfigLoader loader = new ConfigLoader();
        
        // Override specific settings at runtime
        Map<String, Object> overrides = new HashMap<>();
        overrides.put("timeout", 60000);  // Longer timeout for slow connections
        
        // This allows base settings in file, overrides via env vars,
        // and runtime-specific settings programmatically
        return loader.load("./config/fdms-config.json", true, overrides);
    }
    
    // =============================================================================
    // Example 5: Inline Certificate Content
    // =============================================================================
    
    public static FdmsConfig inlineCertificateExample() {
        String certificatePem = "-----BEGIN CERTIFICATE-----\n" +
            "MIIBkTCB+wIJAKHBfpEgcMFvMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnVu\n" +
            "dXNlZDAeFw0yNDAxMjMwMDAwMDBaFw0yNTAxMjMwMDAwMDBaMBExDzANBgNVBAMM\n" +
            "BnVudXNlZDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC5lKUH7MN7z1A2Z5lBz0lM\n" +
            "-----END CERTIFICATE-----";
        
        String privateKeyPem = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIBOgIBAAJBALmUpQfsw3vPUDZnmUHPSUxbQqpM1kvqPw/0PELRnl1XkUZm4NAH\n" +
            "n7HWofsGoiovu3cAWfp4fS8OrouovVlsTS0CAwEAAQJAYJl8W8gXk2P5t3J5y8W7\n" +
            "-----END RSA PRIVATE KEY-----";
        
        return FdmsConfig.builder()
            .deviceId("12345")
            .deviceSerialNo("SN-2024-001")
            .activationKey("your-activation-key")
            .deviceModelName("MyPOS-Terminal")
            .deviceModelVersion("1.0.0")
            
            // Inline certificate and key content
            .certificate(certificatePem)
            .privateKey(privateKeyPem)
            
            .environment(FdmsEnvironment.TEST)
            .build();
    }
    
    // =============================================================================
    // Example 6: Creating a Configuration Template
    // =============================================================================
    
    public static void createConfigTemplateExample() {
        ConfigLoader loader = new ConfigLoader();
        
        // Create a template configuration file
        loader.createTemplate("./config/fdms-config.template.json");
        
        System.out.println("Configuration template created at ./config/fdms-config.template.json");
    }
    
    // =============================================================================
    // Example 7: Configuration Validation
    // =============================================================================
    
    public static void validationExample() {
        // Build config without validation
        FdmsConfig partialConfig = FdmsConfig.builder()
            .deviceId("12345")
            // Missing required fields...
            .buildUnchecked();
        
        ConfigValidator validator = new ConfigValidator();
        ConfigValidator.ValidationResult result = validator.validate(partialConfig);
        
        if (!result.isValid()) {
            System.out.println("Configuration validation failed:");
            for (ConfigValidator.ValidationError error : result.getErrors()) {
                System.out.println("  - " + error.getField() + ": " + error.getMessage());
            }
        }
    }
    
    // =============================================================================
    // Run Examples
    // =============================================================================
    
    public static void main(String[] args) {
        System.out.println("=== ZIMRA FDMS Configuration Examples ===\n");
        
        // Example 7: Validation
        System.out.println("7. Configuration Validation:");
        validationExample();
        System.out.println();
        
        // Example 6: Create template
        System.out.println("6. Create Configuration Template:");
        createConfigTemplateExample();
    }
}
