package com.zimra.fdms.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.zimra.fdms.exception.FdmsException;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

/**
 * FDMS Configuration Loader
 * Provides multiple ways to load and merge configuration
 */
public class ConfigLoader {
    
    private final ObjectMapper objectMapper;
    private final ConfigValidator validator;
    
    public ConfigLoader() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
        this.validator = new ConfigValidator();
    }
    
    /**
     * Load configuration from a JSON file
     * 
     * @param path path to JSON configuration file
     * @return configuration map
     * @throws FdmsException if file not found or invalid JSON
     */
    public Map<String, Object> fromFile(String path) throws FdmsException {
        Path filePath = Paths.get(path).toAbsolutePath();
        
        if (!Files.exists(filePath)) {
            throw new FdmsException("Configuration file not found: " + filePath, "CONFIG_FILE_NOT_FOUND");
        }
        
        try {
            JsonNode rootNode = objectMapper.readTree(filePath.toFile());
            Map<String, Object> config = objectMapper.convertValue(rootNode, Map.class);
            return processCertificatePaths(config, filePath.getParent());
        } catch (IOException e) {
            throw new FdmsException("Invalid JSON in configuration file: " + filePath, "CONFIG_PARSE_ERROR");
        }
    }
    
    /**
     * Load configuration from environment variables
     * 
     * @return configuration map
     */
    public Map<String, Object> fromEnvironment() {
        Map<String, Object> config = new HashMap<>();
        
        for (Map.Entry<String, String> entry : FdmsConfigConstants.ENV_VAR_MAPPING.entrySet()) {
            String envVar = entry.getKey();
            String configKey = entry.getValue();
            String value = System.getenv(envVar);
            
            if (value != null && !value.isEmpty()) {
                config.put(configKey, parseEnvValue(configKey, value));
            }
        }
        
        return config;
    }
    
    /**
     * Merge multiple configuration sources
     * Priority: later sources override earlier sources
     * 
     * @param sources configuration maps in order of increasing priority
     * @return merged configuration
     */
    @SafeVarargs
    public final Map<String, Object> merge(Map<String, Object>... sources) {
        Map<String, Object> merged = new HashMap<>();
        
        for (Map<String, Object> source : sources) {
            for (Map.Entry<String, Object> entry : source.entrySet()) {
                if (entry.getValue() != null) {
                    merged.put(entry.getKey(), entry.getValue());
                }
            }
        }
        
        return merged;
    }
    
    /**
     * Resolve configuration map to FdmsConfig object
     * 
     * @param configMap configuration map
     * @return resolved FdmsConfig
     */
    public FdmsConfig resolve(Map<String, Object> configMap) {
        FdmsConfig.Builder builder = FdmsConfig.builder();
        
        // Required fields
        if (configMap.containsKey("deviceId")) {
            builder.deviceId(String.valueOf(configMap.get("deviceId")));
        }
        if (configMap.containsKey("deviceSerialNo")) {
            builder.deviceSerialNo(String.valueOf(configMap.get("deviceSerialNo")));
        }
        if (configMap.containsKey("activationKey")) {
            builder.activationKey(String.valueOf(configMap.get("activationKey")));
        }
        if (configMap.containsKey("deviceModelName")) {
            builder.deviceModelName(String.valueOf(configMap.get("deviceModelName")));
        }
        if (configMap.containsKey("deviceModelVersion")) {
            builder.deviceModelVersion(String.valueOf(configMap.get("deviceModelVersion")));
        }
        if (configMap.containsKey("certificate")) {
            builder.certificate(String.valueOf(configMap.get("certificate")));
        }
        if (configMap.containsKey("privateKey")) {
            builder.privateKey(String.valueOf(configMap.get("privateKey")));
        }
        
        // Optional fields
        if (configMap.containsKey("privateKeyPassword")) {
            builder.privateKeyPassword(String.valueOf(configMap.get("privateKeyPassword")));
        }
        if (configMap.containsKey("environment")) {
            Object env = configMap.get("environment");
            if (env instanceof FdmsEnvironment) {
                builder.environment((FdmsEnvironment) env);
            } else {
                builder.environment(FdmsEnvironment.fromString(String.valueOf(env)));
            }
        }
        if (configMap.containsKey("baseUrl")) {
            builder.baseUrl(String.valueOf(configMap.get("baseUrl")));
        }
        if (configMap.containsKey("timeout")) {
            builder.timeout(toInt(configMap.get("timeout"), FdmsConfigConstants.DEFAULT_TIMEOUT));
        }
        if (configMap.containsKey("retryAttempts")) {
            builder.retryAttempts(toInt(configMap.get("retryAttempts"), FdmsConfigConstants.DEFAULT_RETRY_ATTEMPTS));
        }
        if (configMap.containsKey("retryDelay")) {
            builder.retryDelay(toInt(configMap.get("retryDelay"), FdmsConfigConstants.DEFAULT_RETRY_DELAY));
        }
        if (configMap.containsKey("enableAuditLog")) {
            builder.enableAuditLog(toBoolean(configMap.get("enableAuditLog"), FdmsConfigConstants.DEFAULT_ENABLE_AUDIT_LOG));
        }
        if (configMap.containsKey("auditLogPath")) {
            builder.auditLogPath(String.valueOf(configMap.get("auditLogPath")));
        }
        if (configMap.containsKey("stateStorePath")) {
            builder.stateStorePath(String.valueOf(configMap.get("stateStorePath")));
        }
        
        return builder.build();
    }
    
    /**
     * Load, merge, and resolve configuration from multiple sources
     * 
     * @param filePath path to JSON configuration file (optional, null to skip)
     * @param loadEnv whether to load from environment variables
     * @param programmaticConfig programmatic configuration (optional, null to skip)
     * @return resolved FdmsConfig
     */
    public FdmsConfig load(String filePath, boolean loadEnv, Map<String, Object> programmaticConfig) {
        Map<String, Object> fileConfig = filePath != null ? fromFile(filePath) : new HashMap<>();
        Map<String, Object> envConfig = loadEnv ? fromEnvironment() : new HashMap<>();
        Map<String, Object> progConfig = programmaticConfig != null ? programmaticConfig : new HashMap<>();
        
        Map<String, Object> merged = merge(fileConfig, envConfig, progConfig);
        return resolve(merged);
    }
    
    /**
     * Load configuration from file with optional environment overrides
     * 
     * @param filePath path to JSON configuration file
     * @return resolved FdmsConfig
     */
    public FdmsConfig loadFromFile(String filePath) {
        return load(filePath, true, null);
    }
    
    /**
     * Load configuration from environment variables only
     * 
     * @param programmaticConfig additional programmatic overrides
     * @return resolved FdmsConfig
     */
    public FdmsConfig loadFromEnvironment(Map<String, Object> programmaticConfig) {
        return load(null, true, programmaticConfig);
    }
    
    /**
     * Create a configuration template file
     * 
     * @param path path to write template
     * @throws FdmsException if writing fails
     */
    public void createTemplate(String path) throws FdmsException {
        Map<String, Object> template = new HashMap<>();
        template.put("deviceId", "YOUR_DEVICE_ID");
        template.put("deviceSerialNo", "YOUR_SERIAL_NUMBER");
        template.put("activationKey", "YOUR_ACTIVATION_KEY");
        template.put("deviceModelName", "YOUR_MODEL_NAME");
        template.put("deviceModelVersion", "1.0.0");
        template.put("certificate", "./certs/device.pem");
        template.put("privateKey", "./certs/device.key");
        template.put("privateKeyPassword", "");
        template.put("environment", "test");
        template.put("timeout", 30000);
        template.put("retryAttempts", 3);
        template.put("retryDelay", 1000);
        template.put("enableAuditLog", true);
        template.put("auditLogPath", "./logs/audit.log");
        template.put("stateStorePath", "./data/fiscal-state.json");
        
        Path filePath = Paths.get(path);
        try {
            Files.createDirectories(filePath.getParent());
            objectMapper.writeValue(filePath.toFile(), template);
        } catch (IOException e) {
            throw new FdmsException("Failed to create configuration template: " + e.getMessage(), "CONFIG_WRITE_ERROR");
        }
    }
    
    private Object parseEnvValue(String key, String value) {
        // Boolean fields
        if ("enableAuditLog".equals(key)) {
            return "true".equalsIgnoreCase(value) || "1".equals(value) || "yes".equalsIgnoreCase(value);
        }
        
        // Numeric fields
        if ("timeout".equals(key) || "retryAttempts".equals(key) || "retryDelay".equals(key)) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                return value;
            }
        }
        
        // Environment field
        if ("environment".equals(key)) {
            try {
                return FdmsEnvironment.fromString(value);
            } catch (IllegalArgumentException e) {
                return value;
            }
        }
        
        return value;
    }
    
    private Map<String, Object> processCertificatePaths(Map<String, Object> config, Path basePath) {
        Map<String, Object> processed = new HashMap<>(config);
        
        // Resolve certificate path if it's a relative path
        Object cert = processed.get("certificate");
        if (cert instanceof String) {
            String certStr = (String) cert;
            if (!certStr.contains("-----BEGIN") && !Paths.get(certStr).isAbsolute()) {
                processed.put("certificate", basePath.resolve(certStr).toString());
            }
        }
        
        // Resolve private key path if it's a relative path
        Object key = processed.get("privateKey");
        if (key instanceof String) {
            String keyStr = (String) key;
            if (!keyStr.contains("-----BEGIN") && !Paths.get(keyStr).isAbsolute()) {
                processed.put("privateKey", basePath.resolve(keyStr).toString());
            }
        }
        
        return processed;
    }
    
    private int toInt(Object value, int defaultValue) {
        if (value == null) return defaultValue;
        if (value instanceof Number) return ((Number) value).intValue();
        try {
            return Integer.parseInt(String.valueOf(value));
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
    
    private boolean toBoolean(Object value, boolean defaultValue) {
        if (value == null) return defaultValue;
        if (value instanceof Boolean) return (Boolean) value;
        String str = String.valueOf(value);
        return "true".equalsIgnoreCase(str) || "1".equals(str) || "yes".equalsIgnoreCase(str);
    }
}
