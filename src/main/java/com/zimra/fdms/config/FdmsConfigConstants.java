package com.zimra.fdms.config;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * FDMS Configuration constants and defaults
 */
public final class FdmsConfigConstants {
    
    private FdmsConfigConstants() {
        // Utility class
    }
    
    // FDMS Base URLs
    public static final String FDMS_TEST_URL = "https://fdmsapitest.zimra.co.zw";
    public static final String FDMS_PRODUCTION_URL = "https://fdmsapi.zimra.co.zw";
    
    // Default values
    public static final FdmsEnvironment DEFAULT_ENVIRONMENT = FdmsEnvironment.TEST;
    public static final int DEFAULT_TIMEOUT = 30000;
    public static final int DEFAULT_RETRY_ATTEMPTS = 3;
    public static final int DEFAULT_RETRY_DELAY = 1000;
    public static final boolean DEFAULT_ENABLE_AUDIT_LOG = true;
    
    // Validation limits
    public static final int MIN_TIMEOUT = 1000;
    public static final int MAX_TIMEOUT = 300000;
    public static final int MIN_RETRY_ATTEMPTS = 0;
    public static final int MAX_RETRY_ATTEMPTS = 10;
    public static final int MIN_RETRY_DELAY = 1;
    public static final int MAX_RETRY_DELAY = 60000;
    
    // Environment variable names
    public static final String ENV_DEVICE_ID = "FDMS_DEVICE_ID";
    public static final String ENV_DEVICE_SERIAL_NO = "FDMS_DEVICE_SERIAL_NO";
    public static final String ENV_ACTIVATION_KEY = "FDMS_ACTIVATION_KEY";
    public static final String ENV_DEVICE_MODEL_NAME = "FDMS_DEVICE_MODEL_NAME";
    public static final String ENV_DEVICE_MODEL_VERSION = "FDMS_DEVICE_MODEL_VERSION";
    public static final String ENV_CERTIFICATE = "FDMS_CERTIFICATE";
    public static final String ENV_PRIVATE_KEY = "FDMS_PRIVATE_KEY";
    public static final String ENV_PRIVATE_KEY_PASSWORD = "FDMS_PRIVATE_KEY_PASSWORD";
    public static final String ENV_ENVIRONMENT = "FDMS_ENVIRONMENT";
    public static final String ENV_BASE_URL = "FDMS_BASE_URL";
    public static final String ENV_TIMEOUT = "FDMS_TIMEOUT";
    public static final String ENV_RETRY_ATTEMPTS = "FDMS_RETRY_ATTEMPTS";
    public static final String ENV_RETRY_DELAY = "FDMS_RETRY_DELAY";
    public static final String ENV_ENABLE_AUDIT_LOG = "FDMS_ENABLE_AUDIT_LOG";
    public static final String ENV_AUDIT_LOG_PATH = "FDMS_AUDIT_LOG_PATH";
    public static final String ENV_STATE_STORE_PATH = "FDMS_STATE_STORE_PATH";
    
    /**
     * Environment variable to config field mapping
     */
    public static final Map<String, String> ENV_VAR_MAPPING;
    
    static {
        Map<String, String> map = new HashMap<>();
        map.put(ENV_DEVICE_ID, "deviceId");
        map.put(ENV_DEVICE_SERIAL_NO, "deviceSerialNo");
        map.put(ENV_ACTIVATION_KEY, "activationKey");
        map.put(ENV_DEVICE_MODEL_NAME, "deviceModelName");
        map.put(ENV_DEVICE_MODEL_VERSION, "deviceModelVersion");
        map.put(ENV_CERTIFICATE, "certificate");
        map.put(ENV_PRIVATE_KEY, "privateKey");
        map.put(ENV_PRIVATE_KEY_PASSWORD, "privateKeyPassword");
        map.put(ENV_ENVIRONMENT, "environment");
        map.put(ENV_BASE_URL, "baseUrl");
        map.put(ENV_TIMEOUT, "timeout");
        map.put(ENV_RETRY_ATTEMPTS, "retryAttempts");
        map.put(ENV_RETRY_DELAY, "retryDelay");
        map.put(ENV_ENABLE_AUDIT_LOG, "enableAuditLog");
        map.put(ENV_AUDIT_LOG_PATH, "auditLogPath");
        map.put(ENV_STATE_STORE_PATH, "stateStorePath");
        ENV_VAR_MAPPING = Collections.unmodifiableMap(map);
    }
    
    /**
     * FDMS Base URLs by environment
     */
    public static final Map<FdmsEnvironment, String> FDMS_BASE_URLS;
    
    static {
        Map<FdmsEnvironment, String> map = new HashMap<>();
        map.put(FdmsEnvironment.TEST, FDMS_TEST_URL);
        map.put(FdmsEnvironment.PRODUCTION, FDMS_PRODUCTION_URL);
        FDMS_BASE_URLS = Collections.unmodifiableMap(map);
    }
    
    /**
     * Get the base URL for a given environment
     * 
     * @param environment the FDMS environment
     * @return the base URL
     */
    public static String getBaseUrl(FdmsEnvironment environment) {
        return FDMS_BASE_URLS.getOrDefault(environment, FDMS_TEST_URL);
    }
}
