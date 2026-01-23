package com.zimra.fdms.config;

import java.util.Objects;

/**
 * FDMS Configuration class
 * Defines all configuration options for the FDMS SDK
 * Use the Builder pattern to construct instances
 */
public class FdmsConfig {
    
    // Required - Device identification
    private final String deviceId;
    private final String deviceSerialNo;
    private final String activationKey;
    private final String deviceModelName;
    private final String deviceModelVersion;
    
    // Required - Certificate configuration
    private final String certificate;
    private final String privateKey;
    private final String privateKeyPassword;
    
    // Optional - Environment settings
    private final FdmsEnvironment environment;
    private final String baseUrl;
    private final int timeout;
    private final int retryAttempts;
    private final int retryDelay;
    
    // Optional - Audit logging
    private final boolean enableAuditLog;
    private final String auditLogPath;
    
    // Optional - State persistence
    private final String stateStorePath;
    
    private FdmsConfig(Builder builder) {
        this.deviceId = builder.deviceId;
        this.deviceSerialNo = builder.deviceSerialNo;
        this.activationKey = builder.activationKey;
        this.deviceModelName = builder.deviceModelName;
        this.deviceModelVersion = builder.deviceModelVersion;
        this.certificate = builder.certificate;
        this.privateKey = builder.privateKey;
        this.privateKeyPassword = builder.privateKeyPassword;
        this.environment = builder.environment;
        this.baseUrl = resolveBaseUrl(builder.baseUrl, builder.environment);
        this.timeout = builder.timeout;
        this.retryAttempts = builder.retryAttempts;
        this.retryDelay = builder.retryDelay;
        this.enableAuditLog = builder.enableAuditLog;
        this.auditLogPath = builder.auditLogPath;
        this.stateStorePath = builder.stateStorePath;
    }
    
    private String resolveBaseUrl(String customBaseUrl, FdmsEnvironment env) {
        if (customBaseUrl != null && !customBaseUrl.isEmpty()) {
            return customBaseUrl;
        }
        return FdmsConfigConstants.getBaseUrl(env);
    }
    
    // Getters
    
    public String getDeviceId() {
        return deviceId;
    }
    
    public String getDeviceSerialNo() {
        return deviceSerialNo;
    }
    
    public String getActivationKey() {
        return activationKey;
    }
    
    public String getDeviceModelName() {
        return deviceModelName;
    }
    
    public String getDeviceModelVersion() {
        return deviceModelVersion;
    }
    
    public String getCertificate() {
        return certificate;
    }
    
    public String getPrivateKey() {
        return privateKey;
    }
    
    public String getPrivateKeyPassword() {
        return privateKeyPassword;
    }
    
    public FdmsEnvironment getEnvironment() {
        return environment;
    }
    
    public String getBaseUrl() {
        return baseUrl;
    }
    
    public int getTimeout() {
        return timeout;
    }
    
    public int getRetryAttempts() {
        return retryAttempts;
    }
    
    public int getRetryDelay() {
        return retryDelay;
    }
    
    public boolean isEnableAuditLog() {
        return enableAuditLog;
    }
    
    public String getAuditLogPath() {
        return auditLogPath;
    }
    
    public String getStateStorePath() {
        return stateStorePath;
    }
    
    /**
     * Create a new Builder instance
     * 
     * @return a new Builder
     */
    public static Builder builder() {
        return new Builder();
    }
    
    /**
     * Create a Builder initialized with this config's values
     * 
     * @return a new Builder with current values
     */
    public Builder toBuilder() {
        return new Builder()
            .deviceId(this.deviceId)
            .deviceSerialNo(this.deviceSerialNo)
            .activationKey(this.activationKey)
            .deviceModelName(this.deviceModelName)
            .deviceModelVersion(this.deviceModelVersion)
            .certificate(this.certificate)
            .privateKey(this.privateKey)
            .privateKeyPassword(this.privateKeyPassword)
            .environment(this.environment)
            .baseUrl(this.baseUrl)
            .timeout(this.timeout)
            .retryAttempts(this.retryAttempts)
            .retryDelay(this.retryDelay)
            .enableAuditLog(this.enableAuditLog)
            .auditLogPath(this.auditLogPath)
            .stateStorePath(this.stateStorePath);
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FdmsConfig that = (FdmsConfig) o;
        return timeout == that.timeout &&
               retryAttempts == that.retryAttempts &&
               retryDelay == that.retryDelay &&
               enableAuditLog == that.enableAuditLog &&
               Objects.equals(deviceId, that.deviceId) &&
               Objects.equals(deviceSerialNo, that.deviceSerialNo) &&
               Objects.equals(activationKey, that.activationKey) &&
               Objects.equals(deviceModelName, that.deviceModelName) &&
               Objects.equals(deviceModelVersion, that.deviceModelVersion) &&
               Objects.equals(certificate, that.certificate) &&
               Objects.equals(privateKey, that.privateKey) &&
               Objects.equals(privateKeyPassword, that.privateKeyPassword) &&
               environment == that.environment &&
               Objects.equals(baseUrl, that.baseUrl) &&
               Objects.equals(auditLogPath, that.auditLogPath) &&
               Objects.equals(stateStorePath, that.stateStorePath);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(deviceId, deviceSerialNo, activationKey, deviceModelName,
            deviceModelVersion, certificate, privateKey, privateKeyPassword,
            environment, baseUrl, timeout, retryAttempts, retryDelay,
            enableAuditLog, auditLogPath, stateStorePath);
    }
    
    @Override
    public String toString() {
        return "FdmsConfig{" +
               "deviceId='" + deviceId + '\'' +
               ", deviceSerialNo='" + deviceSerialNo + '\'' +
               ", deviceModelName='" + deviceModelName + '\'' +
               ", deviceModelVersion='" + deviceModelVersion + '\'' +
               ", environment=" + environment +
               ", baseUrl='" + baseUrl + '\'' +
               ", timeout=" + timeout +
               ", retryAttempts=" + retryAttempts +
               ", enableAuditLog=" + enableAuditLog +
               '}';
    }
    
    /**
     * Builder for FdmsConfig
     */
    public static class Builder {
        private String deviceId;
        private String deviceSerialNo;
        private String activationKey;
        private String deviceModelName;
        private String deviceModelVersion;
        private String certificate;
        private String privateKey;
        private String privateKeyPassword;
        private FdmsEnvironment environment = FdmsConfigConstants.DEFAULT_ENVIRONMENT;
        private String baseUrl;
        private int timeout = FdmsConfigConstants.DEFAULT_TIMEOUT;
        private int retryAttempts = FdmsConfigConstants.DEFAULT_RETRY_ATTEMPTS;
        private int retryDelay = FdmsConfigConstants.DEFAULT_RETRY_DELAY;
        private boolean enableAuditLog = FdmsConfigConstants.DEFAULT_ENABLE_AUDIT_LOG;
        private String auditLogPath;
        private String stateStorePath;
        
        public Builder deviceId(String deviceId) {
            this.deviceId = deviceId;
            return this;
        }
        
        public Builder deviceSerialNo(String deviceSerialNo) {
            this.deviceSerialNo = deviceSerialNo;
            return this;
        }
        
        public Builder activationKey(String activationKey) {
            this.activationKey = activationKey;
            return this;
        }
        
        public Builder deviceModelName(String deviceModelName) {
            this.deviceModelName = deviceModelName;
            return this;
        }
        
        public Builder deviceModelVersion(String deviceModelVersion) {
            this.deviceModelVersion = deviceModelVersion;
            return this;
        }
        
        public Builder certificate(String certificate) {
            this.certificate = certificate;
            return this;
        }
        
        public Builder privateKey(String privateKey) {
            this.privateKey = privateKey;
            return this;
        }
        
        public Builder privateKeyPassword(String privateKeyPassword) {
            this.privateKeyPassword = privateKeyPassword;
            return this;
        }
        
        public Builder environment(FdmsEnvironment environment) {
            this.environment = environment;
            return this;
        }
        
        public Builder baseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
            return this;
        }
        
        public Builder timeout(int timeout) {
            this.timeout = timeout;
            return this;
        }
        
        public Builder retryAttempts(int retryAttempts) {
            this.retryAttempts = retryAttempts;
            return this;
        }
        
        public Builder retryDelay(int retryDelay) {
            this.retryDelay = retryDelay;
            return this;
        }
        
        public Builder enableAuditLog(boolean enableAuditLog) {
            this.enableAuditLog = enableAuditLog;
            return this;
        }
        
        public Builder auditLogPath(String auditLogPath) {
            this.auditLogPath = auditLogPath;
            return this;
        }
        
        public Builder stateStorePath(String stateStorePath) {
            this.stateStorePath = stateStorePath;
            return this;
        }
        
        /**
         * Build and validate the FdmsConfig
         * 
         * @return the validated FdmsConfig
         * @throws ConfigValidationException if validation fails
         */
        public FdmsConfig build() {
            FdmsConfig config = new FdmsConfig(this);
            ConfigValidator validator = new ConfigValidator();
            validator.validateOrThrow(config);
            return config;
        }
        
        /**
         * Build without validation
         * 
         * @return the FdmsConfig (unvalidated)
         */
        public FdmsConfig buildUnchecked() {
            return new FdmsConfig(this);
        }
        
        // Getters for internal use
        String getDeviceId() { return deviceId; }
        String getDeviceSerialNo() { return deviceSerialNo; }
        String getActivationKey() { return activationKey; }
        String getDeviceModelName() { return deviceModelName; }
        String getDeviceModelVersion() { return deviceModelVersion; }
        String getCertificate() { return certificate; }
        String getPrivateKey() { return privateKey; }
        String getPrivateKeyPassword() { return privateKeyPassword; }
        FdmsEnvironment getEnvironment() { return environment; }
        String getBaseUrl() { return baseUrl; }
        int getTimeout() { return timeout; }
        int getRetryAttempts() { return retryAttempts; }
        int getRetryDelay() { return retryDelay; }
        boolean isEnableAuditLog() { return enableAuditLog; }
        String getAuditLogPath() { return auditLogPath; }
        String getStateStorePath() { return stateStorePath; }
    }
}
