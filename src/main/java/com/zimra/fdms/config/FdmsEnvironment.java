package com.zimra.fdms.config;

/**
 * FDMS Environment types
 */
public enum FdmsEnvironment {
    TEST("test"),
    PRODUCTION("production");
    
    private final String value;
    
    FdmsEnvironment(String value) {
        this.value = value;
    }
    
    public String getValue() {
        return value;
    }
    
    public static FdmsEnvironment fromString(String value) {
        if (value == null) {
            return TEST;
        }
        
        for (FdmsEnvironment env : FdmsEnvironment.values()) {
            if (env.value.equalsIgnoreCase(value)) {
                return env;
            }
        }
        throw new IllegalArgumentException("Unknown environment: " + value);
    }
}
