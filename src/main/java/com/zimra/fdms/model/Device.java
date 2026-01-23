package com.zimra.fdms.model;

/**
 * Device model
 */
public class Device {
    private String deviceId;
    private String deviceSerialNo;
    private String deviceModelName;
    private String deviceModelVersion;
    private DeviceStatus status;

    public enum DeviceStatus {
        REGISTERED,
        ACTIVE,
        SUSPENDED,
        DEACTIVATED
    }

    // Getters and setters will be added
}
