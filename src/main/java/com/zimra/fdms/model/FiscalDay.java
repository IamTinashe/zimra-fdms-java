package com.zimra.fdms.model;

/**
 * Fiscal day model
 */
public class FiscalDay {
    private int fiscalDayNo;
    private String fiscalDayOpened;
    private FiscalDayStatus fiscalDayStatus;

    public enum FiscalDayStatus {
        CLOSED,
        OPENED,
        CLOSE_INITIATED,
        CLOSE_FAILED
    }

    // Getters and setters will be added
}
