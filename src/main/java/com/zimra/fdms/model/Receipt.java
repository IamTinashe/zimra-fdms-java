package com.zimra.fdms.model;

import java.util.List;

/**
 * Receipt model
 */
public class Receipt {
    private ReceiptType receiptType;
    private String receiptCurrency;
    private int receiptCounter;
    private int receiptGlobalNo;
    private String invoiceNo;
    private String receiptDate;
    private BuyerData buyerData;
    private List<ReceiptLineItem> receiptLineItems;
    private List<ReceiptTax> receiptTaxes;
    private List<ReceiptPayment> receiptPayments;
    private double receiptTotal;
    private double receiptTaxTotal;
    private String receiptSignature;
    private Integer refReceiptId;
    private Integer refReceiptGlobalNo;

    public enum ReceiptType {
        FISCAL_INVOICE,
        CREDIT_NOTE,
        DEBIT_NOTE
    }

    // Getters and setters will be added
}
