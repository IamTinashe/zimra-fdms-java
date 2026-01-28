package com.zimra.fdms.crypto;

import com.zimra.fdms.exception.FdmsException;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Digital Signature Service for ZIMRA FDMS
 * 
 * <p>Provides RSA-SHA256 digital signature generation and verification
 * for receipts and fiscal day reports according to ZIMRA FDMS specification.
 * 
 * <p>Features:
 * <ul>
 *   <li>Receipt signing per FDMS specification</li>
 *   <li>Fiscal day report signing</li>
 *   <li>Signature verification</li>
 *   <li>Optional signature caching</li>
 * </ul>
 * 
 * <p>Example usage:
 * <pre>{@code
 * SignatureService service = new SignatureService.Builder()
 *     .privateKey(Files.readString(Path.of("./device-key.pem")))
 *     .privateKeyPassword("key-password")
 *     .enableCache(true)
 *     .build();
 * 
 * // Sign a receipt
 * ReceiptSignatureData data = ReceiptSignatureData.builder()
 *     .deviceId(12345)
 *     .receiptType("FiscalInvoice")
 *     .receiptCurrency("USD")
 *     .receiptCounter(1)
 *     .receiptGlobalNo(100)
 *     .invoiceNo("INV-001")
 *     .receiptDate("2025-01-26T10:00:00Z")
 *     .receiptTotal(1150.00)
 *     .build();
 * 
 * SignatureResult result = service.signReceipt(data);
 * System.out.println("Signature: " + result.getSignature());
 * }</pre>
 */
public class SignatureService {
    
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String KEY_ALGORITHM = "RSA";
    
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private final boolean enableCache;
    private final int maxCacheSize;
    private final Map<String, SignatureResult> cache;
    
    private SignatureService(Builder builder) {
        this.enableCache = builder.enableCache;
        this.maxCacheSize = builder.maxCacheSize;
        this.cache = enableCache ? new ConcurrentHashMap<>() : null;
        
        if (builder.privateKey != null) {
            loadPrivateKey(builder.privateKey, builder.privateKeyPassword);
        }
        
        if (builder.publicKey != null) {
            loadPublicKey(builder.publicKey);
        }
    }
    
    /**
     * Load a private key for signing
     * 
     * @param keyPem Private key in PEM format
     * @param password Password for encrypted keys (null if not encrypted)
     * @throws FdmsException if key cannot be loaded
     */
    public void loadPrivateKey(String keyPem, String password) {
        try {
            // Remove PEM headers and decode
            String base64Key = keyPem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", "")
                .replace("-----END ENCRYPTED PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");
            
            byte[] keyBytes = Base64.getDecoder().decode(base64Key);
            
            // Handle encrypted keys
            if (password != null && !password.isEmpty()) {
                keyBytes = decryptPrivateKey(keyBytes, password);
            }
            
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            this.privateKey = keyFactory.generatePrivate(keySpec);
            
            // Extract public key from private key
            this.publicKey = extractPublicKey(this.privateKey);
            
        } catch (Exception e) {
            throw new FdmsException("Failed to load private key: " + e.getMessage(), "CRYPTO30", e);
        }
    }
    
    /**
     * Load a public key or certificate for verification
     * 
     * @param keyOrCertPem Public key or certificate in PEM format
     * @throws FdmsException if key cannot be loaded
     */
    public void loadPublicKey(String keyOrCertPem) {
        try {
            if (keyOrCertPem.contains("CERTIFICATE")) {
                // Load from certificate
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                ByteArrayInputStream certStream = new ByteArrayInputStream(
                    keyOrCertPem.getBytes(StandardCharsets.UTF_8)
                );
                X509Certificate cert = (X509Certificate) certFactory.generateCertificate(certStream);
                this.publicKey = cert.getPublicKey();
            } else {
                // Load public key directly
                String base64Key = keyOrCertPem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");
                
                byte[] keyBytes = Base64.getDecoder().decode(base64Key);
                java.security.spec.X509EncodedKeySpec keySpec = 
                    new java.security.spec.X509EncodedKeySpec(keyBytes);
                KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
                this.publicKey = keyFactory.generatePublic(keySpec);
            }
        } catch (Exception e) {
            throw new FdmsException("Failed to load public key: " + e.getMessage(), "CRYPTO31", e);
        }
    }
    
    /**
     * Sign receipt data according to ZIMRA FDMS specification
     * 
     * @param data Receipt data to sign
     * @return Signature result with Base64-encoded signature
     * @throws FdmsException if signing fails
     */
    public SignatureResult signReceipt(ReceiptSignatureData data) {
        if (privateKey == null) {
            throw new FdmsException("Private key not loaded", "CRYPTO32");
        }
        
        String dataString = prepareReceiptDataString(data);
        
        // Check cache
        if (enableCache && cache.containsKey(dataString)) {
            return cache.get(dataString);
        }
        
        SignatureResult result = sign(dataString);
        
        // Cache result
        if (enableCache) {
            addToCache(dataString, result);
        }
        
        return result;
    }
    
    /**
     * Sign fiscal day report data according to ZIMRA FDMS specification
     * 
     * @param data Fiscal day report data to sign
     * @return Signature result with Base64-encoded signature
     * @throws FdmsException if signing fails
     */
    public SignatureResult signFiscalDayReport(FiscalDayReportData data) {
        if (privateKey == null) {
            throw new FdmsException("Private key not loaded", "CRYPTO32");
        }
        
        String dataString = prepareFiscalDayDataString(data);
        
        // Check cache
        if (enableCache && cache.containsKey(dataString)) {
            return cache.get(dataString);
        }
        
        SignatureResult result = sign(dataString);
        
        // Cache result
        if (enableCache) {
            addToCache(dataString, result);
        }
        
        return result;
    }
    
    /**
     * Sign arbitrary data string
     * 
     * @param dataString Data string to sign
     * @return Signature result
     * @throws FdmsException if signing fails
     */
    public SignatureResult signData(String dataString) {
        if (privateKey == null) {
            throw new FdmsException("Private key not loaded", "CRYPTO32");
        }
        
        return sign(dataString);
    }
    
    /**
     * Verify a receipt signature
     * 
     * @param data Receipt data that was signed
     * @param signature Base64-encoded signature to verify
     * @return Verification result
     */
    public VerificationResult verifyReceiptSignature(ReceiptSignatureData data, String signature) {
        String dataString = prepareReceiptDataString(data);
        return verify(dataString, signature);
    }
    
    /**
     * Verify a fiscal day report signature
     * 
     * @param data Fiscal day report data that was signed
     * @param signature Base64-encoded signature to verify
     * @return Verification result
     */
    public VerificationResult verifyFiscalDaySignature(FiscalDayReportData data, String signature) {
        String dataString = prepareFiscalDayDataString(data);
        return verify(dataString, signature);
    }
    
    /**
     * Verify a signature against arbitrary data
     * 
     * @param dataString Data string that was signed
     * @param signature Base64-encoded signature to verify
     * @return Verification result
     */
    public VerificationResult verifySignature(String dataString, String signature) {
        return verify(dataString, signature);
    }
    
    /**
     * Prepare the data string for receipt signing
     * 
     * @param data Receipt data
     * @return Prepared data string
     */
    public String prepareReceiptDataString(ReceiptSignatureData data) {
        List<String> parts = new ArrayList<>();
        
        // Device identification
        parts.add(String.valueOf(data.getDeviceId()));
        parts.add(data.getReceiptType());
        parts.add(data.getReceiptCurrency());
        parts.add(String.valueOf(data.getReceiptCounter()));
        parts.add(String.valueOf(data.getReceiptGlobalNo()));
        parts.add(data.getInvoiceNo());
        parts.add(data.getReceiptDate());
        
        // Line items (sorted by line number)
        if (data.getReceiptLineItems() != null) {
            data.getReceiptLineItems().stream()
                .sorted(Comparator.comparingInt(ReceiptLineItemData::getLineNo))
                .forEach(item -> parts.add(formatLineItem(item)));
        }
        
        // Tax summaries (sorted by tax code)
        if (data.getReceiptTaxes() != null) {
            data.getReceiptTaxes().stream()
                .sorted(Comparator.comparing(ReceiptTaxData::getTaxCode))
                .forEach(tax -> parts.add(formatTax(tax)));
        }
        
        // Payments (sorted by money type code)
        if (data.getReceiptPayments() != null) {
            data.getReceiptPayments().stream()
                .sorted(Comparator.comparingInt(ReceiptPaymentData::getMoneyTypeCode))
                .forEach(payment -> parts.add(formatPayment(payment)));
        }
        
        // Total
        parts.add(formatAmount(data.getReceiptTotal()));
        
        return String.join("\n", parts);
    }
    
    /**
     * Prepare the data string for fiscal day report signing
     * 
     * @param data Fiscal day report data
     * @return Prepared data string
     */
    public String prepareFiscalDayDataString(FiscalDayReportData data) {
        List<String> parts = new ArrayList<>();
        
        // Device and day identification
        parts.add(String.valueOf(data.getDeviceId()));
        parts.add(String.valueOf(data.getFiscalDayNo()));
        parts.add(data.getFiscalDayOpened());
        
        // Counters
        parts.add(String.valueOf(data.getReceiptCounter()));
        
        // Receipt counters by type (sorted by type name)
        if (data.getReceiptCounterByType() != null) {
            data.getReceiptCounterByType().entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(entry -> parts.add(entry.getKey() + ":" + entry.getValue()));
        }
        
        // Totals
        parts.add(formatAmount(data.getTotalAmount()));
        parts.add(formatAmount(data.getTotalTax()));
        
        // Tax rate totals (sorted by tax percent)
        if (data.getTotalsByTaxRate() != null) {
            data.getTotalsByTaxRate().stream()
                .sorted(Comparator.comparingDouble(TaxRateTotalData::getTaxPercent))
                .forEach(rate -> parts.add(
                    formatAmount(rate.getTaxPercent()) + ":" + formatAmount(rate.getTaxAmount())
                ));
        }
        
        return String.join("\n", parts);
    }
    
    /**
     * Get the hash of a data string (for debugging/verification)
     * 
     * @param dataString Data string to hash
     * @return SHA-256 hash in hexadecimal format
     */
    public String getDataHash(String dataString) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(dataString.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
    
    /**
     * Clear the signature cache
     */
    public void clearCache() {
        if (cache != null) {
            cache.clear();
        }
    }
    
    /**
     * Get current cache size
     */
    public int getCacheSize() {
        return cache != null ? cache.size() : 0;
    }
    
    /**
     * Check if the service has a private key loaded
     */
    public boolean hasPrivateKey() {
        return privateKey != null;
    }
    
    /**
     * Check if the service has a public key loaded
     */
    public boolean hasPublicKey() {
        return publicKey != null;
    }
    
    // Private methods
    
    private SignatureResult sign(String dataString) {
        try {
            Signature signer = Signature.getInstance(SIGNATURE_ALGORITHM);
            signer.initSign(privateKey);
            signer.update(dataString.getBytes(StandardCharsets.UTF_8));
            
            byte[] signatureBytes = signer.sign();
            String signature = Base64.getEncoder().encodeToString(signatureBytes);
            String hash = getDataHash(dataString);
            
            return new SignatureResult(signature, dataString, hash, Instant.now(), SIGNATURE_ALGORITHM);
            
        } catch (Exception e) {
            throw new FdmsException("Failed to sign data: " + e.getMessage(), "CRYPTO33", e);
        }
    }
    
    private VerificationResult verify(String dataString, String signature) {
        if (publicKey == null) {
            return new VerificationResult(false, "Public key not loaded for verification", null);
        }
        
        try {
            Signature verifier = Signature.getInstance(SIGNATURE_ALGORITHM);
            verifier.initVerify(publicKey);
            verifier.update(dataString.getBytes(StandardCharsets.UTF_8));
            
            byte[] signatureBytes = Base64.getDecoder().decode(signature);
            boolean valid = verifier.verify(signatureBytes);
            
            return new VerificationResult(valid, valid ? null : "Signature does not match", dataString);
            
        } catch (Exception e) {
            return new VerificationResult(false, "Verification failed: " + e.getMessage(), dataString);
        }
    }
    
    private void addToCache(String key, SignatureResult result) {
        if (cache.size() >= maxCacheSize) {
            // Remove first entry (simple eviction)
            String firstKey = cache.keySet().iterator().next();
            cache.remove(firstKey);
        }
        cache.put(key, result);
    }
    
    private String formatLineItem(ReceiptLineItemData item) {
        List<String> parts = new ArrayList<>();
        parts.add(String.valueOf(item.getLineNo()));
        parts.add(item.getLineDescription());
        parts.add(formatQuantity(item.getLineQuantity()));
        parts.add(formatAmount(item.getLineUnitPrice()));
        parts.add(formatAmount(item.getLineTaxPercent()));
        parts.add(formatAmount(item.getLineTotal()));
        
        if (item.getHsCode() != null && !item.getHsCode().isEmpty()) {
            parts.add(item.getHsCode());
        }
        
        return String.join("|", parts);
    }
    
    private String formatTax(ReceiptTaxData tax) {
        return String.join("|",
            tax.getTaxCode(),
            formatAmount(tax.getTaxPercent()),
            formatAmount(tax.getTaxAmount()),
            formatAmount(tax.getSalesAmountWithTax())
        );
    }
    
    private String formatPayment(ReceiptPaymentData payment) {
        return String.join("|",
            String.valueOf(payment.getMoneyTypeCode()),
            formatAmount(payment.getPaymentAmount())
        );
    }
    
    private String formatAmount(double amount) {
        return String.format(Locale.US, "%.2f", amount);
    }
    
    private String formatQuantity(double quantity) {
        String formatted = String.format(Locale.US, "%.4f", quantity);
        // Remove trailing zeros
        formatted = formatted.replaceAll("0+$", "").replaceAll("\\.$", "");
        return formatted.isEmpty() ? "0" : formatted;
    }
    
    private byte[] decryptPrivateKey(byte[] encryptedKey, String password) throws Exception {
        // Use encrypted private key info to decrypt
        javax.crypto.EncryptedPrivateKeyInfo encryptedInfo = 
            new javax.crypto.EncryptedPrivateKeyInfo(encryptedKey);
        
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(
            encryptedInfo.getAlgName()
        );
        
        javax.crypto.SecretKeyFactory keyFactory = javax.crypto.SecretKeyFactory.getInstance(
            encryptedInfo.getAlgName()
        );
        
        javax.crypto.SecretKey secretKey = keyFactory.generateSecret(
            new javax.crypto.spec.PBEKeySpec(password.toCharArray())
        );
        
        java.security.AlgorithmParameters algParams = encryptedInfo.getAlgParameters();
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey, algParams);
        
        PKCS8EncodedKeySpec keySpec = encryptedInfo.getKeySpec(cipher);
        return keySpec.getEncoded();
    }
    
    private PublicKey extractPublicKey(PrivateKey privateKey) throws Exception {
        if (privateKey instanceof java.security.interfaces.RSAPrivateCrtKey) {
            java.security.interfaces.RSAPrivateCrtKey rsaKey = 
                (java.security.interfaces.RSAPrivateCrtKey) privateKey;
            java.security.spec.RSAPublicKeySpec publicKeySpec = 
                new java.security.spec.RSAPublicKeySpec(
                    rsaKey.getModulus(),
                    rsaKey.getPublicExponent()
                );
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            return keyFactory.generatePublic(publicKeySpec);
        }
        return null;
    }
    
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    // Builder class
    
    /**
     * Builder for SignatureService
     */
    public static class Builder {
        private String privateKey;
        private String privateKeyPassword;
        private String publicKey;
        private boolean enableCache = false;
        private int maxCacheSize = 1000;
        
        /**
         * Set the private key for signing
         * 
         * @param privateKey Private key in PEM format
         * @return This builder
         */
        public Builder privateKey(String privateKey) {
            this.privateKey = privateKey;
            return this;
        }
        
        /**
         * Set the private key password
         * 
         * @param password Password for encrypted private key
         * @return This builder
         */
        public Builder privateKeyPassword(String password) {
            this.privateKeyPassword = password;
            return this;
        }
        
        /**
         * Set the public key for verification
         * 
         * @param publicKey Public key or certificate in PEM format
         * @return This builder
         */
        public Builder publicKey(String publicKey) {
            this.publicKey = publicKey;
            return this;
        }
        
        /**
         * Enable signature caching
         * 
         * @param enable Whether to enable caching
         * @return This builder
         */
        public Builder enableCache(boolean enable) {
            this.enableCache = enable;
            return this;
        }
        
        /**
         * Set maximum cache size
         * 
         * @param size Maximum number of cached signatures
         * @return This builder
         */
        public Builder maxCacheSize(int size) {
            this.maxCacheSize = size;
            return this;
        }
        
        /**
         * Build the SignatureService
         * 
         * @return New SignatureService instance
         */
        public SignatureService build() {
            return new SignatureService(this);
        }
    }
    
    // Inner data classes
    
    /**
     * Receipt data for signature generation
     */
    public static class ReceiptSignatureData {
        private final int deviceId;
        private final String receiptType;
        private final String receiptCurrency;
        private final int receiptCounter;
        private final int receiptGlobalNo;
        private final String invoiceNo;
        private final String receiptDate;
        private final List<ReceiptLineItemData> receiptLineItems;
        private final List<ReceiptTaxData> receiptTaxes;
        private final List<ReceiptPaymentData> receiptPayments;
        private final double receiptTotal;
        
        private ReceiptSignatureData(ReceiptSignatureDataBuilder builder) {
            this.deviceId = builder.deviceId;
            this.receiptType = builder.receiptType;
            this.receiptCurrency = builder.receiptCurrency;
            this.receiptCounter = builder.receiptCounter;
            this.receiptGlobalNo = builder.receiptGlobalNo;
            this.invoiceNo = builder.invoiceNo;
            this.receiptDate = builder.receiptDate;
            this.receiptLineItems = builder.receiptLineItems;
            this.receiptTaxes = builder.receiptTaxes;
            this.receiptPayments = builder.receiptPayments;
            this.receiptTotal = builder.receiptTotal;
        }
        
        public static ReceiptSignatureDataBuilder builder() {
            return new ReceiptSignatureDataBuilder();
        }
        
        // Getters
        public int getDeviceId() { return deviceId; }
        public String getReceiptType() { return receiptType; }
        public String getReceiptCurrency() { return receiptCurrency; }
        public int getReceiptCounter() { return receiptCounter; }
        public int getReceiptGlobalNo() { return receiptGlobalNo; }
        public String getInvoiceNo() { return invoiceNo; }
        public String getReceiptDate() { return receiptDate; }
        public List<ReceiptLineItemData> getReceiptLineItems() { return receiptLineItems; }
        public List<ReceiptTaxData> getReceiptTaxes() { return receiptTaxes; }
        public List<ReceiptPaymentData> getReceiptPayments() { return receiptPayments; }
        public double getReceiptTotal() { return receiptTotal; }
        
        public static class ReceiptSignatureDataBuilder {
            private int deviceId;
            private String receiptType;
            private String receiptCurrency;
            private int receiptCounter;
            private int receiptGlobalNo;
            private String invoiceNo;
            private String receiptDate;
            private List<ReceiptLineItemData> receiptLineItems = new ArrayList<>();
            private List<ReceiptTaxData> receiptTaxes = new ArrayList<>();
            private List<ReceiptPaymentData> receiptPayments = new ArrayList<>();
            private double receiptTotal;
            
            public ReceiptSignatureDataBuilder deviceId(int deviceId) { this.deviceId = deviceId; return this; }
            public ReceiptSignatureDataBuilder receiptType(String receiptType) { this.receiptType = receiptType; return this; }
            public ReceiptSignatureDataBuilder receiptCurrency(String receiptCurrency) { this.receiptCurrency = receiptCurrency; return this; }
            public ReceiptSignatureDataBuilder receiptCounter(int receiptCounter) { this.receiptCounter = receiptCounter; return this; }
            public ReceiptSignatureDataBuilder receiptGlobalNo(int receiptGlobalNo) { this.receiptGlobalNo = receiptGlobalNo; return this; }
            public ReceiptSignatureDataBuilder invoiceNo(String invoiceNo) { this.invoiceNo = invoiceNo; return this; }
            public ReceiptSignatureDataBuilder receiptDate(String receiptDate) { this.receiptDate = receiptDate; return this; }
            public ReceiptSignatureDataBuilder receiptLineItems(List<ReceiptLineItemData> items) { this.receiptLineItems = items; return this; }
            public ReceiptSignatureDataBuilder receiptTaxes(List<ReceiptTaxData> taxes) { this.receiptTaxes = taxes; return this; }
            public ReceiptSignatureDataBuilder receiptPayments(List<ReceiptPaymentData> payments) { this.receiptPayments = payments; return this; }
            public ReceiptSignatureDataBuilder receiptTotal(double receiptTotal) { this.receiptTotal = receiptTotal; return this; }
            
            public ReceiptSignatureData build() {
                return new ReceiptSignatureData(this);
            }
        }
    }
    
    /**
     * Line item data for signature
     */
    public static class ReceiptLineItemData {
        private final int lineNo;
        private final String lineDescription;
        private final double lineQuantity;
        private final double lineUnitPrice;
        private final double lineTaxPercent;
        private final double lineTotal;
        private final String hsCode;
        
        private ReceiptLineItemData(ReceiptLineItemDataBuilder builder) {
            this.lineNo = builder.lineNo;
            this.lineDescription = builder.lineDescription;
            this.lineQuantity = builder.lineQuantity;
            this.lineUnitPrice = builder.lineUnitPrice;
            this.lineTaxPercent = builder.lineTaxPercent;
            this.lineTotal = builder.lineTotal;
            this.hsCode = builder.hsCode;
        }
        
        public static ReceiptLineItemDataBuilder builder() {
            return new ReceiptLineItemDataBuilder();
        }
        
        // Getters
        public int getLineNo() { return lineNo; }
        public String getLineDescription() { return lineDescription; }
        public double getLineQuantity() { return lineQuantity; }
        public double getLineUnitPrice() { return lineUnitPrice; }
        public double getLineTaxPercent() { return lineTaxPercent; }
        public double getLineTotal() { return lineTotal; }
        public String getHsCode() { return hsCode; }
        
        public static class ReceiptLineItemDataBuilder {
            private int lineNo;
            private String lineDescription;
            private double lineQuantity;
            private double lineUnitPrice;
            private double lineTaxPercent;
            private double lineTotal;
            private String hsCode;
            
            public ReceiptLineItemDataBuilder lineNo(int lineNo) { this.lineNo = lineNo; return this; }
            public ReceiptLineItemDataBuilder lineDescription(String lineDescription) { this.lineDescription = lineDescription; return this; }
            public ReceiptLineItemDataBuilder lineQuantity(double lineQuantity) { this.lineQuantity = lineQuantity; return this; }
            public ReceiptLineItemDataBuilder lineUnitPrice(double lineUnitPrice) { this.lineUnitPrice = lineUnitPrice; return this; }
            public ReceiptLineItemDataBuilder lineTaxPercent(double lineTaxPercent) { this.lineTaxPercent = lineTaxPercent; return this; }
            public ReceiptLineItemDataBuilder lineTotal(double lineTotal) { this.lineTotal = lineTotal; return this; }
            public ReceiptLineItemDataBuilder hsCode(String hsCode) { this.hsCode = hsCode; return this; }
            
            public ReceiptLineItemData build() {
                return new ReceiptLineItemData(this);
            }
        }
    }
    
    /**
     * Tax data for signature
     */
    public static class ReceiptTaxData {
        private final String taxCode;
        private final double taxPercent;
        private final double taxAmount;
        private final double salesAmountWithTax;
        
        private ReceiptTaxData(ReceiptTaxDataBuilder builder) {
            this.taxCode = builder.taxCode;
            this.taxPercent = builder.taxPercent;
            this.taxAmount = builder.taxAmount;
            this.salesAmountWithTax = builder.salesAmountWithTax;
        }
        
        public static ReceiptTaxDataBuilder builder() {
            return new ReceiptTaxDataBuilder();
        }
        
        // Getters
        public String getTaxCode() { return taxCode; }
        public double getTaxPercent() { return taxPercent; }
        public double getTaxAmount() { return taxAmount; }
        public double getSalesAmountWithTax() { return salesAmountWithTax; }
        
        public static class ReceiptTaxDataBuilder {
            private String taxCode;
            private double taxPercent;
            private double taxAmount;
            private double salesAmountWithTax;
            
            public ReceiptTaxDataBuilder taxCode(String taxCode) { this.taxCode = taxCode; return this; }
            public ReceiptTaxDataBuilder taxPercent(double taxPercent) { this.taxPercent = taxPercent; return this; }
            public ReceiptTaxDataBuilder taxAmount(double taxAmount) { this.taxAmount = taxAmount; return this; }
            public ReceiptTaxDataBuilder salesAmountWithTax(double salesAmountWithTax) { this.salesAmountWithTax = salesAmountWithTax; return this; }
            
            public ReceiptTaxData build() {
                return new ReceiptTaxData(this);
            }
        }
    }
    
    /**
     * Payment data for signature
     */
    public static class ReceiptPaymentData {
        private final int moneyTypeCode;
        private final double paymentAmount;
        
        private ReceiptPaymentData(ReceiptPaymentDataBuilder builder) {
            this.moneyTypeCode = builder.moneyTypeCode;
            this.paymentAmount = builder.paymentAmount;
        }
        
        public static ReceiptPaymentDataBuilder builder() {
            return new ReceiptPaymentDataBuilder();
        }
        
        // Getters
        public int getMoneyTypeCode() { return moneyTypeCode; }
        public double getPaymentAmount() { return paymentAmount; }
        
        public static class ReceiptPaymentDataBuilder {
            private int moneyTypeCode;
            private double paymentAmount;
            
            public ReceiptPaymentDataBuilder moneyTypeCode(int moneyTypeCode) { this.moneyTypeCode = moneyTypeCode; return this; }
            public ReceiptPaymentDataBuilder paymentAmount(double paymentAmount) { this.paymentAmount = paymentAmount; return this; }
            
            public ReceiptPaymentData build() {
                return new ReceiptPaymentData(this);
            }
        }
    }
    
    /**
     * Fiscal day report data for signature generation
     */
    public static class FiscalDayReportData {
        private final int deviceId;
        private final int fiscalDayNo;
        private final String fiscalDayOpened;
        private final int receiptCounter;
        private final Map<String, Integer> receiptCounterByType;
        private final double totalAmount;
        private final double totalTax;
        private final List<TaxRateTotalData> totalsByTaxRate;
        
        private FiscalDayReportData(FiscalDayReportDataBuilder builder) {
            this.deviceId = builder.deviceId;
            this.fiscalDayNo = builder.fiscalDayNo;
            this.fiscalDayOpened = builder.fiscalDayOpened;
            this.receiptCounter = builder.receiptCounter;
            this.receiptCounterByType = builder.receiptCounterByType;
            this.totalAmount = builder.totalAmount;
            this.totalTax = builder.totalTax;
            this.totalsByTaxRate = builder.totalsByTaxRate;
        }
        
        public static FiscalDayReportDataBuilder builder() {
            return new FiscalDayReportDataBuilder();
        }
        
        // Getters
        public int getDeviceId() { return deviceId; }
        public int getFiscalDayNo() { return fiscalDayNo; }
        public String getFiscalDayOpened() { return fiscalDayOpened; }
        public int getReceiptCounter() { return receiptCounter; }
        public Map<String, Integer> getReceiptCounterByType() { return receiptCounterByType; }
        public double getTotalAmount() { return totalAmount; }
        public double getTotalTax() { return totalTax; }
        public List<TaxRateTotalData> getTotalsByTaxRate() { return totalsByTaxRate; }
        
        public static class FiscalDayReportDataBuilder {
            private int deviceId;
            private int fiscalDayNo;
            private String fiscalDayOpened;
            private int receiptCounter;
            private Map<String, Integer> receiptCounterByType = new HashMap<>();
            private double totalAmount;
            private double totalTax;
            private List<TaxRateTotalData> totalsByTaxRate = new ArrayList<>();
            
            public FiscalDayReportDataBuilder deviceId(int deviceId) { this.deviceId = deviceId; return this; }
            public FiscalDayReportDataBuilder fiscalDayNo(int fiscalDayNo) { this.fiscalDayNo = fiscalDayNo; return this; }
            public FiscalDayReportDataBuilder fiscalDayOpened(String fiscalDayOpened) { this.fiscalDayOpened = fiscalDayOpened; return this; }
            public FiscalDayReportDataBuilder receiptCounter(int receiptCounter) { this.receiptCounter = receiptCounter; return this; }
            public FiscalDayReportDataBuilder receiptCounterByType(Map<String, Integer> receiptCounterByType) { this.receiptCounterByType = receiptCounterByType; return this; }
            public FiscalDayReportDataBuilder totalAmount(double totalAmount) { this.totalAmount = totalAmount; return this; }
            public FiscalDayReportDataBuilder totalTax(double totalTax) { this.totalTax = totalTax; return this; }
            public FiscalDayReportDataBuilder totalsByTaxRate(List<TaxRateTotalData> totalsByTaxRate) { this.totalsByTaxRate = totalsByTaxRate; return this; }
            
            public FiscalDayReportData build() {
                return new FiscalDayReportData(this);
            }
        }
    }
    
    /**
     * Tax rate total data for fiscal day signature
     */
    public static class TaxRateTotalData {
        private final double taxPercent;
        private final double taxAmount;
        private final Double salesAmount;
        
        private TaxRateTotalData(TaxRateTotalDataBuilder builder) {
            this.taxPercent = builder.taxPercent;
            this.taxAmount = builder.taxAmount;
            this.salesAmount = builder.salesAmount;
        }
        
        public static TaxRateTotalDataBuilder builder() {
            return new TaxRateTotalDataBuilder();
        }
        
        // Getters
        public double getTaxPercent() { return taxPercent; }
        public double getTaxAmount() { return taxAmount; }
        public Double getSalesAmount() { return salesAmount; }
        
        public static class TaxRateTotalDataBuilder {
            private double taxPercent;
            private double taxAmount;
            private Double salesAmount;
            
            public TaxRateTotalDataBuilder taxPercent(double taxPercent) { this.taxPercent = taxPercent; return this; }
            public TaxRateTotalDataBuilder taxAmount(double taxAmount) { this.taxAmount = taxAmount; return this; }
            public TaxRateTotalDataBuilder salesAmount(Double salesAmount) { this.salesAmount = salesAmount; return this; }
            
            public TaxRateTotalData build() {
                return new TaxRateTotalData(this);
            }
        }
    }
    
    /**
     * Signature result containing the signature and metadata
     */
    public static class SignatureResult {
        private final String signature;
        private final String dataString;
        private final String hash;
        private final Instant timestamp;
        private final String algorithm;
        
        public SignatureResult(String signature, String dataString, String hash, Instant timestamp, String algorithm) {
            this.signature = signature;
            this.dataString = dataString;
            this.hash = hash;
            this.timestamp = timestamp;
            this.algorithm = algorithm;
        }
        
        // Getters
        public String getSignature() { return signature; }
        public String getDataString() { return dataString; }
        public String getHash() { return hash; }
        public Instant getTimestamp() { return timestamp; }
        public String getAlgorithm() { return algorithm; }
    }
    
    /**
     * Signature verification result
     */
    public static class VerificationResult {
        private final boolean valid;
        private final String error;
        private final String dataString;
        
        public VerificationResult(boolean valid, String error, String dataString) {
            this.valid = valid;
            this.error = error;
            this.dataString = dataString;
        }
        
        // Getters
        public boolean isValid() { return valid; }
        public String getError() { return error; }
        public String getDataString() { return dataString; }
    }
}
