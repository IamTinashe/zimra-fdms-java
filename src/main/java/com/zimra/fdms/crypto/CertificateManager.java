package com.zimra.fdms.crypto;

import com.zimra.fdms.exception.FdmsException;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * X.509 certificate management for ZIMRA FDMS integration.
 * 
 * <p>Handles certificate loading, validation, CSR generation, and storage.
 * Features:
 * <ul>
 *   <li>Load certificates from PEM/DER formats</li>
 *   <li>Load private keys with optional password protection</li>
 *   <li>Generate RSA key pairs</li>
 *   <li>Generate Certificate Signing Requests (CSRs)</li>
 *   <li>Validate certificate expiry and chain</li>
 *   <li>Secure certificate/key storage</li>
 * </ul>
 * 
 * <p>Example usage:
 * <pre>{@code
 * CertificateManager manager = new CertificateManager();
 * 
 * // Load existing certificate
 * X509Certificate cert = manager.loadCertificate("./cert.pem");
 * PrivateKey key = manager.loadPrivateKey("./key.pem", "password");
 * 
 * // Generate new key pair and CSR
 * KeyPair keyPair = manager.generateKeyPair();
 * byte[] csr = manager.generateCsr(CsrOptions.builder()
 *     .commonName("DEVICE123")
 *     .organization("My Company")
 *     .country("ZW")
 *     .build());
 * }</pre>
 * 
 * @since 1.0.0
 */
public class CertificateManager {
    
    /** Default RSA key size in bits */
    public static final int DEFAULT_KEY_SIZE = 4096;
    
    /** Minimum RSA key size in bits for FDMS compliance */
    public static final int MIN_KEY_SIZE = 2048;
    
    /** Default public exponent */
    public static final int DEFAULT_PUBLIC_EXPONENT = 65537;
    
    /** Default days before expiry to start warning */
    public static final int DEFAULT_EXPIRY_WARNING_DAYS = 30;
    
    /** Default file permissions for certificates (644) */
    private static final Set<PosixFilePermission> CERT_FILE_PERMISSIONS = EnumSet.of(
        PosixFilePermission.OWNER_READ,
        PosixFilePermission.OWNER_WRITE,
        PosixFilePermission.GROUP_READ,
        PosixFilePermission.OTHERS_READ
    );
    
    /** Default file permissions for private keys (600) */
    private static final Set<PosixFilePermission> KEY_FILE_PERMISSIONS = EnumSet.of(
        PosixFilePermission.OWNER_READ,
        PosixFilePermission.OWNER_WRITE
    );
    
    private static final String RSA_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    
    private X509Certificate certificate;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private final int expiryWarningDays;
    
    /**
     * Creates a new CertificateManager with default expiry warning days.
     */
    public CertificateManager() {
        this(DEFAULT_EXPIRY_WARNING_DAYS);
    }
    
    /**
     * Creates a new CertificateManager with custom expiry warning days.
     * 
     * @param expiryWarningDays days before expiry to trigger warning
     */
    public CertificateManager(int expiryWarningDays) {
        this.expiryWarningDays = expiryWarningDays;
    }
    
    /**
     * Load an X.509 certificate from file path or content.
     * Supports both PEM and DER formats.
     * 
     * @param certificateInput file path or certificate content (String or byte[])
     * @return loaded X509Certificate
     * @throws FdmsException if certificate loading fails
     */
    public X509Certificate loadCertificate(String certificateInput) throws FdmsException {
        try {
            byte[] certData = resolveCertificateInput(certificateInput);
            certData = normalizeCertificateData(certData);
            
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            certificate = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(certData)
            );
            publicKey = certificate.getPublicKey();
            
            return certificate;
        } catch (CertificateException e) {
            throw new FdmsException(
                "Failed to load certificate: " + e.getMessage(),
                "CRYPTO01"
            );
        } catch (IOException e) {
            throw new FdmsException(
                "Failed to read certificate: " + e.getMessage(),
                "CRYPTO01"
            );
        }
    }
    
    /**
     * Load an X.509 certificate from byte array.
     * 
     * @param certificateData certificate bytes
     * @return loaded X509Certificate
     * @throws FdmsException if certificate loading fails
     */
    public X509Certificate loadCertificate(byte[] certificateData) throws FdmsException {
        try {
            byte[] certData = normalizeCertificateData(certificateData);
            
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            certificate = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(certData)
            );
            publicKey = certificate.getPublicKey();
            
            return certificate;
        } catch (CertificateException e) {
            throw new FdmsException(
                "Failed to load certificate: " + e.getMessage(),
                "CRYPTO01"
            );
        }
    }
    
    /**
     * Load a private key from file path or content.
     * Supports PEM and DER formats with optional password protection.
     * 
     * @param keyInput file path or key content
     * @param password password for encrypted private keys (null for unencrypted)
     * @return loaded PrivateKey
     * @throws FdmsException if private key loading fails
     */
    public PrivateKey loadPrivateKey(String keyInput, String password) throws FdmsException {
        try {
            byte[] keyData = resolveKeyInput(keyInput);
            privateKey = parsePrivateKey(keyData, password);
            
            // Validate key type (must be RSA for FDMS)
            if (!RSA_ALGORITHM.equals(privateKey.getAlgorithm())) {
                throw new FdmsException(
                    "Unsupported key type: " + privateKey.getAlgorithm() + 
                    ". Only RSA keys are supported.",
                    "CRYPTO03"
                );
            }
            
            return privateKey;
        } catch (FdmsException e) {
            throw e;
        } catch (Exception e) {
            if (e.getMessage() != null && 
                (e.getMessage().contains("password") || e.getMessage().contains("decrypt"))) {
                throw new FdmsException("Invalid private key password", "CRYPTO02");
            }
            throw new FdmsException(
                "Failed to load private key: " + e.getMessage(),
                "CRYPTO03"
            );
        }
    }
    
    /**
     * Load a private key from byte array.
     * 
     * @param keyData key bytes
     * @param password password for encrypted private keys
     * @return loaded PrivateKey
     * @throws FdmsException if private key loading fails
     */
    public PrivateKey loadPrivateKey(byte[] keyData, String password) throws FdmsException {
        try {
            privateKey = parsePrivateKey(keyData, password);
            
            if (!RSA_ALGORITHM.equals(privateKey.getAlgorithm())) {
                throw new FdmsException(
                    "Unsupported key type: " + privateKey.getAlgorithm() + 
                    ". Only RSA keys are supported.",
                    "CRYPTO03"
                );
            }
            
            return privateKey;
        } catch (FdmsException e) {
            throw e;
        } catch (Exception e) {
            throw new FdmsException(
                "Failed to load private key: " + e.getMessage(),
                "CRYPTO03"
            );
        }
    }
    
    /**
     * Generate a new RSA key pair.
     * 
     * @return generated KeyPair
     * @throws FdmsException if key generation fails
     */
    public KeyPair generateKeyPair() throws FdmsException {
        return generateKeyPair(DEFAULT_KEY_SIZE);
    }
    
    /**
     * Generate a new RSA key pair with specified key size.
     * 
     * @param keySize key size in bits (minimum 2048)
     * @return generated KeyPair
     * @throws FdmsException if key generation fails or key size is invalid
     */
    public KeyPair generateKeyPair(int keySize) throws FdmsException {
        if (keySize < MIN_KEY_SIZE) {
            throw new FdmsException(
                "Key size must be at least " + MIN_KEY_SIZE + " bits for FDMS compliance",
                "CRYPTO04"
            );
        }
        
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
            keyGen.initialize(keySize);
            KeyPair keyPair = keyGen.generateKeyPair();
            
            this.publicKey = keyPair.getPublic();
            this.privateKey = keyPair.getPrivate();
            
            return keyPair;
        } catch (NoSuchAlgorithmException e) {
            throw new FdmsException(
                "Failed to generate key pair: " + e.getMessage(),
                "CRYPTO05"
            );
        }
    }
    
    /**
     * Generate a Certificate Signing Request (CSR) for FDMS device registration.
     * 
     * @param options CSR options including subject DN components
     * @return CSR in PEM format
     * @throws FdmsException if CSR generation fails
     */
    public byte[] generateCsr(CsrOptions options) throws FdmsException {
        return generateCsr(options, this.privateKey);
    }
    
    /**
     * Generate a Certificate Signing Request (CSR) with a specific private key.
     * 
     * @param options CSR options including subject DN components
     * @param privateKey private key to sign the CSR
     * @return CSR in PEM format
     * @throws FdmsException if CSR generation fails
     */
    public byte[] generateCsr(CsrOptions options, PrivateKey privateKey) throws FdmsException {
        if (privateKey == null) {
            throw new FdmsException(
                "No private key available. Load or generate a private key first.",
                "CRYPTO07"
            );
        }
        
        if (options.getCommonName() == null || options.getCommonName().isEmpty()) {
            throw new FdmsException(
                "Common Name (CN) is required for CSR generation",
                "CRYPTO08"
            );
        }
        
        try {
            // Build subject DN
            StringBuilder subjectBuilder = new StringBuilder();
            if (options.getCountry() != null && !options.getCountry().isEmpty()) {
                subjectBuilder.append("C=").append(options.getCountry()).append(",");
            }
            if (options.getState() != null && !options.getState().isEmpty()) {
                subjectBuilder.append("ST=").append(options.getState()).append(",");
            }
            if (options.getLocality() != null && !options.getLocality().isEmpty()) {
                subjectBuilder.append("L=").append(options.getLocality()).append(",");
            }
            if (options.getOrganization() != null && !options.getOrganization().isEmpty()) {
                subjectBuilder.append("O=").append(options.getOrganization()).append(",");
            }
            if (options.getOrganizationalUnit() != null && !options.getOrganizationalUnit().isEmpty()) {
                subjectBuilder.append("OU=").append(options.getOrganizationalUnit()).append(",");
            }
            subjectBuilder.append("CN=").append(options.getCommonName());
            
            String subjectDN = subjectBuilder.toString();
            
            // Create CSR using PKCS#10 structure
            return createPkcs10Csr(subjectDN, privateKey);
            
        } catch (Exception e) {
            throw new FdmsException(
                "Failed to generate CSR: " + e.getMessage(),
                "CRYPTO09"
            );
        }
    }
    
    /**
     * Get detailed information about the loaded certificate.
     * 
     * @return certificate information
     * @throws FdmsException if no certificate is loaded
     */
    public CertificateInfo getCertificateInfo() throws FdmsException {
        if (certificate == null) {
            throw new FdmsException(
                "No certificate loaded. Load a certificate first.",
                "CRYPTO10"
            );
        }
        
        Instant now = Instant.now();
        Instant validFrom = certificate.getNotBefore().toInstant();
        Instant validTo = certificate.getNotAfter().toInstant();
        long daysUntilExpiry = ChronoUnit.DAYS.between(now, validTo);
        
        return CertificateInfo.builder()
            .subject(parseDistinguishedName(certificate.getSubjectX500Principal()))
            .issuer(parseDistinguishedName(certificate.getIssuerX500Principal()))
            .serialNumber(certificate.getSerialNumber().toString(16).toUpperCase())
            .validFrom(Date.from(validFrom))
            .validTo(Date.from(validTo))
            .daysUntilExpiry((int) daysUntilExpiry)
            .valid(!now.isBefore(validFrom) && !now.isAfter(validTo))
            .expired(now.isAfter(validTo))
            .expiresWithinWarningPeriod(daysUntilExpiry <= expiryWarningDays)
            .fingerprintSha256(getFingerprint(certificate))
            .publicKeyAlgorithm(certificate.getPublicKey().getAlgorithm())
            .keySize(getKeySize(certificate.getPublicKey()))
            .build();
    }
    
    /**
     * Validate the loaded certificate.
     * Checks expiry, key size, and algorithm requirements.
     * 
     * @return validation result with any issues found
     */
    public ValidationResult validateCertificate() {
        List<String> issues = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        
        if (certificate == null) {
            issues.add("No certificate loaded");
            return new ValidationResult(false, issues, warnings);
        }
        
        try {
            CertificateInfo info = getCertificateInfo();
            
            // Check if expired
            if (info.isExpired()) {
                issues.add("Certificate expired on " + info.getValidTo());
            }
            
            // Check if not yet valid
            Instant now = Instant.now();
            if (now.isBefore(info.getValidFrom().toInstant())) {
                issues.add("Certificate not yet valid. Valid from " + info.getValidFrom());
            }
            
            // Check expiry warning
            if (!info.isExpired() && info.isExpiresWithinWarningPeriod()) {
                warnings.add("Certificate expires in " + info.getDaysUntilExpiry() + 
                    " days (" + info.getValidTo() + ")");
            }
            
            // Check key algorithm
            if (!RSA_ALGORITHM.equals(info.getPublicKeyAlgorithm())) {
                issues.add("Unsupported key algorithm: " + info.getPublicKeyAlgorithm() + 
                    ". Only RSA is supported.");
            }
            
            // Check key size
            if (info.getKeySize() < MIN_KEY_SIZE) {
                issues.add("Key size " + info.getKeySize() + 
                    " bits is below minimum requirement of " + MIN_KEY_SIZE + " bits");
            }
            
            // Warn if key size is less than recommended
            if (info.getKeySize() >= MIN_KEY_SIZE && info.getKeySize() < DEFAULT_KEY_SIZE) {
                warnings.add("Key size " + info.getKeySize() + 
                    " bits is acceptable but " + DEFAULT_KEY_SIZE + " bits is recommended");
            }
            
        } catch (FdmsException e) {
            issues.add(e.getMessage());
        }
        
        return new ValidationResult(issues.isEmpty(), issues, warnings);
    }
    
    /**
     * Verify that the loaded private key matches the loaded certificate.
     * 
     * @return true if key pair matches
     * @throws FdmsException if certificate or private key not loaded
     */
    public boolean verifyKeyPairMatch() throws FdmsException {
        if (certificate == null || privateKey == null) {
            throw new FdmsException(
                "Both certificate and private key must be loaded to verify match",
                "CRYPTO11"
            );
        }
        
        try {
            // Create a test message and sign/verify to confirm key match
            byte[] testData = new byte[32];
            new SecureRandom().nextBytes(testData);
            
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(privateKey);
            signature.update(testData);
            byte[] sig = signature.sign();
            
            signature.initVerify(certificate.getPublicKey());
            signature.update(testData);
            return signature.verify(sig);
            
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Store certificate to file with proper permissions.
     * 
     * @param filePath destination file path
     * @param pemFormat true for PEM format, false for DER
     * @throws FdmsException if storage fails
     */
    public void storeCertificate(String filePath, boolean pemFormat) throws FdmsException {
        storeCertificate(filePath, this.certificate, pemFormat);
    }
    
    /**
     * Store a certificate to file with proper permissions.
     * 
     * @param filePath destination file path
     * @param certificate certificate to store
     * @param pemFormat true for PEM format, false for DER
     * @throws FdmsException if storage fails
     */
    public void storeCertificate(String filePath, X509Certificate certificate, boolean pemFormat) 
            throws FdmsException {
        if (certificate == null) {
            throw new FdmsException(
                "No certificate to store. Load or provide a certificate.",
                "CRYPTO12"
            );
        }
        
        try {
            Path path = Paths.get(filePath);
            Files.createDirectories(path.getParent());
            
            byte[] content;
            if (pemFormat) {
                content = encodeToPem(certificate.getEncoded(), "CERTIFICATE");
            } else {
                content = certificate.getEncoded();
            }
            
            Files.write(path, content);
            setFilePermissions(path, CERT_FILE_PERMISSIONS);
            
        } catch (CertificateEncodingException e) {
            throw new FdmsException(
                "Failed to encode certificate: " + e.getMessage(),
                "CRYPTO13"
            );
        } catch (IOException e) {
            throw new FdmsException(
                "Failed to store certificate: " + e.getMessage(),
                "CRYPTO13"
            );
        }
    }
    
    /**
     * Store private key to file with secure permissions (0600).
     * 
     * @param filePath destination file path
     * @param password optional password to encrypt the key
     * @throws FdmsException if storage fails
     */
    public void storePrivateKey(String filePath, String password) throws FdmsException {
        storePrivateKey(filePath, this.privateKey, password);
    }
    
    /**
     * Store a private key to file with secure permissions (0600).
     * 
     * @param filePath destination file path
     * @param privateKey private key to store
     * @param password optional password to encrypt the key
     * @throws FdmsException if storage fails
     */
    public void storePrivateKey(String filePath, PrivateKey privateKey, String password) 
            throws FdmsException {
        if (privateKey == null) {
            throw new FdmsException(
                "No private key to store. Load or provide a private key.",
                "CRYPTO14"
            );
        }
        
        try {
            Path path = Paths.get(filePath);
            Files.createDirectories(path.getParent());
            
            byte[] keyData;
            if (password != null && !password.isEmpty()) {
                // Encrypt the private key with password using PKCS#8
                keyData = encryptPrivateKey(privateKey, password);
            } else {
                keyData = privateKey.getEncoded();
            }
            
            byte[] pemContent = encodeToPem(keyData, 
                password != null ? "ENCRYPTED PRIVATE KEY" : "PRIVATE KEY");
            
            Files.write(path, pemContent);
            setFilePermissions(path, KEY_FILE_PERMISSIONS);
            
        } catch (IOException e) {
            throw new FdmsException(
                "Failed to store private key: " + e.getMessage(),
                "CRYPTO15"
            );
        }
    }
    
    /**
     * Export public key in PEM format.
     * 
     * @return public key in PEM format
     * @throws FdmsException if no public key available
     */
    public byte[] exportPublicKey() throws FdmsException {
        if (publicKey == null) {
            throw new FdmsException(
                "No public key available. Load a certificate or generate a key pair.",
                "CRYPTO16"
            );
        }
        
        return encodeToPem(publicKey.getEncoded(), "PUBLIC KEY");
    }
    
    /**
     * Export private key in PEM format.
     * 
     * @param password optional password to encrypt the key
     * @return private key in PEM format
     * @throws FdmsException if no private key available
     */
    public byte[] exportPrivateKey(String password) throws FdmsException {
        if (privateKey == null) {
            throw new FdmsException(
                "No private key available. Load or generate a private key.",
                "CRYPTO17"
            );
        }
        
        byte[] keyData;
        if (password != null && !password.isEmpty()) {
            keyData = encryptPrivateKey(privateKey, password);
            return encodeToPem(keyData, "ENCRYPTED PRIVATE KEY");
        } else {
            return encodeToPem(privateKey.getEncoded(), "PRIVATE KEY");
        }
    }
    
    /**
     * Get the loaded certificate.
     * 
     * @return loaded certificate or null
     */
    public X509Certificate getCertificate() {
        return certificate;
    }
    
    /**
     * Get the loaded private key.
     * 
     * @return loaded private key or null
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }
    
    /**
     * Get the public key (from certificate or generated key pair).
     * 
     * @return public key or null
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }
    
    /**
     * Check if certificate needs renewal (within warning period).
     * 
     * @return true if certificate is expired or expires soon
     */
    public boolean needsRenewal() {
        if (certificate == null) {
            return false;
        }
        
        try {
            CertificateInfo info = getCertificateInfo();
            return info.isExpired() || info.isExpiresWithinWarningPeriod();
        } catch (FdmsException e) {
            return false;
        }
    }
    
    /**
     * Clear all loaded certificates and keys from memory.
     */
    public void clear() {
        this.certificate = null;
        this.privateKey = null;
        this.publicKey = null;
    }
    
    // ============ Private Helper Methods ============
    
    private byte[] resolveCertificateInput(String input) throws IOException {
        // Check if it's a file path
        if (isFilePath(input)) {
            return Files.readAllBytes(Paths.get(input));
        }
        
        // Assume it's certificate content
        return input.getBytes(StandardCharsets.UTF_8);
    }
    
    private byte[] resolveKeyInput(String input) throws IOException {
        // Check if it's a file path
        if (isFilePath(input)) {
            return Files.readAllBytes(Paths.get(input));
        }
        
        // Assume it's key content
        return input.getBytes(StandardCharsets.UTF_8);
    }
    
    private boolean isFilePath(String input) {
        // Check for PEM headers
        if (input.contains("-----BEGIN")) {
            return false;
        }
        
        // Check for common file extensions
        String[] extensions = {".pem", ".der", ".crt", ".cer", ".key", ".p8", ".pkcs8"};
        String lowerInput = input.toLowerCase();
        for (String ext : extensions) {
            if (lowerInput.endsWith(ext)) {
                return true;
            }
        }
        
        // Check if file exists
        return Files.exists(Paths.get(input));
    }
    
    private byte[] normalizeCertificateData(byte[] data) {
        String str = new String(data, StandardCharsets.UTF_8);
        
        // If it's PEM format, extract the base64 content
        if (str.contains("-----BEGIN CERTIFICATE-----")) {
            return data;
        }
        
        // If it looks like base64 without headers, wrap it
        if (str.trim().matches("[A-Za-z0-9+/=\\s]+")) {
            String base64 = str.replaceAll("\\s", "");
            return ("-----BEGIN CERTIFICATE-----\n" + base64 + "\n-----END CERTIFICATE-----")
                .getBytes(StandardCharsets.UTF_8);
        }
        
        // Assume DER format
        return data;
    }
    
    private PrivateKey parsePrivateKey(byte[] keyData, String password) 
            throws Exception {
        String keyStr = new String(keyData, StandardCharsets.UTF_8);
        
        // Check if PEM format
        if (keyStr.contains("-----BEGIN")) {
            // Remove PEM headers and decode base64
            String base64Key = keyStr
                .replaceAll("-----BEGIN[^-]*-----", "")
                .replaceAll("-----END[^-]*-----", "")
                .replaceAll("\\s", "");
            
            byte[] derKey = Base64.getDecoder().decode(base64Key);
            
            if (keyStr.contains("ENCRYPTED")) {
                // Handle encrypted PKCS#8 key
                return decryptPrivateKey(derKey, password);
            } else {
                // Handle unencrypted PKCS#8 key
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(derKey);
                KeyFactory kf = KeyFactory.getInstance(RSA_ALGORITHM);
                return kf.generatePrivate(spec);
            }
        } else {
            // Assume DER format
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyData);
            KeyFactory kf = KeyFactory.getInstance(RSA_ALGORITHM);
            return kf.generatePrivate(spec);
        }
    }
    
    private PrivateKey decryptPrivateKey(byte[] encryptedKey, String password) 
            throws Exception {
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password required for encrypted key");
        }
        
        // Use Java's EncryptedPrivateKeyInfo
        javax.crypto.EncryptedPrivateKeyInfo epki = 
            new javax.crypto.EncryptedPrivateKeyInfo(encryptedKey);
        
        javax.crypto.SecretKeyFactory skf = 
            javax.crypto.SecretKeyFactory.getInstance(epki.getAlgName());
        javax.crypto.spec.PBEKeySpec pbeSpec = 
            new javax.crypto.spec.PBEKeySpec(password.toCharArray());
        javax.crypto.SecretKey pbeKey = skf.generateSecret(pbeSpec);
        
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(epki.getAlgName());
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, pbeKey, epki.getAlgParameters());
        
        PKCS8EncodedKeySpec spec = epki.getKeySpec(cipher);
        KeyFactory kf = KeyFactory.getInstance(RSA_ALGORITHM);
        return kf.generatePrivate(spec);
    }
    
    private byte[] encryptPrivateKey(PrivateKey key, String password) {
        try {
            // Use PBE with SHA1 and 3DES (PKCS#8 compatible)
            String algorithm = "PBEWithSHA1AndDESede";
            
            javax.crypto.spec.PBEKeySpec pbeSpec = 
                new javax.crypto.spec.PBEKeySpec(password.toCharArray());
            javax.crypto.SecretKeyFactory skf = 
                javax.crypto.SecretKeyFactory.getInstance(algorithm);
            javax.crypto.SecretKey pbeKey = skf.generateSecret(pbeSpec);
            
            // Generate salt and iteration count
            byte[] salt = new byte[8];
            new SecureRandom().nextBytes(salt);
            int iterationCount = 2048;
            
            javax.crypto.spec.PBEParameterSpec pbeParamSpec = 
                new javax.crypto.spec.PBEParameterSpec(salt, iterationCount);
            
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(algorithm);
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);
            
            byte[] encryptedKey = cipher.doFinal(key.getEncoded());
            
            // Create EncryptedPrivateKeyInfo
            AlgorithmParameters algParams = AlgorithmParameters.getInstance(algorithm);
            algParams.init(pbeParamSpec);
            
            javax.crypto.EncryptedPrivateKeyInfo epki = 
                new javax.crypto.EncryptedPrivateKeyInfo(algParams, encryptedKey);
            
            return epki.getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Failed to encrypt private key", e);
        }
    }
    
    private byte[] createPkcs10Csr(String subjectDN, PrivateKey privateKey) throws Exception {
        // Get public key from private key
        KeyFactory kf = KeyFactory.getInstance(RSA_ALGORITHM);
        java.security.spec.RSAPrivateCrtKeySpec privSpec = 
            kf.getKeySpec(privateKey, java.security.spec.RSAPrivateCrtKeySpec.class);
        java.security.spec.RSAPublicKeySpec pubSpec = 
            new java.security.spec.RSAPublicKeySpec(
                privSpec.getModulus(), 
                privSpec.getPublicExponent()
            );
        PublicKey publicKey = kf.generatePublic(pubSpec);
        
        // Build CSR using ASN.1 structure
        X500Principal subject = new X500Principal(subjectDN);
        
        // CSR Info: version, subject, public key, attributes
        byte[] csrInfo = buildCsrInfo(subject, publicKey);
        
        // Sign CSR Info
        Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
        sig.initSign(privateKey);
        sig.update(csrInfo);
        byte[] signature = sig.sign();
        
        // Build final CSR structure
        byte[] csr = buildCsr(csrInfo, signature);
        
        // Encode to PEM
        return encodeToPem(csr, "CERTIFICATE REQUEST");
    }
    
    private byte[] buildCsrInfo(X500Principal subject, PublicKey publicKey) {
        // This builds a simplified PKCS#10 CSR info structure
        // For production, consider using Bouncy Castle
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        try {
            // Version (0)
            baos.write(new byte[]{0x02, 0x01, 0x00});
            
            // Subject
            byte[] subjectBytes = subject.getEncoded();
            baos.write(subjectBytes);
            
            // Public Key Info
            byte[] pubKeyBytes = publicKey.getEncoded();
            baos.write(pubKeyBytes);
            
            // Attributes (empty)
            baos.write(new byte[]{(byte) 0xa0, 0x00});
            
            // Wrap in SEQUENCE
            byte[] content = baos.toByteArray();
            return wrapInSequence(content);
            
        } catch (IOException e) {
            throw new RuntimeException("Failed to build CSR info", e);
        }
    }
    
    private byte[] buildCsr(byte[] csrInfo, byte[] signature) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        try {
            // CSR Info
            baos.write(csrInfo);
            
            // Signature Algorithm (SHA256withRSA)
            byte[] sigAlg = new byte[]{
                0x30, 0x0d,  // SEQUENCE
                0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7,
                0x0d, 0x01, 0x01, 0x0b,  // OID: sha256WithRSAEncryption
                0x05, 0x00  // NULL
            };
            baos.write(sigAlg);
            
            // Signature as BIT STRING
            byte[] sigBitString = new byte[signature.length + 4];
            sigBitString[0] = 0x03;  // BIT STRING tag
            int sigLen = signature.length + 1;
            if (sigLen < 128) {
                sigBitString[1] = (byte) sigLen;
                sigBitString[2] = 0x00;  // unused bits
                System.arraycopy(signature, 0, sigBitString, 3, signature.length);
                baos.write(sigBitString, 0, signature.length + 3);
            } else {
                baos.write(0x03);  // BIT STRING tag
                baos.write(0x82);  // length in 2 bytes
                baos.write((sigLen >> 8) & 0xff);
                baos.write(sigLen & 0xff);
                baos.write(0x00);  // unused bits
                baos.write(signature);
            }
            
            // Wrap in SEQUENCE
            byte[] content = baos.toByteArray();
            return wrapInSequence(content);
            
        } catch (IOException e) {
            throw new RuntimeException("Failed to build CSR", e);
        }
    }
    
    private byte[] wrapInSequence(byte[] content) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        try {
            baos.write(0x30);  // SEQUENCE tag
            
            int len = content.length;
            if (len < 128) {
                baos.write(len);
            } else if (len < 256) {
                baos.write(0x81);
                baos.write(len);
            } else {
                baos.write(0x82);
                baos.write((len >> 8) & 0xff);
                baos.write(len & 0xff);
            }
            
            baos.write(content);
            return baos.toByteArray();
            
        } catch (IOException e) {
            throw new RuntimeException("Failed to wrap in sequence", e);
        }
    }
    
    private byte[] encodeToPem(byte[] derData, String type) {
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(type).append("-----\n");
        
        String base64 = Base64.getEncoder().encodeToString(derData);
        // Split into 64-character lines
        for (int i = 0; i < base64.length(); i += 64) {
            sb.append(base64, i, Math.min(i + 64, base64.length()));
            sb.append("\n");
        }
        
        sb.append("-----END ").append(type).append("-----\n");
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }
    
    private CertificateSubject parseDistinguishedName(X500Principal principal) {
        String dn = principal.getName();
        CertificateSubject.Builder builder = CertificateSubject.builder();
        
        // Parse DN components
        Pattern pattern = Pattern.compile("([A-Z]+)=([^,]+)");
        Matcher matcher = pattern.matcher(dn);
        
        while (matcher.find()) {
            String key = matcher.group(1);
            String value = matcher.group(2).trim();
            
            switch (key) {
                case "CN":
                    builder.commonName(value);
                    break;
                case "O":
                    builder.organization(value);
                    break;
                case "OU":
                    builder.organizationalUnit(value);
                    break;
                case "C":
                    builder.country(value);
                    break;
                case "ST":
                    builder.state(value);
                    break;
                case "L":
                    builder.locality(value);
                    break;
            }
        }
        
        return builder.build();
    }
    
    private String getFingerprint(X509Certificate cert) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(cert.getEncoded());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02X", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "unknown";
        }
    }
    
    private int getKeySize(PublicKey publicKey) {
        if (publicKey instanceof RSAPublicKey) {
            return ((RSAPublicKey) publicKey).getModulus().bitLength();
        }
        return 0;
    }
    
    private void setFilePermissions(Path path, Set<PosixFilePermission> permissions) {
        try {
            Files.setPosixFilePermissions(path, permissions);
        } catch (UnsupportedOperationException e) {
            // Windows doesn't support POSIX permissions
        } catch (IOException e) {
            // Log warning but don't fail
        }
    }
    
    // ============ Inner Classes ============
    
    /**
     * CSR generation options.
     */
    public static class CsrOptions {
        private final String commonName;
        private final String organization;
        private final String organizationalUnit;
        private final String country;
        private final String state;
        private final String locality;
        private final String emailAddress;
        
        private CsrOptions(Builder builder) {
            this.commonName = builder.commonName;
            this.organization = builder.organization;
            this.organizationalUnit = builder.organizationalUnit;
            this.country = builder.country;
            this.state = builder.state;
            this.locality = builder.locality;
            this.emailAddress = builder.emailAddress;
        }
        
        public String getCommonName() { return commonName; }
        public String getOrganization() { return organization; }
        public String getOrganizationalUnit() { return organizationalUnit; }
        public String getCountry() { return country; }
        public String getState() { return state; }
        public String getLocality() { return locality; }
        public String getEmailAddress() { return emailAddress; }
        
        public static Builder builder() { return new Builder(); }
        
        public static class Builder {
            private String commonName;
            private String organization;
            private String organizationalUnit;
            private String country;
            private String state;
            private String locality;
            private String emailAddress;
            
            public Builder commonName(String commonName) {
                this.commonName = commonName;
                return this;
            }
            
            public Builder organization(String organization) {
                this.organization = organization;
                return this;
            }
            
            public Builder organizationalUnit(String organizationalUnit) {
                this.organizationalUnit = organizationalUnit;
                return this;
            }
            
            public Builder country(String country) {
                this.country = country;
                return this;
            }
            
            public Builder state(String state) {
                this.state = state;
                return this;
            }
            
            public Builder locality(String locality) {
                this.locality = locality;
                return this;
            }
            
            public Builder emailAddress(String emailAddress) {
                this.emailAddress = emailAddress;
                return this;
            }
            
            public CsrOptions build() {
                return new CsrOptions(this);
            }
        }
    }
    
    /**
     * Certificate subject/issuer details.
     */
    public static class CertificateSubject {
        private final String commonName;
        private final String organization;
        private final String organizationalUnit;
        private final String country;
        private final String state;
        private final String locality;
        
        private CertificateSubject(Builder builder) {
            this.commonName = builder.commonName;
            this.organization = builder.organization;
            this.organizationalUnit = builder.organizationalUnit;
            this.country = builder.country;
            this.state = builder.state;
            this.locality = builder.locality;
        }
        
        public String getCommonName() { return commonName; }
        public String getOrganization() { return organization; }
        public String getOrganizationalUnit() { return organizationalUnit; }
        public String getCountry() { return country; }
        public String getState() { return state; }
        public String getLocality() { return locality; }
        
        public static Builder builder() { return new Builder(); }
        
        public static class Builder {
            private String commonName;
            private String organization;
            private String organizationalUnit;
            private String country;
            private String state;
            private String locality;
            
            public Builder commonName(String commonName) {
                this.commonName = commonName;
                return this;
            }
            
            public Builder organization(String organization) {
                this.organization = organization;
                return this;
            }
            
            public Builder organizationalUnit(String organizationalUnit) {
                this.organizationalUnit = organizationalUnit;
                return this;
            }
            
            public Builder country(String country) {
                this.country = country;
                return this;
            }
            
            public Builder state(String state) {
                this.state = state;
                return this;
            }
            
            public Builder locality(String locality) {
                this.locality = locality;
                return this;
            }
            
            public CertificateSubject build() {
                return new CertificateSubject(this);
            }
        }
    }
    
    /**
     * Certificate information.
     */
    public static class CertificateInfo {
        private final CertificateSubject subject;
        private final CertificateSubject issuer;
        private final String serialNumber;
        private final Date validFrom;
        private final Date validTo;
        private final int daysUntilExpiry;
        private final boolean valid;
        private final boolean expired;
        private final boolean expiresWithinWarningPeriod;
        private final String fingerprintSha256;
        private final String publicKeyAlgorithm;
        private final int keySize;
        
        private CertificateInfo(Builder builder) {
            this.subject = builder.subject;
            this.issuer = builder.issuer;
            this.serialNumber = builder.serialNumber;
            this.validFrom = builder.validFrom;
            this.validTo = builder.validTo;
            this.daysUntilExpiry = builder.daysUntilExpiry;
            this.valid = builder.valid;
            this.expired = builder.expired;
            this.expiresWithinWarningPeriod = builder.expiresWithinWarningPeriod;
            this.fingerprintSha256 = builder.fingerprintSha256;
            this.publicKeyAlgorithm = builder.publicKeyAlgorithm;
            this.keySize = builder.keySize;
        }
        
        public CertificateSubject getSubject() { return subject; }
        public CertificateSubject getIssuer() { return issuer; }
        public String getSerialNumber() { return serialNumber; }
        public Date getValidFrom() { return validFrom; }
        public Date getValidTo() { return validTo; }
        public int getDaysUntilExpiry() { return daysUntilExpiry; }
        public boolean isValid() { return valid; }
        public boolean isExpired() { return expired; }
        public boolean isExpiresWithinWarningPeriod() { return expiresWithinWarningPeriod; }
        public String getFingerprintSha256() { return fingerprintSha256; }
        public String getPublicKeyAlgorithm() { return publicKeyAlgorithm; }
        public int getKeySize() { return keySize; }
        
        public static Builder builder() { return new Builder(); }
        
        public static class Builder {
            private CertificateSubject subject;
            private CertificateSubject issuer;
            private String serialNumber;
            private Date validFrom;
            private Date validTo;
            private int daysUntilExpiry;
            private boolean valid;
            private boolean expired;
            private boolean expiresWithinWarningPeriod;
            private String fingerprintSha256;
            private String publicKeyAlgorithm;
            private int keySize;
            
            public Builder subject(CertificateSubject subject) {
                this.subject = subject;
                return this;
            }
            
            public Builder issuer(CertificateSubject issuer) {
                this.issuer = issuer;
                return this;
            }
            
            public Builder serialNumber(String serialNumber) {
                this.serialNumber = serialNumber;
                return this;
            }
            
            public Builder validFrom(Date validFrom) {
                this.validFrom = validFrom;
                return this;
            }
            
            public Builder validTo(Date validTo) {
                this.validTo = validTo;
                return this;
            }
            
            public Builder daysUntilExpiry(int daysUntilExpiry) {
                this.daysUntilExpiry = daysUntilExpiry;
                return this;
            }
            
            public Builder valid(boolean valid) {
                this.valid = valid;
                return this;
            }
            
            public Builder expired(boolean expired) {
                this.expired = expired;
                return this;
            }
            
            public Builder expiresWithinWarningPeriod(boolean expiresWithinWarningPeriod) {
                this.expiresWithinWarningPeriod = expiresWithinWarningPeriod;
                return this;
            }
            
            public Builder fingerprintSha256(String fingerprintSha256) {
                this.fingerprintSha256 = fingerprintSha256;
                return this;
            }
            
            public Builder publicKeyAlgorithm(String publicKeyAlgorithm) {
                this.publicKeyAlgorithm = publicKeyAlgorithm;
                return this;
            }
            
            public Builder keySize(int keySize) {
                this.keySize = keySize;
                return this;
            }
            
            public CertificateInfo build() {
                return new CertificateInfo(this);
            }
        }
    }
    
    /**
     * Certificate validation result.
     */
    public static class ValidationResult {
        private final boolean valid;
        private final List<String> issues;
        private final List<String> warnings;
        
        public ValidationResult(boolean valid, List<String> issues, List<String> warnings) {
            this.valid = valid;
            this.issues = Collections.unmodifiableList(issues);
            this.warnings = Collections.unmodifiableList(warnings);
        }
        
        public boolean isValid() { return valid; }
        public List<String> getIssues() { return issues; }
        public List<String> getWarnings() { return warnings; }
    }
}
