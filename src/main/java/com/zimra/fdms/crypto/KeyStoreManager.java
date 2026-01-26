package com.zimra.fdms.crypto;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.zimra.fdms.exception.FdmsException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Secure key storage for ZIMRA FDMS integration.
 * 
 * <p>Provides secure storage for private keys and certificates using
 * industry-standard encryption (AES-256-GCM) and key derivation (PBKDF2).
 * 
 * <p>Features:
 * <ul>
 *   <li>AES-256-GCM encryption for private keys</li>
 *   <li>PBKDF2 key derivation with configurable iterations</li>
 *   <li>Secure file permissions (0600)</li>
 *   <li>Atomic file writes to prevent corruption</li>
 *   <li>Support for multiple key aliases</li>
 * </ul>
 * 
 * <p>Security Notes:
 * <ul>
 *   <li>Private keys are encrypted at rest</li>
 *   <li>Certificates are stored unencrypted (public data)</li>
 *   <li>Master password is never stored</li>
 *   <li>Salt is unique per key store</li>
 * </ul>
 * 
 * <p>Example usage:
 * <pre>{@code
 * KeyStoreManager keyStore = new KeyStoreManager(
 *     KeyStoreManager.Options.builder()
 *         .storePath("./keystore.json")
 *         .password("secure-password")
 *         .build()
 * );
 * 
 * keyStore.load();
 * keyStore.setKeyPair("device-123", privateKey, certificate);
 * keyStore.save();
 * }</pre>
 * 
 * @since 1.0.0
 */
public class KeyStoreManager {
    
    /** Current key store format version */
    private static final int VERSION = 1;
    
    /** Default PBKDF2 iterations */
    private static final int DEFAULT_ITERATIONS = 100000;
    
    /** AES key length in bytes */
    private static final int KEY_LENGTH = 32;
    
    /** Salt length in bytes */
    private static final int SALT_LENGTH = 32;
    
    /** GCM nonce length in bytes */
    private static final int NONCE_LENGTH = 12;
    
    /** GCM authentication tag length in bits */
    private static final int GCM_TAG_LENGTH = 128;
    
    /** Default file permissions (owner read/write only) */
    private static final Set<PosixFilePermission> FILE_PERMISSIONS = EnumSet.of(
        PosixFilePermission.OWNER_READ,
        PosixFilePermission.OWNER_WRITE
    );
    
    private final Path storePath;
    private final String password;
    private final int iterations;
    private final boolean autoSave;
    private final ObjectMapper objectMapper;
    
    private Map<String, Object> data;
    private byte[] derivedKey;
    private boolean isLoaded = false;
    
    /**
     * Creates a new KeyStoreManager with the specified options.
     * 
     * @param options key store configuration options
     * @throws FdmsException if options are invalid
     */
    public KeyStoreManager(Options options) throws FdmsException {
        if (options.getStorePath() == null || options.getStorePath().isEmpty()) {
            throw new FdmsException("Key store path is required", "CRYPTO20");
        }
        if (options.getPassword() == null || options.getPassword().isEmpty()) {
            throw new FdmsException("Key store password is required", "CRYPTO21");
        }
        if (options.getPassword().length() < 8) {
            throw new FdmsException(
                "Key store password must be at least 8 characters",
                "CRYPTO22"
            );
        }
        
        this.storePath = Paths.get(options.getStorePath()).toAbsolutePath();
        this.password = options.getPassword();
        this.iterations = options.getIterations() > 0 ? options.getIterations() : DEFAULT_ITERATIONS;
        this.autoSave = options.isAutoSave();
        this.objectMapper = new ObjectMapper();
        this.objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
    }
    
    /**
     * Load an existing key store or create a new one.
     * 
     * @throws FdmsException if key store cannot be loaded or decrypted
     */
    public void load() throws FdmsException {
        try {
            if (Files.exists(storePath)) {
                String content = new String(Files.readAllBytes(storePath), StandardCharsets.UTF_8);
                data = objectMapper.readValue(content, new TypeReference<Map<String, Object>>() {});
                
                // Validate version
                int version = ((Number) data.getOrDefault("version", 0)).intValue();
                if (version != VERSION) {
                    throw new FdmsException(
                        "Unsupported key store version: " + version,
                        "CRYPTO23"
                    );
                }
                
                // Derive encryption key from password and stored salt
                String saltHex = (String) data.get("salt");
                byte[] salt = hexToBytes(saltHex);
                derivedKey = deriveKey(password, salt);
            } else {
                // Create new key store
                byte[] salt = new byte[SALT_LENGTH];
                new SecureRandom().nextBytes(salt);
                derivedKey = deriveKey(password, salt);
                
                data = new LinkedHashMap<>();
                data.put("version", VERSION);
                data.put("salt", bytesToHex(salt));
                data.put("entries", new LinkedHashMap<String, Object>());
                
                if (autoSave) {
                    save();
                }
            }
            
            isLoaded = true;
            
        } catch (FdmsException e) {
            throw e;
        } catch (Exception e) {
            throw new FdmsException(
                "Failed to load key store: " + e.getMessage(),
                "CRYPTO23"
            );
        }
    }
    
    /**
     * Save the key store to disk.
     * Uses atomic write to prevent corruption.
     * 
     * @throws FdmsException if save fails
     */
    public void save() throws FdmsException {
        if (data == null) {
            throw new FdmsException(
                "Key store not initialized. Call load() first.",
                "CRYPTO24"
            );
        }
        
        try {
            Files.createDirectories(storePath.getParent());
            
            // Atomic write: write to temp file, then rename
            Path tempPath = storePath.resolveSibling(storePath.getFileName() + ".tmp");
            String content = objectMapper.writeValueAsString(data);
            
            Files.write(tempPath, content.getBytes(StandardCharsets.UTF_8));
            setFilePermissions(tempPath);
            Files.move(tempPath, storePath, 
                java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            
        } catch (Exception e) {
            throw new FdmsException(
                "Failed to save key store: " + e.getMessage(),
                "CRYPTO25"
            );
        }
    }
    
    /**
     * Store a private key in the key store.
     * 
     * @param alias unique identifier for the key
     * @param privateKey private key to store
     * @param overwrite whether to overwrite existing entry
     * @throws FdmsException if entry exists and overwrite is false
     */
    public void setPrivateKey(String alias, PrivateKey privateKey, boolean overwrite) 
            throws FdmsException {
        ensureLoaded();
        
        @SuppressWarnings("unchecked")
        Map<String, Object> entries = (Map<String, Object>) data.get("entries");
        
        if (!overwrite && entries.containsKey(alias)) {
            throw new FdmsException(
                "Entry with alias '" + alias + "' already exists. Set overwrite=true to replace.",
                "CRYPTO26"
            );
        }
        
        Map<String, String> encrypted = encryptPrivateKey(privateKey);
        String now = Instant.now().toString();
        
        @SuppressWarnings("unchecked")
        Map<String, Object> existing = (Map<String, Object>) entries.getOrDefault(alias, new LinkedHashMap<>());
        @SuppressWarnings("unchecked")
        Map<String, Object> existingMetadata = (Map<String, Object>) existing.getOrDefault("metadata", new LinkedHashMap<>());
        
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("encryptedPrivateKey", encrypted.get("ciphertext"));
        entry.put("privateKeyNonce", encrypted.get("nonce"));
        entry.put("certificate", existing.get("certificate"));
        
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("alias", alias);
        metadata.put("type", existing.get("certificate") != null ? "keypair" : "privateKey");
        metadata.put("createdAt", existingMetadata.getOrDefault("createdAt", now));
        metadata.put("modifiedAt", now);
        metadata.put("commonName", existingMetadata.get("commonName"));
        metadata.put("expiryDate", existingMetadata.get("expiryDate"));
        entry.put("metadata", metadata);
        
        entries.put(alias, entry);
        
        if (autoSave) {
            save();
        }
    }
    
    /**
     * Store a certificate in the key store.
     * 
     * @param alias unique identifier for the certificate
     * @param certificate X.509 certificate to store
     * @param overwrite whether to overwrite existing entry
     * @throws FdmsException if certificate exists and overwrite is false
     */
    public void setCertificate(String alias, X509Certificate certificate, boolean overwrite) 
            throws FdmsException {
        ensureLoaded();
        
        @SuppressWarnings("unchecked")
        Map<String, Object> entries = (Map<String, Object>) data.get("entries");
        
        @SuppressWarnings("unchecked")
        Map<String, Object> existing = (Map<String, Object>) entries.getOrDefault(alias, new LinkedHashMap<>());
        
        if (!overwrite && existing.get("certificate") != null) {
            throw new FdmsException(
                "Certificate with alias '" + alias + "' already exists. Set overwrite=true to replace.",
                "CRYPTO27"
            );
        }
        
        try {
            String certPem = encodeCertificateToPem(certificate);
            Map<String, String> certInfo = extractCertificateInfo(certificate);
            String now = Instant.now().toString();
            
            @SuppressWarnings("unchecked")
            Map<String, Object> existingMetadata = (Map<String, Object>) existing.getOrDefault("metadata", new LinkedHashMap<>());
            
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("encryptedPrivateKey", existing.get("encryptedPrivateKey"));
            entry.put("privateKeyNonce", existing.get("privateKeyNonce"));
            entry.put("certificate", certPem);
            
            Map<String, Object> metadata = new LinkedHashMap<>();
            metadata.put("alias", alias);
            metadata.put("type", existing.get("encryptedPrivateKey") != null ? "keypair" : "certificate");
            metadata.put("createdAt", existingMetadata.getOrDefault("createdAt", now));
            metadata.put("modifiedAt", now);
            metadata.put("commonName", certInfo.get("commonName"));
            metadata.put("expiryDate", certInfo.get("expiryDate"));
            entry.put("metadata", metadata);
            
            entries.put(alias, entry);
            
            if (autoSave) {
                save();
            }
            
        } catch (CertificateEncodingException e) {
            throw new FdmsException(
                "Failed to encode certificate: " + e.getMessage(),
                "CRYPTO27"
            );
        }
    }
    
    /**
     * Store both private key and certificate together.
     * 
     * @param alias unique identifier for the key pair
     * @param privateKey private key to store
     * @param certificate X.509 certificate to store
     * @param overwrite whether to overwrite existing entry
     * @throws FdmsException if entry exists and overwrite is false
     */
    public void setKeyPair(String alias, PrivateKey privateKey, X509Certificate certificate, 
            boolean overwrite) throws FdmsException {
        ensureLoaded();
        
        @SuppressWarnings("unchecked")
        Map<String, Object> entries = (Map<String, Object>) data.get("entries");
        
        if (!overwrite && entries.containsKey(alias)) {
            throw new FdmsException(
                "Entry with alias '" + alias + "' already exists. Set overwrite=true to replace.",
                "CRYPTO28"
            );
        }
        
        try {
            Map<String, String> encrypted = encryptPrivateKey(privateKey);
            String certPem = encodeCertificateToPem(certificate);
            Map<String, String> certInfo = extractCertificateInfo(certificate);
            String now = Instant.now().toString();
            
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("encryptedPrivateKey", encrypted.get("ciphertext"));
            entry.put("privateKeyNonce", encrypted.get("nonce"));
            entry.put("certificate", certPem);
            
            Map<String, Object> metadata = new LinkedHashMap<>();
            metadata.put("alias", alias);
            metadata.put("type", "keypair");
            metadata.put("createdAt", now);
            metadata.put("modifiedAt", now);
            metadata.put("commonName", certInfo.get("commonName"));
            metadata.put("expiryDate", certInfo.get("expiryDate"));
            entry.put("metadata", metadata);
            
            entries.put(alias, entry);
            
            if (autoSave) {
                save();
            }
            
        } catch (CertificateEncodingException e) {
            throw new FdmsException(
                "Failed to encode certificate: " + e.getMessage(),
                "CRYPTO28"
            );
        }
    }
    
    /**
     * Retrieve a private key from the key store.
     * 
     * @param alias alias of the key to retrieve
     * @return decrypted private key
     * @throws FdmsException if key not found or decryption fails
     */
    public PrivateKey getPrivateKey(String alias) throws FdmsException {
        ensureLoaded();
        
        @SuppressWarnings("unchecked")
        Map<String, Object> entries = (Map<String, Object>) data.get("entries");
        
        @SuppressWarnings("unchecked")
        Map<String, Object> entry = (Map<String, Object>) entries.get(alias);
        
        if (entry == null || entry.get("encryptedPrivateKey") == null) {
            throw new FdmsException(
                "Private key not found for alias '" + alias + "'",
                "CRYPTO29"
            );
        }
        
        return decryptPrivateKey(
            (String) entry.get("encryptedPrivateKey"),
            (String) entry.get("privateKeyNonce")
        );
    }
    
    /**
     * Retrieve a certificate from the key store.
     * 
     * @param alias alias of the certificate to retrieve
     * @return X.509 certificate
     * @throws FdmsException if certificate not found
     */
    public X509Certificate getCertificate(String alias) throws FdmsException {
        ensureLoaded();
        
        @SuppressWarnings("unchecked")
        Map<String, Object> entries = (Map<String, Object>) data.get("entries");
        
        @SuppressWarnings("unchecked")
        Map<String, Object> entry = (Map<String, Object>) entries.get(alias);
        
        if (entry == null || entry.get("certificate") == null) {
            throw new FdmsException(
                "Certificate not found for alias '" + alias + "'",
                "CRYPTO30"
            );
        }
        
        try {
            String certPem = (String) entry.get("certificate");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(certPem.getBytes(StandardCharsets.UTF_8))
            );
        } catch (CertificateException e) {
            throw new FdmsException(
                "Failed to parse certificate: " + e.getMessage(),
                "CRYPTO30"
            );
        }
    }
    
    /**
     * Check if an entry exists in the key store.
     * 
     * @param alias alias to check
     * @return true if entry exists
     */
    public boolean hasEntry(String alias) {
        ensureLoadedSilent();
        if (data == null) return false;
        
        @SuppressWarnings("unchecked")
        Map<String, Object> entries = (Map<String, Object>) data.get("entries");
        return entries.containsKey(alias);
    }
    
    /**
     * Check if a private key exists for the given alias.
     * 
     * @param alias alias to check
     * @return true if private key exists
     */
    public boolean hasPrivateKey(String alias) {
        ensureLoadedSilent();
        if (data == null) return false;
        
        @SuppressWarnings("unchecked")
        Map<String, Object> entries = (Map<String, Object>) data.get("entries");
        
        @SuppressWarnings("unchecked")
        Map<String, Object> entry = (Map<String, Object>) entries.get(alias);
        
        return entry != null && entry.get("encryptedPrivateKey") != null;
    }
    
    /**
     * Check if a certificate exists for the given alias.
     * 
     * @param alias alias to check
     * @return true if certificate exists
     */
    public boolean hasCertificate(String alias) {
        ensureLoadedSilent();
        if (data == null) return false;
        
        @SuppressWarnings("unchecked")
        Map<String, Object> entries = (Map<String, Object>) data.get("entries");
        
        @SuppressWarnings("unchecked")
        Map<String, Object> entry = (Map<String, Object>) entries.get(alias);
        
        return entry != null && entry.get("certificate") != null;
    }
    
    /**
     * Delete an entry from the key store.
     * 
     * @param alias alias of the entry to delete
     * @return true if entry was deleted, false if not found
     * @throws FdmsException if save fails
     */
    public boolean deleteEntry(String alias) throws FdmsException {
        ensureLoaded();
        
        @SuppressWarnings("unchecked")
        Map<String, Object> entries = (Map<String, Object>) data.get("entries");
        
        if (!entries.containsKey(alias)) {
            return false;
        }
        
        entries.remove(alias);
        
        if (autoSave) {
            save();
        }
        
        return true;
    }
    
    /**
     * List all entries in the key store.
     * 
     * @return list of entry metadata
     */
    public List<KeyStoreEntry> listEntries() {
        ensureLoadedSilent();
        if (data == null) return Collections.emptyList();
        
        @SuppressWarnings("unchecked")
        Map<String, Object> entries = (Map<String, Object>) data.get("entries");
        
        return entries.values().stream()
            .map(e -> {
                @SuppressWarnings("unchecked")
                Map<String, Object> entry = (Map<String, Object>) e;
                @SuppressWarnings("unchecked")
                Map<String, Object> metadata = (Map<String, Object>) entry.get("metadata");
                
                return KeyStoreEntry.builder()
                    .alias((String) metadata.get("alias"))
                    .type((String) metadata.get("type"))
                    .createdAt(Instant.parse((String) metadata.get("createdAt")))
                    .modifiedAt(Instant.parse((String) metadata.get("modifiedAt")))
                    .commonName((String) metadata.get("commonName"))
                    .expiryDate(metadata.get("expiryDate") != null 
                        ? Instant.parse((String) metadata.get("expiryDate")) 
                        : null)
                    .build();
            })
            .collect(Collectors.toList());
    }
    
    /**
     * Get entries that will expire within the specified number of days.
     * 
     * @param days number of days to check
     * @return list of entries expiring soon
     */
    public List<KeyStoreEntry> getExpiringEntries(int days) {
        Instant now = Instant.now();
        Instant threshold = now.plus(days, ChronoUnit.DAYS);
        
        return listEntries().stream()
            .filter(entry -> entry.getExpiryDate() != null && 
                !entry.getExpiryDate().isAfter(threshold))
            .collect(Collectors.toList());
    }
    
    /**
     * Change the key store password.
     * Re-encrypts all private keys with the new password.
     * 
     * @param newPassword new password (minimum 8 characters)
     * @throws FdmsException if new password is too short
     */
    public void changePassword(String newPassword) throws FdmsException {
        ensureLoaded();
        
        if (newPassword == null || newPassword.length() < 8) {
            throw new FdmsException(
                "New password must be at least 8 characters",
                "CRYPTO31"
            );
        }
        
        // Decrypt all private keys with old password
        @SuppressWarnings("unchecked")
        Map<String, Object> entries = (Map<String, Object>) data.get("entries");
        
        Map<String, PrivateKey> decryptedKeys = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : entries.entrySet()) {
            @SuppressWarnings("unchecked")
            Map<String, Object> entry = (Map<String, Object>) e.getValue();
            if (entry.get("encryptedPrivateKey") != null) {
                decryptedKeys.put(e.getKey(), decryptPrivateKey(
                    (String) entry.get("encryptedPrivateKey"),
                    (String) entry.get("privateKeyNonce")
                ));
            }
        }
        
        // Generate new salt and derive new key
        byte[] newSalt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(newSalt);
        derivedKey = deriveKey(newPassword, newSalt);
        data.put("salt", bytesToHex(newSalt));
        
        // Re-encrypt all private keys with new password
        for (Map.Entry<String, PrivateKey> e : decryptedKeys.entrySet()) {
            Map<String, String> encrypted = encryptPrivateKey(e.getValue());
            
            @SuppressWarnings("unchecked")
            Map<String, Object> entry = (Map<String, Object>) entries.get(e.getKey());
            entry.put("encryptedPrivateKey", encrypted.get("ciphertext"));
            entry.put("privateKeyNonce", encrypted.get("nonce"));
        }
        
        save();
    }
    
    /**
     * Export the key store to a new location.
     * 
     * @param exportPath path to export to
     * @param newPassword optional new password for the export (null to use same password)
     * @throws FdmsException if export fails
     */
    public void export(String exportPath, String newPassword) throws FdmsException {
        ensureLoaded();
        
        Path targetPath = Paths.get(exportPath);
        
        if (newPassword != null && !newPassword.isEmpty()) {
            // Create a temporary key store with new password
            KeyStoreManager tempStore = new KeyStoreManager(Options.builder()
                .storePath(exportPath)
                .password(newPassword)
                .iterations(iterations)
                .autoSave(false)
                .build());
            
            // Initialize with new salt
            byte[] salt = new byte[SALT_LENGTH];
            new SecureRandom().nextBytes(salt);
            tempStore.derivedKey = deriveKey(newPassword, salt);
            
            tempStore.data = new LinkedHashMap<>();
            tempStore.data.put("version", VERSION);
            tempStore.data.put("salt", bytesToHex(salt));
            tempStore.data.put("entries", new LinkedHashMap<String, Object>());
            tempStore.isLoaded = true;
            
            // Copy and re-encrypt entries
            @SuppressWarnings("unchecked")
            Map<String, Object> entries = (Map<String, Object>) data.get("entries");
            @SuppressWarnings("unchecked")
            Map<String, Object> tempEntries = (Map<String, Object>) tempStore.data.get("entries");
            
            for (Map.Entry<String, Object> e : entries.entrySet()) {
                @SuppressWarnings("unchecked")
                Map<String, Object> entry = (Map<String, Object>) e.getValue();
                Map<String, Object> newEntry = new LinkedHashMap<>(entry);
                
                if (entry.get("encryptedPrivateKey") != null) {
                    PrivateKey privateKey = decryptPrivateKey(
                        (String) entry.get("encryptedPrivateKey"),
                        (String) entry.get("privateKeyNonce")
                    );
                    Map<String, String> encrypted = tempStore.encryptPrivateKey(privateKey);
                    newEntry.put("encryptedPrivateKey", encrypted.get("ciphertext"));
                    newEntry.put("privateKeyNonce", encrypted.get("nonce"));
                }
                
                tempEntries.put(e.getKey(), newEntry);
            }
            
            tempStore.save();
        } else {
            // Simple copy with same password
            try {
                Files.createDirectories(targetPath.getParent());
                String content = objectMapper.writeValueAsString(data);
                Files.write(targetPath, content.getBytes(StandardCharsets.UTF_8));
                setFilePermissions(targetPath);
            } catch (IOException e) {
                throw new FdmsException(
                    "Failed to export key store: " + e.getMessage(),
                    "CRYPTO25"
                );
            }
        }
    }
    
    /**
     * Clear all entries from the key store.
     * 
     * @throws FdmsException if save fails
     */
    public void clear() throws FdmsException {
        ensureLoaded();
        data.put("entries", new LinkedHashMap<String, Object>());
        
        if (autoSave) {
            save();
        }
    }
    
    /**
     * Get the number of entries in the key store.
     * 
     * @return number of entries
     */
    public int size() {
        if (data == null) return 0;
        
        @SuppressWarnings("unchecked")
        Map<String, Object> entries = (Map<String, Object>) data.get("entries");
        return entries.size();
    }
    
    /**
     * Check if the key store has been loaded.
     * 
     * @return true if loaded
     */
    public boolean isLoaded() {
        return isLoaded;
    }
    
    // ============ Private Helper Methods ============
    
    private void ensureLoaded() throws FdmsException {
        if (!isLoaded || data == null || derivedKey == null) {
            throw new FdmsException(
                "Key store not loaded. Call load() first.",
                "CRYPTO32"
            );
        }
    }
    
    private void ensureLoadedSilent() {
        // Silent version for boolean checks
    }
    
    private byte[] deriveKey(String password, byte[] salt) throws FdmsException {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            KeySpec spec = new PBEKeySpec(
                password.toCharArray(),
                salt,
                iterations,
                KEY_LENGTH * 8
            );
            return factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new FdmsException(
                "Key derivation failed: " + e.getMessage(),
                "CRYPTO33"
            );
        }
    }
    
    private Map<String, String> encryptPrivateKey(PrivateKey privateKey) throws FdmsException {
        if (derivedKey == null) {
            throw new FdmsException("Encryption key not available", "CRYPTO34");
        }
        
        try {
            // Export private key to PKCS#8 format
            byte[] keyBytes = privateKey.getEncoded();
            
            // Generate random nonce
            byte[] nonce = new byte[NONCE_LENGTH];
            new SecureRandom().nextBytes(nonce);
            
            // Encrypt using AES-256-GCM
            SecretKey secretKey = new SecretKeySpec(derivedKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
            
            byte[] ciphertext = cipher.doFinal(keyBytes);
            
            Map<String, String> result = new LinkedHashMap<>();
            result.put("ciphertext", bytesToHex(ciphertext));
            result.put("nonce", bytesToHex(nonce));
            return result;
            
        } catch (Exception e) {
            throw new FdmsException(
                "Failed to encrypt private key: " + e.getMessage(),
                "CRYPTO34"
            );
        }
    }
    
    private PrivateKey decryptPrivateKey(String ciphertextHex, String nonceHex) 
            throws FdmsException {
        if (derivedKey == null) {
            throw new FdmsException("Decryption key not available", "CRYPTO35");
        }
        
        try {
            byte[] ciphertext = hexToBytes(ciphertextHex);
            byte[] nonce = hexToBytes(nonceHex);
            
            // Decrypt using AES-256-GCM
            SecretKey secretKey = new SecretKeySpec(derivedKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
            
            byte[] decrypted = cipher.doFinal(ciphertext);
            
            // Parse PKCS#8 private key
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decrypted);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
            
        } catch (Exception e) {
            throw new FdmsException(
                "Failed to decrypt private key. Invalid password or corrupted data.",
                "CRYPTO36"
            );
        }
    }
    
    private String encodeCertificateToPem(X509Certificate certificate) 
            throws CertificateEncodingException {
        byte[] encoded = certificate.getEncoded();
        String base64 = Base64.getEncoder().encodeToString(encoded);
        
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN CERTIFICATE-----\n");
        // Split into 64-character lines
        for (int i = 0; i < base64.length(); i += 64) {
            sb.append(base64, i, Math.min(i + 64, base64.length()));
            sb.append("\n");
        }
        sb.append("-----END CERTIFICATE-----\n");
        
        return sb.toString();
    }
    
    private Map<String, String> extractCertificateInfo(X509Certificate certificate) {
        Map<String, String> info = new LinkedHashMap<>();
        
        // Extract common name
        String subjectDN = certificate.getSubjectX500Principal().getName();
        java.util.regex.Pattern cnPattern = java.util.regex.Pattern.compile("CN=([^,]+)");
        java.util.regex.Matcher matcher = cnPattern.matcher(subjectDN);
        if (matcher.find()) {
            info.put("commonName", matcher.group(1).trim());
        }
        
        // Extract expiry date
        info.put("expiryDate", certificate.getNotAfter().toInstant().toString());
        
        return info;
    }
    
    private void setFilePermissions(Path path) {
        try {
            Files.setPosixFilePermissions(path, FILE_PERMISSIONS);
        } catch (UnsupportedOperationException e) {
            // Windows doesn't support POSIX permissions
        } catch (IOException e) {
            // Log warning but don't fail
        }
    }
    
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
    
    // ============ Inner Classes ============
    
    /**
     * Key store configuration options.
     */
    public static class Options {
        private final String storePath;
        private final String password;
        private final int iterations;
        private final boolean autoSave;
        
        private Options(Builder builder) {
            this.storePath = builder.storePath;
            this.password = builder.password;
            this.iterations = builder.iterations;
            this.autoSave = builder.autoSave;
        }
        
        public String getStorePath() { return storePath; }
        public String getPassword() { return password; }
        public int getIterations() { return iterations; }
        public boolean isAutoSave() { return autoSave; }
        
        public static Builder builder() { return new Builder(); }
        
        public static class Builder {
            private String storePath;
            private String password;
            private int iterations = DEFAULT_ITERATIONS;
            private boolean autoSave = true;
            
            public Builder storePath(String storePath) {
                this.storePath = storePath;
                return this;
            }
            
            public Builder password(String password) {
                this.password = password;
                return this;
            }
            
            public Builder iterations(int iterations) {
                this.iterations = iterations;
                return this;
            }
            
            public Builder autoSave(boolean autoSave) {
                this.autoSave = autoSave;
                return this;
            }
            
            public Options build() {
                return new Options(this);
            }
        }
    }
    
    /**
     * Key store entry metadata.
     */
    public static class KeyStoreEntry {
        private final String alias;
        private final String type;
        private final Instant createdAt;
        private final Instant modifiedAt;
        private final String commonName;
        private final Instant expiryDate;
        
        private KeyStoreEntry(Builder builder) {
            this.alias = builder.alias;
            this.type = builder.type;
            this.createdAt = builder.createdAt;
            this.modifiedAt = builder.modifiedAt;
            this.commonName = builder.commonName;
            this.expiryDate = builder.expiryDate;
        }
        
        public String getAlias() { return alias; }
        public String getType() { return type; }
        public Instant getCreatedAt() { return createdAt; }
        public Instant getModifiedAt() { return modifiedAt; }
        public String getCommonName() { return commonName; }
        public Instant getExpiryDate() { return expiryDate; }
        
        public static Builder builder() { return new Builder(); }
        
        public static class Builder {
            private String alias;
            private String type;
            private Instant createdAt;
            private Instant modifiedAt;
            private String commonName;
            private Instant expiryDate;
            
            public Builder alias(String alias) {
                this.alias = alias;
                return this;
            }
            
            public Builder type(String type) {
                this.type = type;
                return this;
            }
            
            public Builder createdAt(Instant createdAt) {
                this.createdAt = createdAt;
                return this;
            }
            
            public Builder modifiedAt(Instant modifiedAt) {
                this.modifiedAt = modifiedAt;
                return this;
            }
            
            public Builder commonName(String commonName) {
                this.commonName = commonName;
                return this;
            }
            
            public Builder expiryDate(Instant expiryDate) {
                this.expiryDate = expiryDate;
                return this;
            }
            
            public KeyStoreEntry build() {
                return new KeyStoreEntry(this);
            }
        }
    }
}
