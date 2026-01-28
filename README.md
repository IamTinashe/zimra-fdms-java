# ZIMRA FDMS Integration SDK for Java

[![CI](https://github.com/yourusername/zimra-fdms-java/workflows/CI/badge.svg)](https://github.com/yourusername/zimra-fdms-java/actions)
[![Maven Central](https://img.shields.io/maven-central/v/com.zimra/fdms.svg)](https://search.maven.org/artifact/com.zimra/fdms)
[![codecov](https://codecov.io/gh/yourusername/zimra-fdms-java/branch/main/graph/badge.svg)](https://codecov.io/gh/yourusername/zimra-fdms-java)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Production-grade SDK for integrating with Zimbabwe Revenue Authority's (ZIMRA) Fiscalisation Data Management System (FDMS) API.

## Features

- ✅ Full ZIMRA FDMS API v7.2 compliance
- 🔐 Security-first cryptographic operations
- � X.509 certificate management with CSR generation
- 🔒 Secure encrypted key storage (AES-256-GCM)- ✍️ RSA-SHA256 digital signatures for receipts- �📝 Complete audit logging
- 🔄 Automatic retry and offline queue
- 📊 Real-time fiscal day management
- 🧾 Receipt signing and QR code generation
- ☕ Java 11+ compatible

## Installation

### Maven

```xml
<dependency>
    <groupId>com.zimra</groupId>
    <artifactId>fdms</artifactId>
    <version>0.1.0</version>
</dependency>
```

### Gradle

```groovy
implementation 'com.zimra:fdms:0.1.0'
```

## Quick Start

```java
import com.zimra.fdms.FdmsClient;
import com.zimra.fdms.model.Receipt;

public class Example {
    public static void main(String[] args) {
        FdmsClient client = new FdmsClient.Builder()
            .deviceId("YOUR_DEVICE_ID")
            .deviceSerialNo("YOUR_SERIAL_NO")
            .activationKey("YOUR_ACTIVATION_KEY")
            .deviceModelName("YOUR_MODEL_NAME")
            .deviceModelVersion("YOUR_MODEL_VERSION")
            .certificate("./path/to/cert.pem")
            .privateKey("./path/to/key.pem")
            .environment(FdmsEnvironment.TEST)
            .build();

        // Initialize device
        client.initialize();

        // Open fiscal day
        client.openFiscalDay();

        // Submit receipt
        Receipt receipt = client.submitReceipt(receiptData);

        // Close fiscal day
        client.closeFiscalDay();
    }
}
```

## Certificate Management

The SDK provides comprehensive X.509 certificate management:

```java
import com.zimra.fdms.crypto.CertificateManager;
import com.zimra.fdms.crypto.KeyStoreManager;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

// Certificate Manager
CertificateManager certManager = new CertificateManager();

// Load existing certificate and key
X509Certificate cert = certManager.loadCertificate("./device-cert.pem");
PrivateKey privateKey = certManager.loadPrivateKey("./device-key.pem", "password");

// Generate new RSA key pair (4096-bit recommended)
KeyPair keyPair = certManager.generateKeyPair(
    CertificateManager.KeyPairOptions.builder()
        .keySize(4096)
        .build()
);

// Generate CSR for device registration
String csr = certManager.generateCsr(
    keyPair.getPrivate(),
    CertificateManager.CsrOptions.builder()
        .commonName("DEVICE-12345")
        .organizationName("My Company")
        .countryName("ZW")
        .build()
);

// Validate certificate
CertificateManager.ValidationResult validation = certManager.validateCertificate(cert);
if (!validation.isValid()) {
    System.err.println("Certificate issues: " + validation.getErrors());
}

// Secure Key Storage
KeyStoreManager keyStore = new KeyStoreManager(
    KeyStoreManager.Options.builder()
        .storePath("./keystore.json")
        .password("secure-password")
        .build()
);

keyStore.load();
keyStore.setKeyPair("device-key", privateKey, cert);
keyStore.save();

// Retrieve later
PrivateKey storedKey = keyStore.getPrivateKey("device-key");
X509Certificate storedCert = keyStore.getCertificate("device-key");
```

## Digital Signatures

The SDK provides RSA-SHA256 digital signature services for receipts and fiscal day reports:

```java
import com.zimra.fdms.crypto.SignatureService;
import com.zimra.fdms.crypto.SignatureService.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

// Create signature service with private key
SignatureService signatureService = new SignatureService.Builder()
    .privateKey(Files.readString(Path.of("./device-key.pem")))
    .privateKeyPassword("password")
    .enableCache(true)  // Cache signatures for identical data
    .build();

// Sign a receipt
SignatureResult receiptResult = signatureService.signReceipt(
    ReceiptSignatureData.builder()
        .deviceId(12345)
        .receiptType("FiscalInvoice")
        .receiptCurrency("USD")
        .receiptCounter(1)
        .receiptGlobalNo(100)
        .invoiceNo("INV-001")
        .receiptDate("2025-01-26T10:00:00Z")
        .receiptLineItems(List.of(
            ReceiptLineItemData.builder()
                .lineNo(1).lineDescription("Product A").lineQuantity(2)
                .lineUnitPrice(500).lineTaxPercent(15).lineTotal(1000).build()
        ))
        .receiptTaxes(List.of(
            ReceiptTaxData.builder()
                .taxCode("A").taxPercent(15).taxAmount(150).salesAmountWithTax(1150).build()
        ))
        .receiptPayments(List.of(
            ReceiptPaymentData.builder().moneyTypeCode(0).paymentAmount(1150).build()
        ))
        .receiptTotal(1150)
        .build()
);

System.out.println("Receipt Signature: " + receiptResult.getSignature());

// Sign fiscal day report
SignatureResult dayResult = signatureService.signFiscalDayReport(
    FiscalDayReportData.builder()
        .deviceId(12345)
        .fiscalDayNo(1)
        .fiscalDayOpened("2025-01-26T08:00:00Z")
        .receiptCounter(50)
        .receiptCounterByType(Map.of("FiscalInvoice", 48, "CreditNote", 2))
        .totalAmount(125000)
        .totalTax(16304.35)
        .totalsByTaxRate(List.of(
            TaxRateTotalData.builder().taxPercent(15).taxAmount(16304.35).build()
        ))
        .build()
);

System.out.println("Day Signature: " + dayResult.getSignature());

// Verify a signature
VerificationResult verification = signatureService.verifyReceiptSignature(receiptData, signature);
if (verification.isValid()) {
    System.out.println("Signature is valid");
}
```

## Documentation

- [Installation Guide](./docs/guides/installation.md)
- [Configuration Guide](./docs/guides/configuration.md)
- [API Reference](./docs/api/README.md)
- [Examples](./examples/)

## Requirements

- Java 11 or higher
- ZIMRA device credentials

## Development

```bash
# Clone repository
git clone https://github.com/yourusername/zimra-fdms-java.git
cd zimra-fdms-java

# Build
mvn clean install

# Run tests
mvn test

# Run with coverage
mvn clean test jacoco:report

# Check style
mvn checkstyle:check

# Format code
mvn fmt:format
```

## License

MIT

## Support

For issues and questions, please open an issue on [GitHub](https://github.com/yourusername/zimra-fdms-java/issues).
