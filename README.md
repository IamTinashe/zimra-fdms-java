# ZIMRA FDMS Integration SDK for Java

[![CI](https://github.com/yourusername/zimra-fdms-java/workflows/CI/badge.svg)](https://github.com/yourusername/zimra-fdms-java/actions)
[![Maven Central](https://img.shields.io/maven-central/v/com.zimra/fdms.svg)](https://search.maven.org/artifact/com.zimra/fdms)
[![codecov](https://codecov.io/gh/yourusername/zimra-fdms-java/branch/main/graph/badge.svg)](https://codecov.io/gh/yourusername/zimra-fdms-java)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Production-grade SDK for integrating with Zimbabwe Revenue Authority's (ZIMRA) Fiscalisation Data Management System (FDMS) API.

## Features

- ✅ Full ZIMRA FDMS API v7.2 compliance
- 🔐 Security-first cryptographic operations
- 📝 Complete audit logging
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
