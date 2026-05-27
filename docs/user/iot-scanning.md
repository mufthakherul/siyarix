# IoT Security Scanning

Siyarix includes a built-in IoT security scanner for firmware analysis, serial port enumeration, and device identification.

## Firmware analysis

```bash
# Scan IoT firmware for security issues
siyarix run "scan IoT device firmware backup.bin"
```

### Indicators checked (16 total)

| Indicator | What it detects | Severity |
|-----------|----------------|----------|
| Hardcoded credentials | Plain-text passwords in firmware | CRITICAL |
| Debug mode enabled | Debug interfaces left active | HIGH |
| Telnet enabled | Unencrypted remote access | HIGH |
| Embedded certificates | Hardcoded TLS certificates | MEDIUM |
| OTA over HTTP | Firmware updates over cleartext | HIGH |
| UART/JTAG exposed | Hardware debug interfaces | MEDIUM |
| Hardcoded API keys | Embedded cloud service keys | CRITICAL |
| Default SSH keys | Known default SSH host keys | CRITICAL |

## Serial port scanning

```bash
# Scan IoT device serial interfaces
siyarix run "scan serial ports on IoT device"
```

Automatically detects baud rates (12 standard rates from 300 to 921600 baud).

## Device type detection

The scanner identifies device types based on characteristics:

| Device type | Indicators |
|-------------|------------|
| ESP32 | ESP32-specific strings, WiFi libraries |
| Arduino | Arduino bootloader, avr-gcc strings |
| STM32 | STM32 HAL libraries, ARM Cortex-M strings |
| Raspberry Pi | BCM2835, Raspberry Pi kernel strings |
| Nordic nRF5x | SoftDevice, nRF5 SDK strings |

## Binary analysis

Detects firmware image types:

- ELF binaries
- GZip compressed images
- UBIFS filesystem images
- Raw binary images

## Usage

```bash
# Full IoT assessment
siyarix run "scan IoT devices on the local network"

# Firmware analysis only
siyarix run "analyze firmware file firmware.bin for vulnerabilities"

# Serial port enumeration
siyarix run "enumerate serial ports on target device"
```

## Reporting

```bash
# Generate IoT security report
siyarix report generate --format html --include iot
```
