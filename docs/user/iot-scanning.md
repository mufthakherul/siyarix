> [!NOTE]
> 👋 **Hey there!** Siyarix is a personal passion project built by a single developer that is growing and under active development. The feature described on this page is currently **Planned / Under Development** and may not be fully functional in the codebase yet. Stay tuned for updates! 🚀

# 🔌 IoT Security Scanning

The Internet of Things (IoT) is notoriously difficult to secure. Siyarix aims to change that by providing a comprehensive toolkit for analyzing firmware, enumerating serial ports, and detecting embedded devices.

> [!WARNING]
> **Active Development Notice**: Siyarix's IoT scanning module is currently under active development. An `IoTScanner` stub is present in the code, and we are working on the underlying analysis engines.

---

## 🚧 Current Status

Right now, the `IoTScanner` class is just a placeholder. You can invoke it, but it will not yet extract or analyze firmware.

```python
from siyarix.chat.stubs import IoTScanner

scanner = IoTScanner()

# This is a stub! It currently returns an empty dictionary {}.
result = scanner.scan_firmware("firmware.bin")
```

---

## 🔮 Planned Capabilities

We are building a powerful suite of tools tailored specifically for hardware and embedded systems.

### 📦 Firmware Analysis
- **Hardcoded Credentials**: Automatically extracting embedded passwords, API keys, and backdoors from binary images.
- **Debug Interfaces**: Hunting down development or debug modes (like SSH or Telnet) left active in production builds.
- **Certificate Inspection**: Extracting and validating hardcoded TLS certificates and private keys.
- **OTA Security**: Analyzing Over-The-Air update mechanisms for vulnerabilities and missing signatures.

### 🔌 Serial Port Scanning
- **Baud Rate Detection**: Automatically fuzzing and detecting correct baud rates.
- **Interface Enumeration**: Identifying exposed UART, JTAG, and SPI interfaces.
- **Protocol Identification**: Detecting and communicating via common IoT protocols (MQTT, CoAP, etc.).

### 🖥️ Device Type Detection
- **Chipset Identification**: Profiling devices like ESP32, Arduino, STM32, Raspberry Pi, and Nordic nRF5x.
- **Binary Analysis**: Parsing and extracting files from ELF, GZip, UBIFS, and raw binary images.
- **OS Fingerprinting**: Detecting the underlying operating system (RTOS, embedded Linux, or bare-metal).

---

## 📣 Stay Tuned!

Securing the physical world is a large challenge, and the IoT scanner is a key part of Siyarix's future. Keep an eye on our releases for updates on supported devices and firmware formats!
