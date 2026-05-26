"""IoT and embedded device security testing module.

Provides firmware analysis, serial port inspection, and common
embedded device vulnerability checks.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class IoTFinding:
    severity: str = "medium"
    category: str = ""
    message: str = ""
    remediation: str = ""
    detail: str = ""


@dataclass
class IoTScanResult:
    findings: list[IoTFinding] = field(default_factory=list)
    device_path: str = ""
    device_type: str = ""
    firmware_analyzed: bool = False
    serial_ports_found: list[str] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


FIRMWARE_INDICATORS: list[tuple[str, str, str, str]] = [
    (r"admin.*admin", "Hardcoded admin/admin credentials", "critical", "Change default credentials"),
    (r"root.*root", "Hardcoded root/root credentials", "critical", "Change default root password"),
    (r"password.*1234", "Weak default password", "high", "Set strong password policy"),
    (r"(?i)debug.*(true|1|enabled)", "Debug mode enabled in firmware", "high", "Disable debug mode for production"),
    (r"(?i)telnet.*(true|1|enabled)", "Telnet enabled (unencrypted)", "high", "Use SSH instead of Telnet"),
    (r"(?i)(key|cert).*\n.*-----BEGIN", "Embedded TLS certificate/key", "critical", "Use unique certificates per device"),
    (r"(?i)http://", "HTTP endpoint in firmware", "medium", "Use HTTPS for all communications"),
    (r"(?i)ota.*http://", "OTA update over HTTP", "critical", "Use HTTPS for OTA updates"),
    (r"(?i)no.*secure.*boot", "Secure boot disabled", "high", "Enable secure boot"),
    (r"(?i)uart.*(enabled|true)", "UART debug interface active", "medium", "Disable UART in production"),
    (r"(?i)jtag.*(enabled|true)", "JTAG debug interface active", "medium", "Disable JTAG in production"),
    (r"(?i)api.*endpoint.*http://", "API endpoint over HTTP", "high", "Use HTTPS for API endpoints"),
    (r"(?i)mqtt.*(://|broker).*[0-9]+", "MQTT connection detected", "info", "Ensure MQTT over TLS"),
    (r"(?i)secret.*=[^;]+", "Hardcoded secret in firmware", "critical", "Use secure element storage"),
    (r"(?i)token.*=[^;]+", "Hardcoded token in firmware", "critical", "Provision per-device tokens"),
]

SERIAL_BAUD_RATES = [300, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200]


class IoTScanner:
    """IoT and embedded device security analysis."""

    def __init__(self) -> None:
        self._findings: list[IoTFinding] = []

    def detect_device_type(self, device_path: str) -> str:
        path_lower = device_path.lower()
        if any(kw in path_lower for kw in ("esp32", "esp8266")):
            return "ESP32/ESP8266"
        if any(kw in path_lower for kw in ("arduino", "avr", "atmega")):
            return "Arduino/AVR"
        if any(kw in path_lower for kw in ("stm32", "stm")):
            return "STM32"
        if any(kw in path_lower for kw in ("raspberry", "rpi")):
            return "Raspberry Pi"
        if any(kw in path_lower for kw in ("nrf52", "nrf", "nordic")):
            return "Nordic nRF5x"
        return "Unknown IoT device"

    def scan_serial_port(self, port: str, baud: int = 115200, timeout: float = 2.0) -> IoTScanResult:
        """Attempt to connect to a serial port and detect banner/identify device."""
        result = IoTScanResult(device_path=port, device_type=self.detect_device_type(port))
        result.serial_ports_found = [port]

        try:
            import serial
            ser = serial.Serial(port=port, baudrate=baud, timeout=timeout)
            banner = ser.read(1024).decode("utf-8", errors="replace")
            ser.close()
            if banner:
                self._analyze_banner(banner, result)
                result.firmware_analyzed = True
        except ImportError:
            result.findings.append(IoTFinding(
                severity="info", category="library",
                message="pyserial not installed — install with: pip install pyserial",
            ))
        except Exception as exc:
            result.findings.append(IoTFinding(
                severity="info", category="serial",
                message=f"Could not open serial port {port}: {exc}",
            ))

        return result

    def scan_firmware(self, firmware_path: str | Path) -> IoTScanResult:
        """Analyze a firmware binary/image for security issues."""
        path = Path(firmware_path)
        if not path.exists():
            return IoTScanResult(device_path=str(path))

        result = IoTScanResult(device_path=str(path), device_type=self.detect_device_type(str(path)))

        try:
            raw = path.read_bytes()
            # Try to extract strings
            strings = self._extract_strings(raw)
            for s in strings[:500]:
                for pattern, message, severity, remediation in FIRMWARE_INDICATORS:
                    if re.search(pattern, s):
                        result.findings.append(IoTFinding(
                            severity=severity,
                            category="firmware",
                            message=message,
                            remediation=remediation,
                            detail=s.strip()[:100],
                        ))

            # Check for common firmware headers
            if raw[:4] == b"\x7fELF":
                result.findings.insert(0, IoTFinding(
                    severity="info", category="firmware",
                    message="ELF binary detected — firmware appears to be Linux-based",
                ))
            elif raw[:2] == b"\x1f\x8b":
                result.findings.insert(0, IoTFinding(
                    severity="info", category="firmware",
                    message="GZip compressed firmware image",
                ))
            elif raw[:4] == b"UBI#":
                result.findings.insert(0, IoTFinding(
                    severity="info", category="firmware",
                    message="UBIFS firmware image detected",
                ))

            result.firmware_analyzed = True
        except Exception as exc:
            logger.warning("Firmware scan error: %s", exc)
            result.findings.append(IoTFinding(
                severity="medium", category="firmware",
                message=f"Firmware analysis error: {exc}",
            ))

        return result

    def _analyze_banner(self, banner: str, result: IoTScanResult) -> None:
        if "esp32" in banner.lower() or "esp8266" in banner.lower():
            result.device_type = "ESP32/ESP8266"
        if any(kw in banner.lower() for kw in ("login:", "password:", "user:")):
            result.findings.append(IoTFinding(
                severity="info", category="serial",
                message="Serial console requires authentication",
            ))
        if "# " in banner or "$ " in banner:
            result.findings.append(IoTFinding(
                severity="high", category="serial",
                message="Serial shell accessible — potential backdoor access",
                remediation="Disable serial shell in production firmware",
            ))

    def _extract_strings(self, data: bytes, min_len: int = 6) -> list[str]:
        result = []
        current = bytearray()
        for byte in data:
            if 32 <= byte <= 126:
                current.append(byte)
            else:
                if len(current) >= min_len:
                    result.append(current.decode("ascii", errors="replace"))
                current = bytearray()
        if len(current) >= min_len:
            result.append(current.decode("ascii", errors="replace"))
        return result

    def generate_report(self, result: IoTScanResult, fmt: str = "text") -> str:
        if fmt == "json":
            return json.dumps({
                "device_path": result.device_path,
                "device_type": result.device_type,
                "firmware_analyzed": result.firmware_analyzed,
                "findings_count": len(result.findings),
                "summary": result.summary,
                "findings": [
                    {
                        "severity": f.severity,
                        "category": f.category,
                        "message": f.message,
                        "remediation": f.remediation,
                    }
                    for f in result.findings
                ],
            }, indent=2)
        lines = [f"IoT Scan: {result.device_type} @ {result.device_path}"]
        lines.append(f"  Findings: {len(result.findings)}")
        for sev in ("critical", "high", "medium", "low", "info"):
            c = result.summary.get(sev, 0)
            if c:
                lines.append(f"    {sev}: {c}")
        for f in result.findings[:20]:
            lines.append(f"\n  [{f.severity.upper()}] [{f.category}] {f.message}")
            if f.remediation:
                lines.append(f"    Fix: {f.remediation}")
            if f.detail:
                lines.append(f"    Detail: {f.detail}")
        if len(result.findings) > 20:
            lines.append(f"\n  ... and {len(result.findings)-20} more")
        return "\n".join(lines)


__all__ = ["IoTScanner", "IoTFinding", "IoTScanResult"]
