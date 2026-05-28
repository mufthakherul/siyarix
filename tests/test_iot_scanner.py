# SPDX-License-Identifier: AGPL-3.0-or-later

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from siyarix.iot_scanner import IoTFinding, IoTScanResult, IoTScanner


@pytest.fixture
def scanner():
    return IoTScanner()


@pytest.fixture
def sample_firmware(tmp_path):
    f = tmp_path / "firmware.bin"
    data = b"".join([
        b"\x7fELF" + b"\x00" * 60,
        b"admin admin pw=1234 ",
        b"telnet enabled=true ",
        b"http://api.example.com ",
        b"secret=abc123 token=xyz789 ",
        b"uart enabled=true ",
        b"debug enabled=1 ",
        b"no secure boot ",
        b"jtag enabled=true ",
        b"ota http://update.example.com ",
        b"MQTT broker 1883 ",
        b"key cert \n-----BEGIN ",
    ])
    f.write_bytes(data)
    return f


class TestIoTScanner:
    def test_init(self, scanner):
        assert scanner._findings == []

    def test_detect_device_type_esp32(self, scanner):
        assert scanner.detect_device_type("/dev/esp32") == "ESP32/ESP8266"
        assert scanner.detect_device_type("/dev/ESP8266") == "ESP32/ESP8266"

    def test_detect_device_type_arduino(self, scanner):
        assert scanner.detect_device_type("/dev/arduino") == "Arduino/AVR"
        assert scanner.detect_device_type("/dev/avr") == "Arduino/AVR"
        assert scanner.detect_device_type("/dev/atmega328") == "Arduino/AVR"

    def test_detect_device_type_stm32(self, scanner):
        assert scanner.detect_device_type("/dev/stm32") == "STM32"
        assert scanner.detect_device_type("/dev/stm") == "STM32"

    def test_detect_device_type_rpi(self, scanner):
        assert scanner.detect_device_type("/dev/raspberry") == "Raspberry Pi"
        assert scanner.detect_device_type("/dev/rpi") == "Raspberry Pi"

    def test_detect_device_type_nrf(self, scanner):
        assert scanner.detect_device_type("/dev/nrf52") == "Nordic nRF5x"
        assert scanner.detect_device_type("/dev/nrf") == "Nordic nRF5x"
        assert scanner.detect_device_type("/dev/nordic") == "Nordic nRF5x"

    def test_detect_device_type_unknown(self, scanner):
        assert scanner.detect_device_type("/dev/unknown") == "Unknown IoT device"

    def test_scan_serial_port_import_error(self, scanner):
        with patch.dict("sys.modules", {"serial": None}):
            result = scanner.scan_serial_port("/dev/ttyUSB0")
            assert len(result.findings) == 1
            assert result.findings[0].severity == "info"
            assert "pyserial not installed" in result.findings[0].message

    def test_scan_serial_port_open_error(self, scanner):
        mock_serial = MagicMock()
        mock_serial.Serial.side_effect = PermissionError("Access denied")
        with patch.dict("sys.modules", {"serial": mock_serial}):
            result = scanner.scan_serial_port("/dev/ttyUSB0")
            assert len(result.findings) >= 1
            assert "/dev/ttyUSB0" in result.serial_ports_found

    def test_scan_serial_port_success(self, scanner):
        mock_serial = MagicMock()
        mock_ser = MagicMock()
        mock_ser.read.return_value = b"login: esp32\r\n# "
        mock_serial.Serial.return_value = mock_ser
        with patch.dict("sys.modules", {"serial": mock_serial}):
            result = scanner.scan_serial_port("/dev/ttyUSB0", baud=9600, timeout=1.0)
            assert result.device_type == "ESP32/ESP8266"
            assert result.firmware_analyzed is True
            assert any("authentication" in f.message for f in result.findings)
            assert any("shell" in f.message for f in result.findings)

    def test_scan_firmware_not_found(self, scanner):
        result = scanner.scan_firmware("/nonexistent/path.bin")
        assert "nonexistent" in result.device_path
        assert "path.bin" in result.device_path
        assert result.firmware_analyzed is False

    def test_scan_firmware_elf(self, scanner, sample_firmware):
        result = scanner.scan_firmware(sample_firmware)
        assert result.firmware_analyzed is True
        assert len(result.findings) >= 1

    def test_scan_firmware_gzip(self, scanner, tmp_path):
        f = tmp_path / "gzip.bin"
        f.write_bytes(b"\x1f\x8b" + b"test data")
        result = scanner.scan_firmware(f)
        assert any("GZip compressed" in f.message for f in result.findings)

    def test_scan_firmware_ubifs(self, scanner, tmp_path):
        f = tmp_path / "ubifs.bin"
        f.write_bytes(b"UBI#" + b"test data")
        result = scanner.scan_firmware(f)
        assert any("UBIFS" in f.message for f in result.findings)

    def test_scan_firmware_read_error(self, scanner, tmp_path):
        f = tmp_path / "broken.bin"
        f.write_bytes(b"data")
        with patch.object(Path, "read_bytes", side_effect=PermissionError("denied")):
            result = scanner.scan_firmware(f)
            assert any("error" in f.message.lower() for f in result.findings)

    def test_extract_strings(self, scanner):
        data = b"hello\x00world\x00abcdef"
        result = scanner._extract_strings(data, min_len=3)
        assert "hello" in result
        assert "world" in result
        assert "abcdef" in result

    def test_extract_strings_short_min_len(self, scanner):
        data = b"ab\x00cdefgh"
        result = scanner._extract_strings(data, min_len=10)
        assert "ab" not in result

    def test_generate_report_text(self, scanner):
        result = IoTScanResult(
            device_path="/dev/ttyUSB0",
            device_type="ESP32",
            firmware_analyzed=True,
            findings=[
                IoTFinding(severity="critical", category="firmware", message="test issue", remediation="fix it"),
            ],
        )
        report = scanner.generate_report(result, fmt="text")
        assert "ESP32" in report
        assert "test issue" in report
        assert "CRITICAL" in report

    def test_generate_report_json(self, scanner):
        result = IoTScanResult(
            device_path="/dev/ttyUSB0",
            device_type="ESP32",
            firmware_analyzed=True,
            findings=[
                IoTFinding(severity="high", category="firmware", message="json issue", remediation="json fix", detail="some detail"),
            ],
        )
        report = scanner.generate_report(result, fmt="json")
        import json
        data = json.loads(report)
        assert data["device_type"] == "ESP32"
        assert data["findings_count"] == 1
        assert data["findings"][0]["severity"] == "high"

    def test_generate_report_truncated_findings(self, scanner):
        findings = [IoTFinding(severity="info", category="test", message=f"finding {i}") for i in range(25)]
        result = IoTScanResult(findings=findings)
        report = scanner.generate_report(result)
        assert "and 5 more" in report

    def test_iot_scan_result_summary(self):
        result = IoTScanResult(
            findings=[
                IoTFinding(severity="critical"),
                IoTFinding(severity="high"),
                IoTFinding(severity="high"),
            ]
        )
        s = result.summary
        assert s == {"critical": 1, "high": 2}

    def test_iot_finding_defaults(self):
        f = IoTFinding()
        assert f.severity == "medium"
        assert f.category == ""
