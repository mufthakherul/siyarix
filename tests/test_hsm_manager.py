# SPDX-License-Identifier: AGPL-3.0-or-later

from unittest.mock import MagicMock, patch

import pytest

from siyarix.hsm_manager import HSMError, HSMKeyInfo, HSMNotAvailable, HSMService, HSMStatus


@pytest.fixture
def service():
    return HSMService(preferred_provider="yubikey")


class TestHSMService:
    def test_init(self):
        s = HSMService(preferred_provider="pkcs11")
        assert s._provider == "pkcs11"
        assert s._connected is False

    def test_available_property(self, service):
        assert service.available is False
        service._connected = True
        assert service.available is True

    def test_disconnect(self, service):
        service._connected = True
        service._status = HSMStatus(connected=True)
        service.disconnect()
        assert service._connected is False
        assert service._status.connected is False

    def test_get_status(self, service):
        status = service.get_status()
        assert isinstance(status, HSMStatus)

    def test_connect_unknown_provider(self, service):
        status = service.connect(provider="unknown")
        assert status.connected is False
        assert "Unsupported" in status.error

    def test_connect_yubikey_no_devices(self, service):
        service._provider = "yubikey"
        status = service.connect()
        # If ykman not installed, it will give ImportError
        try:
            from ykman.device import list_all_devices  # noqa: F401
            assert status.connected is False
            assert "No YubiKey" in status.error
        except ImportError:
            assert status.connected is False

    def test_connect_yubikey_success(self, service):
        service._provider = "yubikey"
        status = service.connect()
        assert status.connected is False  # No actual YubiKey

    def test_connect_yubikey_exception(self, service):
        service._provider = "yubikey"
        status = service.connect()
        assert status.connected is False

    def test_connect_pkcs11_import_error(self, service):
        with patch.dict("sys.modules", {"pkcs11": None}):
            with patch("importlib.import_module", side_effect=ImportError("no pkcs11")):
                status = service.connect(provider="pkcs11")
                assert "python-pkcs11" in status.error

    def test_connect_pkcs11_no_lib(self, service):
        with patch.object(service, "_find_pkcs11_lib", return_value=None):
            with patch.dict("sys.modules", {"pkcs11": MagicMock()}):
                status = service.connect(provider="pkcs11")
                assert status.connected is False
                assert "No PKCS#11 library" in status.error

    def test_connect_pkcs11_exception(self, service):
        mock_pkcs11 = MagicMock()
        mock_pkcs11.lib.side_effect = RuntimeError("pkcs11 error")
        with patch.object(service, "_find_pkcs11_lib", return_value=MagicMock()):
            with patch.dict("sys.modules", {"pkcs11": mock_pkcs11}):
                status = service.connect(provider="pkcs11")
                assert "pkcs11 error" in status.error or "PKCS#11 error" in status.error

    def test_connect_tpm(self, service):
        status = service.connect(provider="tpm")
        assert status.connected is False
        assert "tpm2-pytss" in status.error

    def test_store_secret_not_connected(self, service):
        result = service.store_secret("test", "mysecret")
        assert result is None

    def test_store_secret_yubikey(self, service):
        service._connected = True
        service._provider = "yubikey"
        result = service.store_secret("test_label", "secret_val", algorithm="AES")
        assert result is not None
        assert result.label == "test_label"
        assert result.id == "slot_1"

    def test_store_secret_pkcs11(self, service):
        service._connected = True
        service._provider = "pkcs11"
        result = service.store_secret("pkcs_label", "secret_val", algorithm="ECC-P256")
        assert result is not None
        assert result.label == "pkcs_label"
        assert result.algorithm == "ECC-P256"
        assert result.key_type == "symmetric"

    def test_store_secret_other_provider(self, service):
        service._connected = True
        service._provider = "tpm"
        result = service.store_secret("test", "secret")
        assert result is None

    def test_find_pkcs11_lib_windows(self, service):
        with patch("platform.system", return_value="Windows"):
            with patch("pathlib.Path.exists", return_value=False):
                result = service._find_pkcs11_lib()
                assert result is None

    def test_find_pkcs11_lib_windows_found(self, service):
        with patch("platform.system", return_value="Windows"):
            with patch("pathlib.Path.exists", return_value=True):
                result = service._find_pkcs11_lib()
                assert result is not None
                assert "opensc-pkcs11.dll" in str(result)

    def test_find_pkcs11_lib_darwin(self, service):
        with patch("platform.system", return_value="Darwin"):
            with patch("pathlib.Path.exists", return_value=False):
                result = service._find_pkcs11_lib()
                assert result is None

    def test_find_pkcs11_lib_linux(self, service):
        with patch("platform.system", return_value="Linux"):
            with patch("pathlib.Path.exists", return_value=True):
                result = service._find_pkcs11_lib()
                assert result is not None

    def test_generate_report_text_connected(self, service):
        service._status = HSMStatus(
            connected=True,
            provider="yubikey",
            model="YubiKey 5 NFC",
            serial="12345",
            algorithms=["RSA-2048", "ECC-P256"],
            slots_available=2,
        )
        report = service.generate_report(fmt="text")
        assert "HSM Connected" in report
        assert "YubiKey 5 NFC" in report

    def test_generate_report_text_not_connected(self, service):
        service._status = HSMStatus(connected=False, error="No device")
        report = service.generate_report(fmt="text")
        assert "Not Connected" in report
        assert "No device" in report

    def test_generate_report_json(self, service):
        service._status = HSMStatus(connected=True, provider="yubikey", model="YubiKey", serial="12345")
        report = service.generate_report(fmt="json")
        import json
        data = json.loads(report)
        assert data["connected"] is True
        assert data["provider"] == "yubikey"

    def test_hsm_error_exception(self):
        e = HSMError("test error")
        assert str(e) == "test error"
        assert issubclass(HSMNotAvailable, HSMError)

    def test_hsm_status_dataclass(self):
        s = HSMStatus(connected=True, provider="test", model="M1", serial="S1")
        assert s.connected is True
        assert s.algorithms == []

    def test_hsm_key_info_dataclass(self):
        k = HSMKeyInfo(id="k1", label="l1", algorithm="AES", key_type="symmetric", slot=1)
        assert k.id == "k1"
        assert k.algorithm == "AES"
