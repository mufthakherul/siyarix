import pytest

from phalanx.response_sensor import ResponseSensor


def test_mask_unmask_and_redact_simple():
    rs = ResponseSensor()
    text = "connect to 192.168.1.5 with key sk-ABCDEF1234567890abcdef"
    masked, mask = rs.mask_for_model(text)
    assert "__PHX_MASK_" in masked

    # simulate provider returning a payload that includes the masked token
    payload = {"result": masked, "note": "keep sk-ABCDEF1234567890abcdef safe"}
    out = rs.unmask_and_redact(payload, mask=mask)
    assert "192.168.1.5" in out["result"]
    # the raw API key should be redacted in redactor output
    assert "[REDACTED]" in out["note"]

