from phalanx.masking import MaskingEngine


def test_mask_unmask_domain_and_apikey():
    m = MaskingEngine()
    # domain and API key rules
    m.add_rule("domain", r"[a-z0-9.-]+\.[a-z]{2,}")
    m.add_rule("apikey", r"sk-[A-Za-z0-9]{24,}")

    text = "Scan xyz.com and use key sk-abcdefghijklmnopqrstuvwx1234 to auth"
    masked = m.mask(text)
    assert "xyz.com" not in masked
    assert "sk-abcdefghijklmnopqrstuvwx1234" not in masked

    unmasked = m.unmask(masked)
    assert unmasked == text


def test_reset_clears_mappings():
    m = MaskingEngine()
    m.add_rule("domain", r"[a-z0-9.-]+\.[a-z]{2,}")
    t = "example.com"
    masked = m.mask(t)
    assert masked != t
    m.reset()
    # After reset, masking same text should produce token counter restart
    masked2 = m.mask(t)
    assert masked2 != t
