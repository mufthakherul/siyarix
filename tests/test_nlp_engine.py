from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later
from siyarix.nlp_engine import NaturalLanguageParser


def test_nlp_target_extraction():
    nlp = NaturalLanguageParser()

    url, ttype = nlp.extract_entities("scan https://example.com please")
    assert url == "https://example.com"

    ip, ttype = nlp.extract_entities("check 192.168.1.5 fast")
    assert ip == "192.168.1.5"


def test_nlp_parameter_extraction():
    nlp = NaturalLanguageParser()
    params = nlp.extract_parameters(
        "scan port 80,443 very fast with timeout 5m and critical vulnerabilities json"
    )

    assert params.get("ports") == "80,443"
    assert params.get("speed") == "fast"
    assert params.get("timeout") == "5m"
    assert params.get("severity") == "critical"
    assert params.get("format") == "json"


def test_nlp_fuzzy_matching():
    nlp = NaturalLanguageParser()
    assert nlp.fuzzy_match("vulnaribility", ["vulnerability"]) is True
    assert nlp.fuzzy_match("direcotry", ["directory"]) is True
    assert nlp.fuzzy_match("abc", ["vulnerability"]) is False


def test_nlp_stemming_and_synonyms():
    nlp = NaturalLanguageParser()
    # default synonym for 'bug' is 'vuln' -> stem of vuln is 'vuln'
    assert nlp.tokenize("scanning bugs") == ["scan", "vuln", "scan_vuln"]


def test_nlp_scoring():
    nlp = NaturalLanguageParser()
    nlp.train_tools(
        [
            {"name": "nmap", "description": "network port scanner"},
            {"name": "sqlmap", "description": "sql injection vulnerabilities"},
        ]
    )

    intent = nlp.parse("run a network port scan")
    assert intent.tool_name == "nmap"

    intent2 = nlp.parse("find sql injection bugs")
    assert intent2.tool_name == "sqlmap"


# ── custom_synonyms (line 113) ───────────────────────────────────────────


class TestCustomSynonyms:
    def test_custom_synonyms_merged(self):
        nlp = NaturalLanguageParser(custom_synonyms={"custom_word": "canonical"})
        tokens = nlp.tokenize("custom_word")
        assert "canonical" in tokens

    def test_custom_synonyms_override_default(self):
        nlp = NaturalLanguageParser(custom_synonyms={"bug": "custom_vuln"})
        tokens = nlp.tokenize("bug")
        assert "custom_vuln" in tokens


# ── Domain entity extraction with filtering (line 194) ───────────────────


class TestDomainEntityExtraction:
    def test_domain_with_valid_match(self):
        nlp = NaturalLanguageParser()
        target, ttype = nlp.extract_entities("scan example.com and test.com")
        assert ttype == "domain"
        assert target == "example.com"

    def test_domain_short_match_filtered(self):
        nlp = NaturalLanguageParser()
        target, ttype = nlp.extract_entities("check v.1 for bugs")
        # No valid domain (> 4 chars, not starting with e.g)
        assert target == ""
        assert ttype == ""

    def test_domain_e_dot_g_filtered(self):
        nlp = NaturalLanguageParser()
        target, ttype = nlp.extract_entities("see e.g. example for reference")
        assert ttype == ""


# ── all ports extraction (line 214) ──────────────────────────────────────


class TestAllPorts:
    def test_all_ports(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("scan all ports")
        assert params.get("ports") == "all"

    def test_full_ports(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("scan full ports")
        assert params.get("ports") == "all"


# ── Negation handling (lines 222-232) ────────────────────────────────────


class TestNegationSpeed:
    def test_negated_fast_becomes_stealth(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("not fast scan")
        assert params.get("speed") == "stealth"

    def test_negated_aggressive_becomes_stealth(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("no aggressive scan")
        assert params.get("speed") == "stealth"

    def test_negated_stealth_becomes_fast(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("without stealth scan")
        assert params.get("speed") == "fast"

    def test_non_negated_aggressive(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("intense aggressive scan")
        assert params.get("speed") == "aggressive"

    def test_non_negated_stealth(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("sneaky stealth scan")
        assert params.get("speed") == "stealth"

    def test_non_negated_fast(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("quick rapid scan")
        assert params.get("speed") == "fast"


# ── Severity extraction (lines 244-253) ──────────────────────────────────


class TestSeverityExtraction:
    def test_severity_all_levels(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("find critical, high, medium, low vulns")
        assert params.get("severity") == "critical,high,medium,low"

    def test_severity_single(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("only high vulns")
        assert params.get("severity") == "high"

    def test_negated_with_low_becomes_high_critical(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("skip low severity vulns")
        assert params.get("severity") == "high,critical"


# ── Output format (lines 259-261) ────────────────────────────────────────


class TestOutputFormat:
    def test_xml_format(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("output in xml")
        assert params.get("format") == "xml"

    def test_markdown_format(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("generate md report")
        assert params.get("format") == "markdown"

    def test_markdown_via_full_word(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("markdown output")
        assert params.get("format") == "markdown"

    def test_json_overrides_xml(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("json and xml output")
        assert params.get("format") == "json"


# ── Protocol extraction with negation (lines 265-267) ────────────────────


class TestProtocolExtraction:
    def test_udp_negated_becomes_tcp(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("not udp")
        assert params.get("protocol") == "tcp"

    def test_tcp_negated_becomes_udp(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("skip tcp")
        assert params.get("protocol") == "udp"

    def test_non_negated_udp(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("use udp")
        assert params.get("protocol") == "udp"

    def test_non_negated_tcp(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("use tcp")
        assert params.get("protocol") == "tcp"


# ── Verbose extraction (line 271-272) ────────────────────────────────────


class TestVerboseExtraction:
    def test_verbose_not_negated(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("verbose scan")
        assert params.get("verbose") == "true"

    def test_detailed_not_negated(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("detailed output")
        assert params.get("verbose") == "true"

    def test_verbose_negated_skipped(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("not verbose scan")
        assert "verbose" not in params


# ── Wordlist extraction (line 277) ───────────────────────────────────────


class TestWordlistExtraction:
    def test_wordlist_found(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("use wordlist /path/to/words.txt")
        assert params.get("wordlist") == "/path/to/words.txt"

    def test_wordlist_no_match(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("scan without custom dictionary")
        assert "wordlist" not in params


# ── _get_char_bigrams (line 299) ─────────────────────────────────────────


class TestGetCharBigrams:
    def test_short_word_returns_set_with_word(self):
        nlp = NaturalLanguageParser()
        result = nlp._get_char_bigrams("a")
        assert result == {"a"}

    def test_normal_word_returns_bigrams(self):
        nlp = NaturalLanguageParser()
        result = nlp._get_char_bigrams("hello")
        assert "he" in result
        assert "el" in result
        assert "ll" in result
        assert "lo" in result

    def test_empty_string(self):
        nlp = NaturalLanguageParser()
        result = nlp._get_char_bigrams("")
        assert result == {""}


# ── fuzzy_match (lines 305, 315, 329, 333) ───────────────────────────────


class TestFuzzyMatchEdgeCases:
    def test_empty_corpus_returns_false(self):
        nlp = NaturalLanguageParser()
        assert nlp.fuzzy_match("test", []) is False

    def test_short_token_exact_match(self):
        nlp = NaturalLanguageParser()
        assert nlp.fuzzy_match("abcd", ["abcd", "efgh"]) is True

    def test_short_token_no_match(self):
        nlp = NaturalLanguageParser()
        assert nlp.fuzzy_match("abcd", ["wxyz"]) is False

    def test_long_token_difflib_match(self):
        nlp = NaturalLanguageParser()
        assert nlp.fuzzy_match("direcotry", ["directory"]) is True

    def test_phonetic_similarity_above_threshold(self):
        nlp = NaturalLanguageParser()
        # "vulnurability" phonetically simplified vs "vulnerability"
        assert nlp.fuzzy_match("vulnurability", ["vulnerability"]) is True

    def test_below_threshold_no_match(self):
        nlp = NaturalLanguageParser()
        assert nlp.fuzzy_match("completelydifferent", ["short"]) is False

    def test_union_is_zero(self):
        nlp = NaturalLanguageParser()
        result = nlp.fuzzy_match("", [""])
        # both empty -> bigrams are {''}, intersection={''}, union={''}
        # similarity = 1/1 = 1.0 >= 0.5
        assert result is True


# ── score_intent BM25 formula (lines 371-385) ────────────────────────────


class TestScoreIntent:
    def test_exact_name_match_boost(self):
        nlp = NaturalLanguageParser()
        nlp.train_tools([{"name": "nmap", "description": "port scanner"}])
        tokens = nlp.tokenize("nmap port scanner")
        best, score = nlp.score_intent(tokens, nlp._tool_corpus)
        assert best == "nmap"
        assert score > 0

    def test_ngram_boost(self):
        nlp = NaturalLanguageParser()
        nlp.train_tools([{"name": "sqlmap", "description": "sql injection tool"}])
        tokens = nlp.tokenize("sql injection")
        best, score = nlp.score_intent(tokens, nlp._tool_corpus)
        assert best == "sqlmap"

    def test_empty_corpus(self):
        nlp = NaturalLanguageParser()
        best, score = nlp.score_intent(["test"], {})
        assert best is None
        assert score == 0.0

    def test_idf_scoring(self):
        nlp = NaturalLanguageParser()
        nlp.train_tools(
            [
                {"name": "nmap", "description": "network port scanner"},
                {"name": "sqlmap", "description": "sql injection scanner"},
            ]
        )
        # "scanner" appears in both docs, idf should be lower
        scanner_idf = nlp.get_idf("scanner")
        assert scanner_idf < nlp.get_idf("network")

    def test_fuzzy_match_in_scoring(self):
        nlp = NaturalLanguageParser()
        nlp.train_tools([{"name": "nmap", "description": "port scanner"}])
        tokens = nlp.tokenize("vulnarability port scanner")
        best, score = nlp.score_intent(tokens, nlp._tool_corpus)
        assert best == "nmap"


# ── parse method template matching (lines 406-418) ───────────────────────


class TestParseEdgeCases:
    def test_template_preferred_over_tool(self):
        nlp = NaturalLanguageParser()
        nlp.train_tools([{"name": "nmap", "description": "port scanner"}])
        nlp.train_templates({"fast_scan": "quick port scan"})
        intent = nlp.parse("perform a quick port scan")
        assert intent.template_name == "fast_scan"

    def test_tool_used_when_template_score_low(self):
        nlp = NaturalLanguageParser()
        nlp.train_tools([{"name": "nmap", "description": "port scanner slow"}])
        nlp.train_templates({"deep_scan": "intrusive aggressive full scan"})
        intent = nlp.parse("port scanner")
        assert intent.tool_name == "nmap"

    def test_no_tokens_returns_empty_intent(self):
        nlp = NaturalLanguageParser()
        intent = nlp.parse("")
        assert intent.tool_name is None
        assert intent.template_name is None
        assert intent.confidence == 0.0

    def test_stopwords_only_returns_empty(self):
        nlp = NaturalLanguageParser()
        intent = nlp.parse("the a an and")
        assert intent.tool_name is None

    def test_extracted_target_removed_from_clean_text(self):
        nlp = NaturalLanguageParser()
        nlp.train_tools([{"name": "nmap", "description": "port scanner"}])
        intent = nlp.parse("nmap scan 192.168.1.1")
        assert intent.target == "192.168.1.1"
        assert intent.target_type == "ipv4"


# ── Stemming edge cases ─────────────────────────────────────────────────


class TestStemming:
    def test_stem_word_no_suffix(self):
        nlp = NaturalLanguageParser()
        assert nlp.stem_word("test") == "test"

    def test_stem_word_with_repeated_char(self):
        nlp = NaturalLanguageParser()
        stem = nlp.stem_word("running")
        assert stem == "run"

    def test_stem_word_short_stem(self):
        nlp = NaturalLanguageParser()
        stem = nlp.stem_word("ing")
        assert stem == "ing"  # len('i') = 1 < 3, so suffix not stripped


# ── Tokenize edge cases ─────────────────────────────────────────────────


class TestTokenize:
    def test_punctuation_removed_except_hyphen(self):
        nlp = NaturalLanguageParser()
        tokens = nlp.tokenize("hello, world! test-driven")
        assert "hello" in tokens
        assert "world" in tokens
        # Hyphen is preserved so "test-driven" stays as a token
        assert "test-driven" in tokens

    def test_synonym_mapped_in_tokenize(self):
        nlp = NaturalLanguageParser()
        tokens = nlp.tokenize("bug")
        assert "vuln" in tokens
        assert "bug" not in tokens

    def test_bigrams_and_trigrams(self):
        nlp = NaturalLanguageParser()
        tokens = nlp.tokenize("port scan fast")
        assert "port_scan" in tokens
        assert "port_scan_fast" in tokens


# ── _recalculate_idf ─────────────────────────────────────────────────────


class TestRecalculateIdf:
    def test_recalculate_clears_and_rebuilds(self):
        nlp = NaturalLanguageParser()
        nlp.train_tools([{"name": "nmap", "description": "port scanner"}])
        nlp.train_templates({"test": "just a test descriptor"})
        assert nlp._total_docs == 2
        assert nlp._doc_frequencies.get("port") == 1


# ── get_idf edge cases (line 284-285) ────────────────────────────────────


class TestGetIdf:
    def test_unknown_token_returns_one(self):
        nlp = NaturalLanguageParser()
        assert nlp.get_idf("completelyunknown") == 1.0

    def test_zero_total_docs_returns_one(self):
        nlp = NaturalLanguageParser()
        assert nlp.get_idf("anything") == 1.0


# ── _phonetic_simplify ──────────────────────────────────────────────────


class TestPhoneticSimplify:
    def test_consecutive_duplicates_removed(self):
        nlp = NaturalLanguageParser()
        assert nlp._phonetic_simplify("ffuf") == "fuf"

    def test_ph_replaced_by_f(self):
        nlp = NaturalLanguageParser()
        assert nlp._phonetic_simplify("ph") == "f"

    def test_y_replaced_by_i(self):
        nlp = NaturalLanguageParser()
        assert nlp._phonetic_simplify("my") == "mi"

    def test_c_replaced_by_k(self):
        nlp = NaturalLanguageParser()
        assert nlp._phonetic_simplify("cat") == "kat"


# ── CVE / SHA / IPv6 entity extraction ──────────────────────────────────


class TestEntityExtractionTypes:
    def test_cve_extraction(self):
        nlp = NaturalLanguageParser()
        target, ttype = nlp.extract_entities("check CVE-2024-1234")
        assert target == "CVE-2024-1234"
        assert ttype == "cve"

    def test_sha256_extraction(self):
        nlp = NaturalLanguageParser()
        sha = "a" * 64
        target, ttype = nlp.extract_entities(f"hash {sha}")
        assert target == sha
        assert ttype == "sha256"

    def test_sha1_extraction(self):
        nlp = NaturalLanguageParser()
        sha1 = "a" * 40
        target, ttype = nlp.extract_entities(f"hash {sha1}")
        assert target == sha1
        assert ttype == "sha1"

    def test_md5_extraction(self):
        nlp = NaturalLanguageParser()
        md5 = "a" * 32
        target, ttype = nlp.extract_entities(f"hash {md5}")
        assert target == md5
        assert ttype == "md5"

    def test_ipv6_extraction(self):
        nlp = NaturalLanguageParser()
        target, ttype = nlp.extract_entities("scan 2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert target == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        assert ttype == "ipv6"

    def test_mac_extraction(self):
        nlp = NaturalLanguageParser()
        target, ttype = nlp.extract_entities("device aa:bb:cc:dd:ee:ff")
        assert target == "aa:bb:cc:dd:ee:ff"
        assert ttype == "mac"

    def test_asn_extraction(self):
        nlp = NaturalLanguageParser()
        target, ttype = nlp.extract_entities("check AS12345")
        assert target == "AS12345"
        assert ttype == "asn"

    def test_email_extraction(self):
        nlp = NaturalLanguageParser()
        target, ttype = nlp.extract_entities("contact admin@example.com")
        assert ttype == "domain"

    def test_cidr_extraction(self):
        nlp = NaturalLanguageParser()
        target, ttype = nlp.extract_entities("scan 10.0.0.0/24")
        assert target == "10.0.0.0/24"
        assert ttype == "cidr"


# ── extract_parameters no matches returns empty dict ─────────────────────


class TestExtractParametersNoMatch:
    def test_no_parameters_found(self):
        nlp = NaturalLanguageParser()
        params = nlp.extract_parameters("just scan something")
        assert params == {}
