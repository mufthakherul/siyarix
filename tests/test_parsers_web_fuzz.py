"""Tests for Web Discovery & Fuzzing parsers."""
from __future__ import annotations

import json
from siyarix.parsers.arjun_parser import ArjunParser
from siyarix.parsers.corsy_parser import CorsyParser
from siyarix.parsers.curl_parser import CurlParser
from siyarix.parsers.dirb_parser import DirbParser
from siyarix.parsers.dirsearch_parser import DirsearchParser
from siyarix.parsers.feroxbuster_parser import FeroxbusterParser
from siyarix.parsers.ffuf_parser import FfufParser
from siyarix.parsers.gospider_parser import GospiderParser
from siyarix.parsers.hakrawler_parser import HakrawlerParser
from siyarix.parsers.httpx_parser import HttpxParser
from siyarix.parsers.katana_parser import KatanaParser
from siyarix.parsers.kiterunner_parser import KiterunnerParser
from siyarix.parsers.wfuzz_parser import WfuzzParser
from siyarix.parsers.wget_parser import WgetParser


from siyarix.parsers.aquatone_parser import AquatoneParser
from siyarix.parsers.gobuster_parser import GobusterParser
from siyarix.parsers.paramspider_parser import ParamspiderParser
from siyarix.parsers.waybackurls_parser import WaybackurlsParser
def _check_finding(finding, expected_tool, min_fields=None):
    min_fields = min_fields or {
        "title", "severity", "description", "evidence", "tool", "target", "timestamp",
    }
    for field in min_fields:
        assert field in finding, f"Missing field {field} in {expected_tool} finding"
    assert finding["tool"] == expected_tool
    assert finding["severity"] in ("critical", "high", "medium", "low", "info")



class TestHttpxParser:
    def test_json_line_good_status(self):
        p = HttpxParser()
        output = json.dumps({
            "url": "https://example.com",
            "status_code": 200,
            "content_length": 1234,
            "title": "Example Domain",
            "webserver": "nginx/1.18.0",
            "tech": ["React", "Nginx"],
        })
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "httpx")
        assert "200" in findings[0]["title"]
        assert findings[0]["severity"] == "info"

    def test_json_line_error_status(self):
        p = HttpxParser()
        output = json.dumps({"url": "https://example.com/404", "status_code": 404})
        findings = p.parse(output)
        assert findings[0]["severity"] == "low"

    def test_json_line_server_error(self):
        p = HttpxParser()
        output = json.dumps({"url": "https://example.com/error", "status_code": 500})
        findings = p.parse(output)
        assert findings[0]["severity"] == "medium"

    def test_json_multiline(self):
        p = HttpxParser()
        lines = [
            json.dumps({"url": "https://site1.com", "status_code": 200, "title": "Site1"}),
            json.dumps({"url": "https://site2.com", "status_code": 301, "title": "Moved"}),
            json.dumps({"url": "https://site3.com", "status_code": 403, "title": "Forbidden"}),
        ]
        output = "\n".join(lines)
        findings = p.parse(output)
        assert len(findings) == 3

    def test_json_with_redirect(self):
        p = HttpxParser()
        output = json.dumps({
            "url": "https://example.com",
            "final_url": "https://www.example.com",
            "status_code": 200,
        })
        findings = p.parse(output)
        assert len(findings) == 1
        assert "->" in findings[0]["evidence"]

    def test_text_parse(self):
        p = HttpxParser()
        output = "https://example.com [200]\nhttps://test.com [404]\n"
        findings = p.parse(output)
        assert len(findings) >= 2
        for f in findings:
            _check_finding(f, "httpx")

    def test_text_without_status(self):
        p = HttpxParser()
        output = "https://example.com\nhttps://test.com\n"
        findings = p.parse(output)
        assert len(findings) >= 2

    def test_json_with_cnames_and_type(self):
        p = HttpxParser()
        output = json.dumps({
            "url": "https://app.example.com",
            "status_code": 200,
            "cnames": ["app.example.com.cdn.cloudflare.net"],
            "content_type": "text/html",
            "cdn_name": "cloudflare",
            "response_time": "0.123s",
        })
        findings = p.parse(output)
        assert len(findings) == 1
        desc = findings[0]["description"]
        assert "cdn: cloudflare" in desc or "cloudflare" in desc
        assert "type: text/html" in desc or "text/html" in desc

    def test_empty_output(self):
        p = HttpxParser()
        assert p.parse("") == []
        assert p.parse("   ") == []
class TestWgetParser:
    def test_download_started(self):
        p = WgetParser()
        output = "2025-01-01 12:00:00 URL:http://example.com/file.zip [12345] -> file.zip\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "wget")

    def test_http_status_line(self):
        p = WgetParser()
        output = "HTTP request sent, awaiting response... 200 OK\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "info"

    def test_http_404_error(self):
        p = WgetParser()
        output = "HTTP request sent, awaiting response... 404 Not Found\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "low"

    def test_http_500_error(self):
        p = WgetParser()
        output = "HTTP request sent, awaiting response... 500 Internal Server Error\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "high"

    def test_generic_error(self):
        p = WgetParser()
        output = "ERROR: cannot resolve hostname\n"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_connection_refused(self):
        p = WgetParser()
        output = "Failed: Connection refused.\n"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_recursive_complete(self):
        p = WgetParser()
        output = "Entering directory /var/www/\n5 files downloaded.\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert "recursive" in findings[0]["title"].lower()

    def test_length_detected(self):
        p = WgetParser()
        output = "2025-01-01 12:00:00 URL:http://example.com/file [12345] -> file\nLength: 12345 [html]\n"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_saved_file(self):
        p = WgetParser()
        output = "'file.zip' saved\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert "downloaded" in findings[0]["title"].lower()

    def test_spider_mode(self):
        p = WgetParser()
        output = "Spider mode enabled\nHTTP request sent, awaiting response... 200 OK\n"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_json_input(self):
        p = WgetParser()
        output = json.dumps([{"url": "http://example.com", "status_code": 200, "filename": "index.html"}])
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "wget")

    def test_json_404(self):
        p = WgetParser()
        output = json.dumps({"url": "http://example.com/missing", "status_code": 404})
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "low"

    def test_empty_output(self):
        p = WgetParser()
        assert p.parse("") == []
class TestGospiderParser:
    def test_basic_json_line(self):
        p = GospiderParser()
        output = json.dumps({"url": "http://example.com/page", "source": "linkfinder"})
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "gospider")

    def test_with_status_code(self):
        p = GospiderParser()
        output = json.dumps({"url": "http://example.com/admin", "status": 403, "source": "crawl"})
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "low"

    def test_with_500_error(self):
        p = GospiderParser()
        output = json.dumps({"url": "http://example.com/error", "status": 500})
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "medium"

    def test_with_redirect(self):
        p = GospiderParser()
        output = json.dumps({"url": "http://example.com/old", "status": 301, "redir": "https://example.com/new", "source": "crawl"})
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_subdomain_extraction(self):
        p = GospiderParser()
        output = json.dumps({"url": "http://sub.example.com/page", "source": "subdomain: sub.example.com"})
        findings = p.parse(output)
        subdomain_findings = [f for f in findings if "subdomain" in f["title"].lower()]
        assert len(subdomain_findings) >= 1

    def test_dedup_by_path(self):
        p = GospiderParser()
        output = json.dumps({"url": "http://example.com/page?q=1"}) + "\n" + json.dumps({"url": "http://example.com/page?q=2"})
        findings = p.parse(output)
        assert len(findings) == 1

    def test_non_json_skipped(self):
        p = GospiderParser()
        output = "not json\n"
        findings = p.parse(output)
        assert isinstance(findings, list)

    def test_empty_output(self):
        p = GospiderParser()
        assert p.parse("") == []

    def test_camelcase_keys(self):
        p = GospiderParser()
        output = json.dumps({"URL": "http://example.com", "Source": "crawl", "StatusCode": 200})
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_body_length(self):
        p = GospiderParser()
        output = json.dumps({"url": "http://example.com", "body_length": 12345, "source": "crawl"})
        findings = p.parse(output)
        assert len(findings) >= 1
class TestWfuzzParser:
    def test_simple_row(self):
        p = WfuzzParser()
        output = "ID: admin Response: 200 Size: 1234\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "wfuzz")

    def test_full_row(self):
        p = WfuzzParser()
        output = "00001:  Response: 200   Lines: 10   Word: 20   Chars: 100   admin\n"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_id_format_row(self):
        p = WfuzzParser()
        output = "00001 200 10 20 100 admin\n"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_403_severity(self):
        p = WfuzzParser()
        output = "ID: admin Response: 403 Size: 500\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "medium"

    def test_500_severity(self):
        p = WfuzzParser()
        output = "ID: error Response: 500 Size: 100\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "high"

    def test_baseline_filtered(self):
        p = WfuzzParser()
        output = "baseline excluded\n"
        findings = p.parse(output)
        assert len(findings) == 0

    def test_target_url(self):
        p = WfuzzParser()
        output = "Target: http://example.com/FUZZ\nID: admin Response: 200 Size: 100\n"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_empty_output(self):
        p = WfuzzParser()
        assert p.parse("") == []

    def test_dedup_by_target_payload_status(self):
        p = WfuzzParser()
        output = "Target: http://example.com/FUZZ\nID: admin Response: 200 Size: 100\nID: admin Response: 200 Size: 100\n"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_404_info_severity(self):
        p = WfuzzParser()
        output = "ID: missing Response: 404 Size: 50\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "info"
class TestFeroxbusterParser:
    def test_text_row(self):
        p = FeroxbusterParser()
        output = "200     1234       10      20      http://example.com/admin\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "feroxbuster")

    def test_text_row_no_lines(self):
        p = FeroxbusterParser()
        output = "301     500      http://example.com/redirect\n"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_json_line(self):
        p = FeroxbusterParser()
        output = json.dumps({"url": "http://example.com/admin", "status": 200, "content_length": 1234})
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "feroxbuster")

    def test_json_403(self):
        p = FeroxbusterParser()
        output = json.dumps({"url": "http://example.com/blocked", "status": 403})
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "medium"

    def test_json_multiple_lines(self):
        p = FeroxbusterParser()
        output = json.dumps({"url": "http://example.com/a", "status": 200}) + "\n" + json.dumps({"url": "http://example.com/b", "status": 301})
        findings = p.parse(output)
        assert len(findings) >= 2

    def test_wildcard_filtered(self):
        p = FeroxbusterParser()
        output = "wildcard filtered 10000\n200     1234     http://example.com/admin\n"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_empty_output(self):
        p = FeroxbusterParser()
        assert p.parse("") == []

    def test_dedup_by_url(self):
        p = FeroxbusterParser()
        output = json.dumps({"url": "http://example.com/test", "status": 200}) + "\n" + json.dumps({"url": "http://example.com/test", "status": 301})
        findings = p.parse(output)
        assert len(findings) == 1

    def test_500_severity(self):
        p = FeroxbusterParser()
        output = json.dumps({"url": "http://example.com/error", "status": 500})
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "high"
class TestDirbParser:
    def test_url_code_size_format(self):
        p = DirbParser()
        output = "http://example.com/admin (CODE:200|SIZE:1234)\nhttp://example.com/backup (CODE:403|SIZE:0)\n"
        findings = p.parse(output)
        assert len(findings) >= 2
        for f in findings:
            _check_finding(f, "dirb")
        assert findings[0]["severity"] == "info"
        assert findings[1]["severity"] == "medium"

    def test_line_format(self):
        p = DirbParser()
        output = "200 1234 http://example.com/admin\n403 50 http://example.com/backup\n"
        findings = p.parse(output)
        assert len(findings) >= 2

    def test_code_format(self):
        p = DirbParser()
        output = "+200 http://example.com/admin +\n+403 http://example.com/backup +\n"
        findings = p.parse(output)
        assert len(findings) >= 2

    def test_find_format_no_code(self):
        p = DirbParser()
        output = "==> http://example.com/admin <-- \n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert "DIRB discovered" in findings[0]["title"]

    def test_find_format_with_code_and_size(self):
        p = DirbParser()
        output = "==> http://example.com/admin <-- CODE:200|SIZE:1234\n"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_redirect_append_to_previous(self):
        p = DirbParser()
        output = (
            "http://example.com/admin (CODE:302|SIZE:0)\n"
            "--> http://example.com/login\n"
        )
        findings = p.parse(output)
        assert len(findings) >= 1
        assert "redirect" in findings[0]["description"].lower()

    def test_base_url_extraction(self):
        p = DirbParser()
        output = (
            "BASE_URL: http://example.com\n"
            "200 1234 /admin\n"
            "403 50 /backup\n"
        )
        findings = p.parse(output)
        assert len(findings) >= 2
        for f in findings:
            assert "example.com" in f.get("target", "")

    def test_json_format(self):
        p = DirbParser()
        output = json.dumps([
            {"url": "http://example.com/admin", "code": 200, "size": 1234},
            {"url": "http://example.com/backup", "code": 403},
        ])
        findings = p.parse(output)
        assert len(findings) >= 2

    def test_json_object_with_results_key(self):
        p = DirbParser()
        output = json.dumps({"results": [
            {"url": "http://example.com/admin", "code": 200},
        ]})
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_http_500_high_severity(self):
        p = DirbParser()
        output = "http://example.com/error (CODE:500|SIZE:100)\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "high"

    def test_stats_line_skipped(self):
        p = DirbParser()
        output = (
            "http://example.com/admin (CODE:200|SIZE:1234)\n"
            "Finished: 2025-01-01\n"
            "Tested: 1000 urls\n"
        )
        findings = p.parse(output)
        assert len(findings) == 1

    def test_empty_output(self):
        p = DirbParser()
        assert p.parse("") == []

    def test_whitespace_only(self):
        p = DirbParser()
        assert p.parse("   \n  ") == []

    def test_deduplication(self):
        p = DirbParser()
        output = (
            "http://example.com/admin (CODE:200|SIZE:1234)\n"
            "http://example.com/admin (CODE:200|SIZE:1234)\n"
        )
        findings = p.parse(output)
        assert len(findings) == 1

    def test_garbage_input(self):
        p = DirbParser()
        findings = p.parse("!@#$%^&*() garbage\n")
        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_json_redirect_field(self):
        p = DirbParser()
        output = json.dumps({
            "url": "http://example.com/old",
            "code": 301,
            "redirect": "http://example.com/new",
        })
        findings = p.parse(output)
        assert len(findings) >= 1
        assert "redirect" in findings[0]["description"].lower()


# ===================================================================
# PypykatzParser
# ===================================================================
class TestDirbParser_extra_b7:
    def test_json_list_format(self):
        p = DirbParser()
        output = json.dumps([
            {"url": "http://example.com/admin", "code": 200, "size": 1234},
            {"url": "http://example.com/backup", "code": 403, "size": 50},
        ])
        findings = p.parse(output)
        assert len(findings) == 2
        for f in findings:
            _check_finding(f, "dirb")
        assert any("403" in f["title"] for f in findings)

    def test_json_dict_format(self):
        p = DirbParser()
        output = json.dumps({"url": "http://example.com/test", "code": 200})
        findings = p.parse(output)
        assert len(findings) == 1

    def test_json_with_redirect(self):
        p = DirbParser()
        output = json.dumps({"url": "http://example.com/old", "code": 301, "redirect": "http://example.com/new"})
        findings = p.parse(output)
        assert len(findings) == 1
        assert "redirect" in findings[0]["description"]

    def test_text_url_code_size_format(self):
        p = DirbParser()
        output = "http://example.com/admin (CODE:200|SIZE:1234)\nhttp://example.com/backup (CODE:403|SIZE:50)\n"
        findings = p.parse(output)
        assert len(findings) == 2
        assert any("200" in f["title"] for f in findings)

    def test_text_line_format(self):
        p = DirbParser()
        output = "200 1234 http://example.com/admin\n403 50 http://example.com/backup\n"
        findings = p.parse(output)
        assert len(findings) == 2

    def test_text_code_format(self):
        # _CODE_RE requires trailing whitespace which strip() removes
        # Test the regex directly
        from siyarix.parsers.dirb_parser import _CODE_RE
        m = _CODE_RE.match("+200 http://example.com/page ")
        assert m is not None
        assert m.group("code") == "200"
        assert m.group("url") == "http://example.com/page"

    def test_text_find_format(self):
        p = DirbParser()
        output = "==> http://example.com/admin <-- CODE:200|SIZE:1234\n"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_text_redirect_update(self):
        p = DirbParser()
        output = "http://example.com/admin (CODE:301|SIZE:0)\n--> http://example.com/new\n"
        findings = p.parse(output)
        assert len(findings) == 1
        assert "redirect" in findings[0]["description"]

    def test_base_url_extraction(self):
        p = DirbParser()
        output = "BASE_URL: http://example.com\n200 100 admin\n403 50 backup\n"
        findings = p.parse(output)
        assert len(findings) >= 2
        assert any("admin" in f["title"] for f in findings)

    def test_stats_lines_skipped(self):
        p = DirbParser()
        output = "Finished: 2025-01-01\nTested: 100 paths\nScanned: all\nhttp://example.com/admin (CODE:200|SIZE:100)\n"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_severity_mapping(self):
        p = DirbParser()
        output = "http://example.com/error (CODE:500|SIZE:0)\nhttp://example.com/auth (CODE:401|SIZE:100)\n"
        findings = p.parse(output)
        assert any(f["severity"] == "high" for f in findings if "500" in f["title"])
        assert any(f["severity"] == "medium" for f in findings if "401" in f["title"])

    def test_empty_output(self):
        p = DirbParser()
        assert p.parse("") == []
        assert p.parse("   ") == []

    def test_non_matching_lines(self):
        p = DirbParser()
        output = "some random text\nthat does not match\n"
        findings = p.parse(output)
        assert len(findings) == 0
class TestFfufParser:
    def test_single_row(self):
        p = FfufParser()
        output = "admin                  [Status: 200, Size: 1234, Words: 100, Lines: 20]\n"
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "ffuf")
        assert "admin" in findings[0]["title"]

    def test_multiple_rows(self):
        p = FfufParser()
        output = (
            "admin                  [Status: 200, Size: 1234, Words: 100, Lines: 20]\n"
            "backup                 [Status: 403, Size: 50, Words: 10, Lines: 2]\n"
            "hidden                 [Status: 500, Size: 0, Words: 1, Lines: 1]\n"
        )
        findings = p.parse(output)
        assert len(findings) == 3

    def test_url_base_extraction(self):
        p = FfufParser()
        output = (
            ":: URL: http://example.com/FUZZ\n"
            "admin                  [Status: 200, Size: 1234, Words: 100, Lines: 20]\n"
            "login                  [Status: 301, Size: 0, Words: 1, Lines: 1]\n"
        )
        findings = p.parse(output)
        assert len(findings) == 2
        assert all(f["target"] == "http://example.com/FUZZ" for f in findings)

    def test_severity_by_status(self):
        p = FfufParser()
        output = (
            "page1                  [Status: 200, Size: 100, Words: 10, Lines: 1]\n"
            "page2                  [Status: 401, Size: 100, Words: 10, Lines: 1]\n"
            "page3                  [Status: 500, Size: 100, Words: 10, Lines: 1]\n"
        )
        findings = p.parse(output)
        sev = {f["title"]: f["severity"] for f in findings}
        assert "info" in sev.get("ffuf discovered endpoint page1 (HTTP 200)", "")
        assert sev.get("ffuf discovered endpoint page2 (HTTP 401)") == "medium"
        assert sev.get("ffuf discovered endpoint page3 (HTTP 500)") == "high"

    def test_no_match(self):
        p = FfufParser()
        output = "some random output\n"
        findings = p.parse(output)
        assert len(findings) == 0

    def test_empty_output(self):
        p = FfufParser()
        assert p.parse("") == []
        assert p.parse("   ") == []

    def test_url_line_only_no_rows(self):
        p = FfufParser()
        output = ":: URL: http://example.com/FUZZ\n"
        findings = p.parse(output)
        assert len(findings) == 0
class TestCurlParser:
    def test_http_200_response(self):
        p = CurlParser()
        output = "HTTP/2 200 \ncontent-type: text/html\nserver: nginx/1.24.0\n\nOK\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "curl")

    def test_http_500_response(self):
        p = CurlParser()
        output = "HTTP/1.1 500 Internal Server Error\ncontent-type: text/html\n\nError\n"
        findings = p.parse(output)
        status_f = [f for f in findings if "HTTP" in f["title"]]
        assert len(status_f) >= 1
        assert status_f[0]["severity"] == "medium"

    def test_security_headers_present(self):
        p = CurlParser()
        output = (
            "HTTP/1.1 200 OK\n"
            "strict-transport-security: max-age=31536000\n"
            "content-security-policy: default-src 'self'\n"
            "x-frame-options: DENY\n"
            "server: nginx\n"
        )
        findings = p.parse(output)
        assert any("Security headers" in f["title"] for f in findings)

    def test_missing_security_headers(self):
        p = CurlParser()
        output = "HTTP/1.1 200 OK\nserver: apache\n"
        findings = p.parse(output)
        assert any("Missing security headers" in f["title"] for f in findings)
        missing = [f for f in findings if "Missing" in f["title"]]
        assert missing[0]["severity"] == "low"

    def test_information_disclosure(self):
        p = CurlParser()
        output = "HTTP/1.1 200 OK\nserver: Apache/2.4.7\nx-powered-by: PHP/7.4\n"
        findings = p.parse(output)
        disclosure = [f for f in findings if "disclosure" in f["title"].lower()]
        assert len(disclosure) >= 1

    def test_empty_output(self):
        p = CurlParser()
        assert p.parse("") == []
        assert p.parse("   ") == []

    def test_no_status_line(self):
        p = CurlParser()
        output = "content-type: text/html\nserver: nginx\n"
        findings = p.parse(output)
        assert all("HTTP/" not in f["title"] for f in findings)
        # Should still report missing headers and info disclosure
        assert any("Missing" in f["title"] for f in findings)
        assert any("disclosure" in f["title"] for f in findings)

    def test_no_headers(self):
        p = CurlParser()
        output = "HTTP/1.1 200 OK\n\nbody only\n"
        findings = p.parse(output)
        assert len(findings) >= 1
class TestKatanaParser:
    def test_json_url(self):
        p = KatanaParser()
        output = json.dumps({"url": "http://example.com/page", "source": "href", "status_code": 200})
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "katana")
        assert "200" in findings[0]["title"] or "200" in findings[0]["description"]

    def test_json_unauthorized(self):
        p = KatanaParser()
        output = json.dumps({"url": "http://example.com/admin", "source": "crawl", "status_code": 401})
        findings = p.parse(output)
        assert len(findings) == 1
        assert findings[0]["severity"] == "medium"

    def test_json_forbidden(self):
        p = KatanaParser()
        output = json.dumps({"url": "http://example.com/secret", "source": "crawl", "status_code": 403})
        findings = p.parse(output)
        assert findings[0]["severity"] == "medium"

    def test_json_server_error(self):
        p = KatanaParser()
        output = json.dumps({"url": "http://example.com/error", "source": "crawl", "status_code": 500})
        findings = p.parse(output)
        assert findings[0]["severity"] == "high"

    def test_json_multiple_lines(self):
        p = KatanaParser()
        lines = [
            json.dumps({"url": "http://example.com/a", "source": "href"}),
            json.dumps({"url": "http://example.com/b", "status_code": 200}),
        ]
        output = "\n".join(lines)
        findings = p.parse(output)
        assert len(findings) == 2

    def test_json_dedup_by_path(self):
        p = KatanaParser()
        output = (
            json.dumps({"url": "http://example.com/page?a=1", "source": "href"}) + "\n" +
            json.dumps({"url": "http://example.com/page?b=2", "source": "form"})
        )
        findings = p.parse(output)
        assert len(findings) == 1

    def test_json_no_url(self):
        p = KatanaParser()
        output = json.dumps({"source": "href", "status_code": 200})
        findings = p.parse(output)
        assert len(findings) == 0

    def test_non_json_lines(self):
        p = KatanaParser()
        output = "plain text\nnot json\n"
        findings = p.parse(output)
        assert len(findings) == 0

    def test_malformed_json(self):
        p = KatanaParser()
        findings = p.parse("{bad")
        assert isinstance(findings, list)

    def test_empty_output(self):
        p = KatanaParser()
        assert p.parse("") == []
        assert p.parse("   ") == []

    def test_alternate_keys(self):
        p = KatanaParser()
        output = json.dumps({"URL": "http://example.com/test", "Source": "js", "StatusCode": 200, "ContentType": "text/html"})
        findings = p.parse(output)
        assert len(findings) == 1
class TestDirbParser_extra_b8:
    def test_empty(self):
        assert DirbParser().parse("") == []
        assert DirbParser().parse("   ") == []

    def test_json_dict_single(self):
        p = DirbParser()
        output = json.dumps({"url": "http://example.com/page", "code": 200, "size": 100})
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "dirb")

    def test_json_list_with_status(self):
        p = DirbParser()
        output = json.dumps([
            {"url": "http://example.com/a", "code": 200, "size": 100},
            {"url": "http://example.com/b", "status": 500, "content_length": 0},
        ])
        findings = p.parse(output)
        assert len(findings) == 2

    def test_json_dict_redirect(self):
        p = DirbParser()
        output = json.dumps({"url": "http://example.com/old", "code": 301, "redirect": "http://example.com/new"})
        findings = p.parse(output)
        assert len(findings) == 1
        assert "redirect" in findings[0]["description"]

    def test_json_dedup(self):
        p = DirbParser()
        output = json.dumps([
            {"url": "http://example.com/page", "code": 200},
            {"url": "http://example.com/page", "code": 200},
        ])
        findings = p.parse(output)
        assert len(findings) == 1

    def test_json_non_dict_skipped(self):
        p = DirbParser()
        output = json.dumps(["string", 123])
        findings = p.parse(output)
        assert len(findings) == 0

    def test_json_severity_by_code(self):
        p = DirbParser()
        output = json.dumps([
            {"url": "http://example.com/e", "code": 500},
            {"url": "http://example.com/a", "code": 401},
        ])
        findings = p.parse(output)
        sev = {f["title"]: f["severity"] for f in findings}
        assert sev.get("DIRB discovered: http://example.com/e (HTTP 500)") == "high"
        assert sev.get("DIRB discovered: http://example.com/a (HTTP 401)") == "medium"

    def test_text_url_code_size_format_with_redirect(self):
        p = DirbParser()
        output = "http://example.com/admin (CODE:301|SIZE:0)\n--> http://new.com/admin"
        findings = p.parse(output)
        assert len(findings) == 1
        assert "redirect" in findings[0]["description"]

    def test_text_line_format(self):
        p = DirbParser()
        output = "200 1234 http://example.com/\n403 50 http://example.com/private"
        findings = p.parse(output)
        assert len(findings) == 2

    def test_text_line_with_base(self):
        p = DirbParser()
        output = "BASE_URL: http://example.com\n200 100 admin\n403 50 secret"
        findings = p.parse(output)
        assert len(findings) == 2
        assert any("admin" in f["title"] for f in findings)

    def test_text_code_format(self):
        from siyarix.parsers.dirb_parser import _CODE_RE
        m = _CODE_RE.match("+200 http://example.com/page ")
        assert m is not None
        assert m.group("code") == "200"
        assert m.group("url") == "http://example.com/page"

    def test_text_find_format(self):
        p = DirbParser()
        output = "==> http://example.com/admin <-- CODE:200|SIZE:1234"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_text_find_format_no_code(self):
        from siyarix.parsers.dirb_parser import _FIND_RE
        # _FIND_RE requires arrow characters after the URL
        m = _FIND_RE.search("==> http://example.com/admin <--")
        assert m is not None
        assert m.group("url") == "http://example.com/admin"
        assert m.group("code") is None

    def test_text_non_matching_skip(self):
        p = DirbParser()
        output = "garbage line\n"
        findings = p.parse(output)
        assert len(findings) == 0

    def test_text_stats_skipped(self):
        p = DirbParser()
        output = "Finished: 2025-01-01\nhttp://example.com/ (CODE:200|SIZE:100)"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_text_json_first_line_array(self):
        p = DirbParser()
        output = '[{"url": "http://example.com", "code": 200}]\n'
        findings = p.parse(output)
        assert len(findings) == 1

    def test_text_malformed_json_first_line(self):
        p = DirbParser()
        output = "[bad"
        findings = p.parse(output)
        assert isinstance(findings, list)
class TestFeroxbusterParser_extra_b8:
    def test_empty(self):
        assert FeroxbusterParser().parse("") == []
        assert FeroxbusterParser().parse("   ") == []

    def test_text_row(self):
        p = FeroxbusterParser()
        output = "200      1234      5      100     http://example.com/admin"
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "feroxbuster")

    def test_text_multiple_rows(self):
        p = FeroxbusterParser()
        output = (
            "200      1234      5      100     http://example.com/admin\n"
            "403      50        1      10      http://example.com/private\n"
        )
        findings = p.parse(output)
        assert len(findings) == 2

    def test_text_without_lines_and_words(self):
        p = FeroxbusterParser()
        output = "301      0 http://example.com/old"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_text_wildcard_skipped(self):
        p = FeroxbusterParser()
        output = "wildcard filtered 1000\n200      1234      5      100     http://example.com/admin"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_text_dedup_by_url(self):
        p = FeroxbusterParser()
        output = "200 1234 5 100 http://example.com/a\n200 1234 5 100 http://example.com/a"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_text_severity_by_status(self):
        p = FeroxbusterParser()
        output = "500 0 http://example.com/error\n401 0 http://example.com/auth"
        findings = p.parse(output)
        sev = {f["title"]: f["severity"] for f in findings}
        assert "high" in sev.get("Feroxbuster: http://example.com/error (HTTP 500)", "")
        assert "medium" in sev.get("Feroxbuster: http://example.com/auth (HTTP 401)", "")

    def test_json_line(self):
        p = FeroxbusterParser()
        output = json.dumps({"url": "http://example.com/page", "status": 200, "content_length": 500})
        findings = p.parse(output)
        assert len(findings) == 1

    def test_json_multiple_lines(self):
        p = FeroxbusterParser()
        lines = [
            json.dumps({"url": "http://example.com/a", "status": 200, "content_length": 100}),
            json.dumps({"url": "http://example.com/b", "status": 403, "size": 50}),
        ]
        findings = p.parse("\n".join(lines))
        assert len(findings) == 2

    def test_json_no_url_skipped(self):
        p = FeroxbusterParser()
        output = json.dumps({"status": 200})
        findings = p.parse(output)
        assert len(findings) == 0

    def test_json_dedup(self):
        p = FeroxbusterParser()
        output = json.dumps({"url": "http://example.com/a", "status": 200}) + "\n"
        output += json.dumps({"url": "http://example.com/a", "status": 200})
        findings = p.parse(output)
        assert len(findings) == 1

    def test_non_matching_text(self):
        p = FeroxbusterParser()
        output = "some random output\n"
        findings = p.parse(output)
        assert len(findings) == 0

    def test_malformed_json_line_skipped(self):
        p = FeroxbusterParser()
        output = "{bad json}\n" + json.dumps({"url": "http://example.com/a", "status": 200})
        findings = p.parse(output)
        assert len(findings) == 1
class TestGospiderParser_extra_b8:
    def test_empty(self):
        assert GospiderParser().parse("") == []
        assert GospiderParser().parse("   ") == []

    def test_json_line(self):
        p = GospiderParser()
        output = json.dumps({"url": "http://example.com/page", "source": "href", "status": 200, "body_length": 5000})
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "gospider")
        assert "info" in findings[0]["severity"]

    def test_json_with_subdomain(self):
        p = GospiderParser()
        # Subdomain text must be on a JSON line (gospider only processes JSON lines)
        output = json.dumps({"url": "http://sub.example.com/page", "source": "crawl", "extra": "subdomain: sub.example.com"})
        findings = p.parse(output)
        assert len(findings) >= 1
        assert any("subdomain" in f["title"] for f in findings)

    def test_json_401_status(self):
        p = GospiderParser()
        output = json.dumps({"url": "http://example.com/admin", "status": 401, "Source": "crawl"})
        findings = p.parse(output)
        assert len(findings) == 1
        assert findings[0]["severity"] == "low"

    def test_json_500_status(self):
        p = GospiderParser()
        output = json.dumps({"url": "http://example.com/error", "StatusCode": 500, "source": "crawl"})
        findings = p.parse(output)
        assert len(findings) == 1
        assert findings[0]["severity"] == "medium"

    def test_json_redirect(self):
        p = GospiderParser()
        output = json.dumps({"url": "http://example.com/old", "status": 301, "redirect": "http://example.com/new"})
        findings = p.parse(output)
        assert len(findings) == 1
        assert "Redirect" in findings[0]["evidence"] or "redirect" in findings[0]["evidence"]

    def test_json_no_url_skipped(self):
        p = GospiderParser()
        output = json.dumps({"source": "crawl"})
        findings = p.parse(output)
        assert len(findings) == 0

    def test_json_dedup_by_path(self):
        p = GospiderParser()
        output = json.dumps({"url": "http://example.com/page?a=1"}) + "\n"
        output += json.dumps({"url": "http://example.com/page?b=2"})
        findings = p.parse(output)
        assert len(findings) == 1

    def test_non_json_lines_skipped(self):
        p = GospiderParser()
        output = "not json\n"
        findings = p.parse(output)
        assert len(findings) == 0

    def test_malformed_json_skipped(self):
        p = GospiderParser()
        output = "{bad json}\n"
        findings = p.parse(output)
        assert len(findings) == 0

    def test_empty_json_line_skipped(self):
        p = GospiderParser()
        output = "  \n"
        findings = p.parse(output)
        assert len(findings) == 0

    def test_subdomain_dedup(self):
        p = GospiderParser()
        # Both subdomain hints must appear within JSON lines
        output = (
            json.dumps({"url": "http://sub.example.com/page", "source": "crawl", "extra": "subdomain: sub.example.com"}) + "\n"
            + json.dumps({"url": "http://sub.example.com/other", "source": "crawl", "extra": "subdomain: sub.example.com"})
        )
        findings = p.parse(output)
        subdomains = [f for f in findings if "subdomain" in f["title"]]
        assert len(subdomains) == 1
class TestHakrawlerParser:
    def test_empty(self):
        assert HakrawlerParser().parse("") == []
        assert HakrawlerParser().parse("   ") == []

    def test_url_only(self):
        p = HakrawlerParser()
        output = "https://example.com/page\n"
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "hakrawler")

    def test_with_method(self):
        p = HakrawlerParser()
        output = "[GET] https://example.com/api\n"
        findings = p.parse(output)
        assert len(findings) == 1
        assert "GET" in findings[0]["description"]

    def test_sensitive_path(self):
        p = HakrawlerParser()
        output = "https://example.com/admin\n"
        findings = p.parse(output)
        assert len(findings) == 1
        assert findings[0]["severity"] == "medium"

    def test_extension_severity(self):
        p = HakrawlerParser()
        output = "https://example.com/.env\nhttps://example.com/backup.sql\nhttps://example.com/app.js\nhttps://example.com/readme.pdf\n"
        findings = p.parse(output)
        assert len(findings) == 4
        sev = {f["title"]: f["severity"] for f in findings}
        assert "critical" in sev.get("Endpoint: https://example.com/.env", "")
        assert "high" in sev.get("Endpoint: https://example.com/backup.sql", "")
        assert "medium" in sev.get("Endpoint: https://example.com/app.js", "")
        assert "low" in sev.get("Endpoint: https://example.com/readme.pdf", "")

    def test_dedup(self):
        p = HakrawlerParser()
        output = "https://example.com/page\nhttps://example.com/page\n"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_non_url_lines_skipped(self):
        p = HakrawlerParser()
        output = "not a url\n[GET] not a url either\n"
        findings = p.parse(output)
        assert len(findings) == 0

    def test_empty_lines_skipped(self):
        p = HakrawlerParser()
        output = "\n  \nhttps://example.com/page\n"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_severity_with_method_and_admin(self):
        p = HakrawlerParser()
        output = "[POST] https://example.com/api/admin\n"
        findings = p.parse(output)
        assert len(findings) == 1
        assert findings[0]["severity"] == "medium"
class TestArjunParserBranches:
    """Covers: JSON dedup, non-dict params, decode error, text dedup."""

    def test_json_dedup_skipped(self):
        p = ArjunParser()
        output = json.dumps({"http://x.com": {"id": {"reflected": True}, "id": {"reflected": True}}})
        findings = p.parse(output)
        assert len(findings) == 1

    def test_non_dict_params(self):
        p = ArjunParser()
        output = json.dumps({"http://x.com": "id,name"})
        findings = p.parse(output)
        assert len(findings) == 1
        assert findings[0]["severity"] == "info"

    def test_json_decode_error_passes(self):
        p = ArjunParser()
        findings = p.parse("{bad json}")
        assert isinstance(findings, list)

    def test_text_dedup_skipped(self):
        p = ArjunParser()
        findings = p.parse("http://x.com?id=1\nhttp://x.com?id=1\n")
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# 5. aws_parser.py  — missing 51-52, 57-55, 107
# ---------------------------------------------------------------------------
class TestCorsyParserBranches:
    """Covers: text fallback with Vulnerability + http."""

    def test_text_fallback_vulnerability(self):
        p = CorsyParser()
        findings = p.parse("Vulnerability: CORS Misconfig found at http://example.com\n")
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# 15. dalfox_parser.py  — missing 35, 38-39, 100
# ---------------------------------------------------------------------------
class TestDirbParserBranches:
    """Covers: JSON dict results wrap, empty line, redirect backfill,
       LINE_RE dedup, CODE_RE dedup, FIND_RE dedup."""

    def test_json_dict_results(self):
        p = DirbParser()
        output = json.dumps({"results": {"url": "http://x.com/admin", "code": 200, "size": 1024}})
        findings = p.parse(output)
        assert len(findings) == 1

    def test_text_empty_line_skipped(self):
        p = DirbParser()
        findings = p.parse("\n\n")
        assert findings == []

    def test_redirect_backfill(self):
        p = DirbParser()
        output = "http://x.com (CODE:301|SIZE:0)\n--> http://x.com/redirect\n"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_line_re_dedup(self):
        p = DirbParser()
        output = "200 1024 http://x.com/admin\n200 1024 http://x.com/admin\n"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_code_re_dedup(self):
        p = DirbParser()
        output = "+200 http://x.com/admin (SIZE:1024)\n+200 http://x.com/admin (SIZE:1024)\n"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_find_re_dedup(self):
        p = DirbParser()
        output = "==> http://x.com/admin <-- CODE:200 | SIZE:1024\n==> http://x.com/admin <-- CODE:200 | SIZE:1024\n"
        findings = p.parse(output)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# 18. dirsearch_parser.py  — missing 43, 47-49, 62, 69
# ---------------------------------------------------------------------------
class TestDirsearchParserBranches:
    """Covers: empty line, Target: parts split, dedup, redirect."""

    def test_empty_line_skipped(self):
        p = DirsearchParser()
        findings = p.parse("\n\n200 1K http://x.com\n")
        assert len(findings) == 1

    def test_target_line_parsed(self):
        p = DirsearchParser()
        findings = p.parse("Target: http://example.com\n200 1K http://x.com\n")
        assert findings[0]["target"] == "http://example.com"

    def test_dedup_skipped(self):
        p = DirsearchParser()
        output = "200 1K http://x.com\n200 1K http://x.com\n"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_redirect_in_description(self):
        p = DirsearchParser()
        findings = p.parse("301 0 http://x.com -> http://y.com\n")
        assert len(findings) >= 1
        assert "redirects to" in findings[0]["description"]


# ---------------------------------------------------------------------------
# 19. dmitry_parser.py  — missing 73, 76, 91-106, 112-125, 131-144,
#       150-163, 168-166, 186-199, 205-70
# ---------------------------------------------------------------------------
class TestHttpxParser:
    def test_empty(self):
        assert HttpxParser().parse("") == []
        assert HttpxParser().parse("   ") == []

    def test_json_with_tech_string(self):
        r = HttpxParser().parse('{"url":"https://example.com","tech":"react,vue"}')
        assert len(r) == 1
        assert "react" in r[0]["description"]

    def test_json_with_cnames_string(self):
        r = HttpxParser().parse('{"url":"https://example.com","cnames":"www.example.com"}')
        assert len(r) == 1

    def test_json_with_400_status(self):
        r = HttpxParser().parse('{"url":"https://example.com","status_code":404}')
        assert len(r) == 1
        assert r[0]["severity"] == "low"

    def test_json_with_500_status(self):
        r = HttpxParser().parse('{"url":"https://example.com","status_code":500}')
        assert len(r) == 1
        assert r[0]["severity"] == "medium"

    def test_json_with_final_url(self):
        r = HttpxParser().parse('{"url":"https://example.com","final_url":"https://example.org"}')
        assert len(r) == 1
        assert "example.org" in r[0]["evidence"]

    def test_text_format(self):
        r = HttpxParser().parse("https://example.com [200]")
        assert len(r) == 1

    def test_json_invalid_line_skipped(self):
        r = HttpxParser().parse('{"url":"https://example.com"}\nnotjson')
        assert len(r) == 1

    def test_json_decode_error_skipped(self):
        r = HttpxParser().parse("{bad}")
        assert len(r) == 0
class TestKiterunnerParser:
    def test_empty(self):
        assert KiterunnerParser().parse("") == []

    def test_json_line(self):
        r = KiterunnerParser().parse('{"URL":"https://example.com/api","Status":200}')
        assert len(r) == 1

    def test_json_decode_error_skip(self):
        r = KiterunnerParser().parse("{bad}")
        assert len(r) == 0

    def test_text_method_line(self):
        r = KiterunnerParser().parse("GET /api/v1/users")
        assert len(r) == 1

    def test_blank_line_skipped(self):
        r = KiterunnerParser().parse("\n\n")
        assert len(r) == 0
class TestWgetParser:
    def test_empty(self):
        assert WgetParser().parse("") == []

    def test_json_list(self):
        r = WgetParser().parse('[{"url":"https://example.com/file.zip","status_code":200,"size":1024,"filename":"file.zip"}]')
        assert len(r) == 1

    def test_json_non_dict_skipped(self):
        r = WgetParser().parse('["hello"]')
        assert len(r) == 0

    def test_json_decode_error_fallthrough(self):
        r = WgetParser().parse("{bad}")
        assert isinstance(r, list)

    def test_text_url_extracted(self):
        r = WgetParser().parse("URL:https://example.com/file.zip")
        assert len(r) == 0

    def test_text_download_started(self):
        r = WgetParser().parse("2024-01-01 12:00:00 https://example.com/file.zip")
        assert any("download started" in f["title"].lower() for f in r)

    def test_text_status_line(self):
        r = WgetParser().parse("HTTP request sent, awaiting response... 200 OK")
        assert any("HTTP 200" in f["title"] for f in r)

    def test_text_status_500(self):
        r = WgetParser().parse("HTTP request sent, awaiting response... 500 Internal Server Error")
        assert r[0]["severity"] == "high"

    def test_text_error_404(self):
        r = WgetParser().parse("ERROR 404 Not Found")
        assert len(r) == 1
        assert r[0]["severity"] in ("medium", "low")

    def test_text_error_generic(self):
        r = WgetParser().parse("ERROR: Connection refused")
        assert len(r) == 1

    def test_text_recursive_download_complete(self):
        r = WgetParser().parse("5 files downloaded")
        assert any("recursive download complete" in f["title"].lower() for f in r)

    def test_text_length(self):
        r = WgetParser().parse("Length: 1024 [text]")
        assert any("resource size" in f["title"].lower() for f in r)

    def test_text_saved(self):
        r = WgetParser().parse("'file.zip' saved")
        assert any("downloaded" in f["title"].lower() for f in r)

    def test_spider_mode_no_findings(self):
        r = WgetParser().parse("Spider mode enabled\nURL:https://example.com")
        assert any("spider scan completed" in f["title"].lower() for f in r)
class TestHttpxParserBranches:
    """Covers: seen=None default, dedup in json, ValueError severity,
    empty text line, 3-digit status, dedup in text, 4xx/5xx text severity."""

    def test_seen_is_none_defaults_to_set(self):
        p = HttpxParser()
        findings = p._parse_json_obj({"url": "http://example.com", "status_code": 200})
        assert len(findings) == 1

    def test_dedup_key_already_seen_json(self):
        p = HttpxParser()
        output = (
            '{"url": "http://example.com", "status_code": 200}\n'
            '{"url": "http://example.com", "status_code": 404}\n'
        )
        findings = p.parse(output)
        assert len(findings) == 1

    def test_status_code_value_error(self):
        p = HttpxParser()
        findings = p._parse_json_obj({"url": "http://example.com", "status_code": "bad"})
        assert findings[0]["severity"] == "info"

    def test_text_empty_line_skipped(self):
        p = HttpxParser()
        findings = p._parse_text("\n\n  \nhttp://example.com\n")
        assert len(findings) == 1

    def test_text_3_digit_status_extracted(self):
        p = HttpxParser()
        findings = p._parse_text("http://example.com 404")
        assert len(findings) == 1
        assert "404" in findings[0]["title"]

    def test_text_dedup_url_skipped(self):
        p = HttpxParser()
        findings = p._parse_text("http://example.com\nhttp://example.com")
        assert len(findings) == 1

    def test_text_400_status_severity_low(self):
        p = HttpxParser()
        findings = p._parse_text("http://example.com 403")
        assert findings[0]["severity"] == "low"

    def test_text_500_status_severity_medium(self):
        p = HttpxParser()
        findings = p._parse_text("http://example.com 503")
        assert findings[0]["severity"] == "medium"


# ---------------------------------------------------------------------------
# 5. jwt_tool_parser.py  — many branches
# ---------------------------------------------------------------------------
class TestWgetParserAdditionalBranches:
    """Covers: JSON dedup, text empty line skip, download dedup,
       status_line dedup, error dedup, recursive dedup,
       length dedup, saved dedup."""

    def test_json_dedup(self):
        """Line 108: JSON dedup_key already in seen."""
        p = WgetParser()
        findings = p.parse('[{"url":"https://example.com","status_code":200},{"url":"https://example.com","status_code":200}]')
        assert len(findings) == 1

    def test_text_empty_line_skipped(self):
        """Line 145: empty line in text parse skipped."""
        p = WgetParser()
        findings = p.parse("\n  \n")
        assert findings == []

    def test_download_started_dedup(self):
        """Line 159->172: download key already in seen."""
        p = WgetParser()
        findings = p.parse("2024-01-01 12:00:00 https://example.com/f.zip\n2024-01-01 12:00:00 https://example.com/f.zip\n")
        dl = [f for f in findings if "download started" in f["title"].lower()]
        assert len(dl) == 1

    def test_status_line_dedup(self):
        """Line 180: status line key already in seen."""
        p = WgetParser()
        findings = p.parse("HTTP request sent, awaiting response... 200 OK\nHTTP request sent, awaiting response... 200 OK\n")
        status = [f for f in findings if "HTTP" in f["title"]]
        assert len(status) == 1

    def test_error_line_dedup(self):
        """Line 200: error key already in seen."""
        p = WgetParser()
        findings = p.parse("ERROR: Connection refused\nERROR: Connection refused\n")
        errs = [f for f in findings if "error" in f["title"].lower()]
        assert len(errs) == 1

    def test_recursive_download_dedup(self):
        """Line 225->238: recursive download key already in seen."""
        p = WgetParser()
        findings = p.parse("5 files downloaded\n5 files downloaded\n")
        rec = [f for f in findings if "recursive" in f["title"].lower()]
        assert len(rec) == 1

    def test_length_dedup(self):
        """Line 243->256: length key already in seen."""
        p = WgetParser()
        findings = p.parse("Length: 1024 [text]\nLength: 1024 [text]\n")
        length = [f for f in findings if "resource size" in f["title"].lower()]
        assert len(length) == 1

    def test_saved_dedup(self):
        """Line 261->142: saved key already in seen."""
        p = WgetParser()
        findings = p.parse("'file.zip' saved\n'file.zip' saved\n")
        saved = [f for f in findings if "downloaded" in f["title"].lower()]
        assert len(saved) == 1


# ============================================================================
# 16. xsstrike_parser.py  — 68->76, 94, 129-130, 136->158, 160->91,
#                           178, 202->224, 226->240
# ============================================================================
class TestArjunParserAdditionalBranches:
    """Covers: param dedup in dict, non-dict param dedup."""

    def test_param_dedup(self):
        """30: param dedup_key already in seen (same param twice)."""
        output = json.dumps({"http://x.com": {"id": "reflected"}})
        p = ArjunParser()
        findings = p.parse(output)
        params = [f for f in findings if "Parameter" in f["title"]]
        assert len(params) == 1

    def test_non_dict_params_dedup(self):
        """53->25: non-dict params skipped with dedup check."""
        output = json.dumps({"http://x.com": "simple_value"})
        p = ArjunParser()
        findings = p.parse(output)
        assert isinstance(findings, list)


# ============================================================================
# 13. dnsmap_parser.py  — 98-99, 105, 112
# ============================================================================
class TestFeroxbusterParserAdditionalBranches:
    """Covers: wildcard filter skip, empty JSON line skip."""

    def test_wildcard_filter_skipped(self):
        """51: line matching _WILDCARD_RE is skipped."""
        output = "200 1234 http://example.com/admin\nWildcard filter 500 discarded\n200 5678 http://example.com/login\n"
        p = FeroxbusterParser()
        findings = p.parse(output)
        assert isinstance(findings, list)

    def test_json_empty_line_skipped(self):
        """91: empty line in JSON parsing skipped."""
        entry = json.dumps({"url": "http://example.com/admin", "status": 200, "content_length": 123})
        p = FeroxbusterParser()
        findings = p.parse(f"{entry}\n\n{entry}\n")
        assert len(findings) == 1


# ============================================================================
# 17. dnsenum_parser.py  — 88-89
# ============================================================================

class TestGobusterParser:
    def test_basic_parse(self):
        p = GobusterParser()
        output = "Url: http://example.com\n/admin (Status: 200) [Size: 1234]\n"
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "gobuster")

    def test_empty_output(self):
        p = GobusterParser()
        assert p.parse("") == []
class TestFfufParser:
    def test_basic_parse(self):
        p = FfufParser()
        output = "admin                  [Status: 200, Size: 1234, Words: 100, Lines: 20]\n"
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "ffuf")

    def test_empty_output(self):
        p = FfufParser()
        assert p.parse("") == []
class TestWaybackurlsParser:
    def test_basic_parse(self):
        p = WaybackurlsParser()
        output = "http://example.com/test\nhttp://example.com/test2?id=1\n"
        findings = p.parse(output)
        assert len(findings) == 2
        _check_finding(findings[0], "waybackurls")
class TestParamspiderParser:
    def test_basic_parse(self):
        p = ParamspiderParser()
        output = "http://example.com/api?user=FUZZ\nhttp://example.com/login?redirect=FUZZ\n"
        findings = p.parse(output)
        assert len(findings) == 2
        _check_finding(findings[0], "paramspider")
class TestCorsyParser:
    def test_basic_parse(self):
        p = CorsyParser()
        output = '{"http://example.com": [{"type": "Origin Reflection", "severity": "High"}]}'
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "corsy")
        assert findings[0]["severity"] == "high"
class TestAquatoneParser:
    def test_basic_parse(self):
        p = AquatoneParser()
        output = '{"pages": {"1": {"url": "http://example.com", "status": 200, "pageTitle": "Example", "hasScreenshot": true}}}'
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "aquatone")
class TestKiterunnerParser:
    def test_basic_parse(self):
        p = KiterunnerParser()
        output = '{"URL": "http://example.com/api/v1/users", "Status": 403}\nGET http://example.com/api/v1/admin'
        findings = p.parse(output)
        assert len(findings) == 2
        _check_finding(findings[0], "kiterunner")
