"""Debug script to test which parsers work with which samples."""
import sys
sys.path.insert(0, 'src')
from siyarix.parsers import ParserRegistry

reg = ParserRegistry()
reg.discover()

test_cases = {
    'aircrack-ng': 'KEY FOUND! [ secretpass ]\nMaster Key: 1234ABCD\n',
    'bloodhound-python': 'INFO: Found 3 domains\nINFO: Found 5 computers\nINFO: Found 10 users\n',
    'crowbar': '2025-01-01 12:00:00 RDP successfully logged into 10.0.0.1:3389 with user admin and password Passw0rd!\n',
    'dirb': 'http://example.com/admin (CODE:200|SIZE:1234)\nhttp://example.com/backup (CODE:403|SIZE:0)\n',
    'dnsmap': 'sub1.example.com (1.2.3.4)\nsub2.example.com (5.6.7.8)\n',
    'dnsrecon': '[*] A sub1.example.com 1.2.3.4\n[*] A sub2.example.com 5.6.7.8\n',
    'lynis': '[!] some warning message\n[+] some positive finding\n[-] Some negative issue\n',
    'medusa': 'ACCOUNT FOUND: [ssh] Host: 10.0.0.1 User: root Password: toor [SUCCESS]\nACCOUNT FOUND: [ftp] Host: 10.0.0.1 User: admin Password: admin [SUCCESS]\n',
    'recon-ng': "[*] Recon module: whois_pocs\n[+] admin@example.com found.\n[+] tech@example.com found.\n",
    'sherlock': '[+] GitHub: https://github.com/user1\n[+] Twitter: https://twitter.com/user1\n[+] Reddit: https://reddit.com/user/user1\n',
    'sslscan': 'Preferred: TLSv1.2  TLS_ECDHE_RSA_AES_128_GCM_SHA256  256 bits\nTLSv1.0: Disabled\nTLSv1.1: Disabled\nTLSv1.2: Enabled\n',
    'dnsx': '{"host":"example.com","type":"A","a":"1.2.3.4"}\n{"host":"example.org","type":"AAAA","a":"::1"}\n',
    'findomain': '{"domain":"sub1.example.com","ip_address":"1.2.3.4"}\n{"domain":"sub2.example.com","ip_address":"5.6.7.8"}\n{"domain":"sub3.example.com","ip_address":"9.10.11.12"}\n',
    'gitleaks': '{"line":"password=supersecret","file":".env","ruleID":"Generic API Key","secret":"supersecret","severity":"high"}\n{"line":"token=abcdef","file":"config.js","ruleID":"Token","secret":"abcdef","severity":"medium"}\n',
    'gospider': '{"url":"http://example.com/admin","source":"crawl","status":200}\n{"url":"http://example.com/login","source":"crawl","status":301}\n{"url":"http://example.com/api","source":"crawl","status":403}\n',
    'gowitness': '[{"url":"http://example.com","status_code":200,"title":"Example","screenshot_path":"test.png"},{"url":"http://example.org","status_code":301,"title":"Moved","screenshot_path":"test2.png"}]',
    'interactsh': '{"protocol":"HTTP","unique-id":"abc123","remote-address":"1.2.3.4","timestamp":"2025-01-01T12:00:00Z","raw-request":"GET /test"}\n{"protocol":"DNS","unique-id":"def456","remote-address":"5.6.7.8","timestamp":"2025-01-01T12:00:01Z","raw-request":"example.com A"}\n',
    'katana': '{"url":"http://example.com/admin","source":"href","status_code":200}\n{"url":"http://example.com/login","source":"form","status_code":301}\n{"url":"http://example.com/api","source":"href","status_code":403}\n',
    'prowler': '{"Control":"s3_bucket_public_access","Status":"FAIL","Severity":"high","Region":"us-east-1","ResourceArn":"arn:aws:s3:::test-bucket"}\n',
    'semgrep': '{"results":[{"check_id":"sql-injection","path":"app.py","start":{"line":12},"extra":{"severity":"HIGH","message":"SQL injection detected"}},{"check_id":"hardcoded-secret","path":"auth.py","start":{"line":45},"extra":{"severity":"MEDIUM","message":"Hardcoded secret"}}],"totals":{"found":2}}\n',
    'zgrab': '{"ip":"10.0.0.1","domain":"example.com","http":{"status":"success","status_code":200,"title":"Index of /"}}\n{"ip":"10.0.0.2","domain":"example.org","tls":{"status":"success","handshake_done":true}}\n',
    'dnstwist': '[{"domain":"example.com","fuzzed":"example.org","dns-a":["1.2.3.4"],"score":75},{"domain":"example.com","fuzzed":"examp1e.com","dns-a":["5.6.7.8"],"score":50}]',
    'exiftool': '{"SourceFile":"image.jpg","Make":"Canon","Model":"EOS 5D","Software":"Adobe Photoshop"}',
    'mimikatz': '{"username":"Admin","domain":"EXAMPLE","ntlm":"31d6cfe0d16ae931b73c59d7e0c089c1","password":"Passw0rd!"}\n',
    'scoutsuite': '{"services":{"ec2":{"findings":{"ec2-public-snapshot":{"description":"Public snapshot","level":"high"}}}},"rule_results":{"iam-user-keys":{"level":"medium","items":["admin@123456789012"]}}}',
    'bloodhound': '{"data":[{"Label":"ADMIN@EXAMPLE.LOCAL","ObjectId":"S-1-5-21-1234-500","ObjectType":"User"}]}',
    's3scanner': 'test-bucket - OPEN\nprivate-bucket - AUTH\nmore-bucket - OPEN\n',
    'bettercap': '[12:34:56] [sys.log] [mitm] spoofing detected on 192.168.1.1\n[12:34:57] [sys.log] [endpoint] new device 192.168.1.2 00:11:22:33:44:55\n',
    'shodan': '{"ip_str":"1.2.3.4","org":"Test Corp","os":"Linux","ports":[80,443],"vulns":["CVE-2023-1234","CVE-2023-5678"]}',
    'testssl': 'Testing results for example.com:443\nTLS 1.2  offered (OK)\nTLS 1.1  offered (NOT ok)\nTLS 1.0  offered (NOT ok)\n',
    'dirsearch': 'Target: http://example.com\n200 1234 http://example.com/admin\n301 0 http://example.com/backup\n403 50 http://example.com/.htaccess\n',
    'dnsenum': "Host's addresses:\n  sub1.example.com...................... [A: 1.2.3.4]\n\nBrute Force:\n  www.example.com....................... [A: 5.6.7.8]\n",
    'kerbrute': '2025/01/01 12:00:00 >  [+] VALID USER: admin@example.local\n2025/01/01 12:00:01 >  [+] VALID USER: svc_account@example.local\n',
}

for tool, sample in sorted(test_cases.items()):
    findings = reg.parse(tool, sample)
    print(f'{tool}: {len(findings)} findings')
    for f in findings[:2]:
        print(f'  title={f.get("title","")[:60]} sev={f.get("severity","")}')
