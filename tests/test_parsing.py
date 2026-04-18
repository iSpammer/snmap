#!/usr/bin/env python3
"""Unit tests for SmartNmap critical parsing/helper functions.

Run with:  python3 -m pytest tests/ -v
Or simply: python3 tests/test_parsing.py
"""
import sys
import os
import tempfile
import unittest
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import smartnmap  # noqa: E402


class TestCIDRExpansion(unittest.TestCase):
    def test_single_ip(self):
        is_range, hosts = smartnmap.expand_cidr_targets('10.0.0.1')
        self.assertFalse(is_range)
        self.assertEqual(hosts, ['10.0.0.1'])

    def test_cidr_32(self):
        is_range, hosts = smartnmap.expand_cidr_targets('10.0.0.1/32')
        self.assertFalse(is_range)
        self.assertEqual(hosts, ['10.0.0.1'])

    def test_cidr_30(self):
        is_range, hosts = smartnmap.expand_cidr_targets('10.0.0.0/30')
        self.assertTrue(is_range)
        self.assertEqual(hosts, ['10.0.0.1', '10.0.0.2'])

    def test_cidr_27(self):
        is_range, hosts = smartnmap.expand_cidr_targets('10.0.0.0/27')
        self.assertTrue(is_range)
        self.assertEqual(len(hosts), 30)

    def test_cidr_large(self):
        is_range, hosts = smartnmap.expand_cidr_targets('10.0.0.0/16')
        self.assertTrue(is_range)
        self.assertEqual(hosts, ['10.0.0.0/16'])

    def test_hostname(self):
        is_range, hosts = smartnmap.expand_cidr_targets('scanme.nmap.org')
        self.assertFalse(is_range)
        self.assertEqual(hosts, ['scanme.nmap.org'])


class TestTargetValidation(unittest.TestCase):
    def test_valid_ip(self):
        self.assertTrue(smartnmap.is_valid_target('10.0.0.1'))

    def test_valid_cidr(self):
        self.assertTrue(smartnmap.is_valid_target('10.0.0.0/24'))

    def test_valid_hostname(self):
        self.assertTrue(smartnmap.is_valid_target('example.com'))
        self.assertTrue(smartnmap.is_valid_target('sub.example.com'))

    def test_invalid_empty(self):
        self.assertFalse(smartnmap.is_valid_target(''))

    def test_invalid_chars(self):
        self.assertFalse(smartnmap.is_valid_target('invalid!!!'))

    def test_invalid_ip(self):
        self.assertFalse(smartnmap.is_valid_target('256.256.256.256'))


class TestCheckVulns(unittest.TestCase):
    def test_vsftpd_backdoor(self):
        services = {
            21: {'service': 'ftp', 'product': 'vsftpd', 'version': '2.3.4',
                 'extra': '', 'tunnel': '', 'scripts': {}, 'proto': 'tcp'}
        }
        vulns = smartnmap.check_vulns(services)
        self.assertGreaterEqual(len(vulns), 1)
        self.assertTrue(any('vsftpd' in v['desc'].lower() for v in vulns))

    def test_apache_traversal(self):
        services = {
            80: {'service': 'http', 'product': 'Apache httpd', 'version': '2.4.49',
                 'extra': '', 'tunnel': '', 'scripts': {}, 'proto': 'tcp'}
        }
        vulns = smartnmap.check_vulns(services)
        self.assertTrue(any('CVE-2021-41773' in v['cve'] for v in vulns))

    def test_no_vulns_for_unknown(self):
        services = {
            9999: {'service': 'unknown', 'product': 'FooBar', 'version': '1.0',
                   'extra': '', 'tunnel': '', 'scripts': {}, 'proto': 'tcp'}
        }
        vulns = smartnmap.check_vulns(services)
        self.assertEqual(len(vulns), 0)


class TestSeverityGuess(unittest.TestCase):
    def test_rce(self):
        self.assertEqual(smartnmap.guess_severity('Remote Code Execution'), 'critical')
        self.assertEqual(smartnmap.guess_severity('Unauthenticated RCE'), 'critical')

    def test_sqli(self):
        self.assertEqual(smartnmap.guess_severity('SQL injection in endpoint', 'CVE-2023-1234'), 'high')

    def test_info_disclosure(self):
        self.assertEqual(smartnmap.guess_severity('Information disclosure'), 'medium')

    def test_low_default(self):
        self.assertEqual(smartnmap.guess_severity('default credentials'), 'low')

    def test_info_fallback(self):
        self.assertEqual(smartnmap.guess_severity('some obscure thing'), 'info')

    def test_famous_cves(self):
        self.assertEqual(smartnmap.guess_severity('SMB vuln', 'ms17-010'), 'critical')
        self.assertEqual(smartnmap.guess_severity('Heartbleed check', 'CVE-2014-0160'), 'critical')
        self.assertEqual(smartnmap.guess_severity('Log4Shell', 'CVE-2021-44228'), 'critical')
        self.assertEqual(smartnmap.guess_severity('', 'cve-2019-0708'), 'critical')

    def test_xss_medium(self):
        self.assertEqual(smartnmap.guess_severity('Cross site scripting (XSS)'), 'medium')

    def test_null_session_high(self):
        self.assertEqual(smartnmap.guess_severity('SMB null session allowed'), 'high')

    def test_ssrf_high(self):
        self.assertEqual(smartnmap.guess_severity('Possible SSRF'), 'high')

    def test_self_signed_low(self):
        self.assertEqual(smartnmap.guess_severity('Self-signed certificate'), 'low')


class TestCVEExtraction(unittest.TestCase):
    def test_cve_basic(self):
        self.assertEqual(smartnmap.extract_cve('CVE-2014-6271 shellshock'), 'CVE-2014-6271')
        self.assertEqual(smartnmap.extract_cve('references cve-2008-4250'), 'CVE-2008-4250')
        self.assertEqual(smartnmap.extract_cve('nothing'), '')

    def test_cve_ms(self):
        self.assertEqual(smartnmap.extract_cve('MS17-010 eternalblue'), 'MS17-010')

    def test_top_cve(self):
        out = 'CVE-2022-1 3.0 something\nCVE-2023-9999 9.8 critical\nCVE-2023-5 5.0 medium'
        top = smartnmap.extract_top_cve(out)
        self.assertEqual(top['cve'], 'CVE-2023-9999')
        self.assertEqual(top['cvss'], 9.8)

    def test_top_cve_empty(self):
        self.assertIsNone(smartnmap.extract_top_cve(''))
        self.assertIsNone(smartnmap.extract_top_cve('no CVE here'))


class TestNSEMapping(unittest.TestCase):
    def test_nse_desc_known(self):
        self.assertEqual(smartnmap.nse_vuln_desc('smb-vuln-ms17-010', ''),
                         'MS17-010 EternalBlue SMB RCE')
        self.assertEqual(smartnmap.nse_vuln_desc('smb-vuln-ms08-067', ''),
                         'MS08-067 Windows Server Service RCE')

    def test_nse_desc_unknown(self):
        d = smartnmap.nse_vuln_desc('http-some-check', 'Check performed')
        self.assertIn('http-some-check', d)

    def test_nse_hint_known(self):
        self.assertIn('eternalblue', smartnmap.nse_exploit_hint('smb-vuln-ms17-010').lower())
        self.assertIn('ms08_067', smartnmap.nse_exploit_hint('smb-vuln-ms08-067'))

    def test_nse_hint_fallback(self):
        h = smartnmap.nse_exploit_hint('new-check', 'CVE-2024-1234')
        self.assertIn('CVE-2024-1234', h)


class TestParseXML(unittest.TestCase):
    def test_missing_file(self):
        result = smartnmap.parse_xml(Path('/nonexistent/file.xml'))
        self.assertEqual(result['ports'], [])
        self.assertEqual(result['services'], {})

    def test_parse_sample(self):
        sample_xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
<host>
  <status state="up" reason="syn-ack"/>
  <address addr="10.0.0.1" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack"/>
      <service name="ssh" product="OpenSSH" version="7.4" extrainfo="protocol 2.0"/>
    </port>
    <port protocol="tcp" portid="80">
      <state state="open" reason="syn-ack"/>
      <service name="http" product="Apache httpd" version="2.4.29" tunnel=""/>
      <script id="http-title" output="Test Page"/>
    </port>
    <port protocol="tcp" portid="443">
      <state state="closed" reason="reset"/>
    </port>
  </ports>
  <os>
    <osmatch name="Linux 4.15" accuracy="96"/>
  </os>
</host>
</nmaprun>
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(sample_xml)
            tmp = Path(f.name)
        try:
            result = smartnmap.parse_xml(tmp)
            self.assertEqual(sorted(result['ports']), [22, 80])
            self.assertIn('10.0.0.1', result['alive_hosts'])
            self.assertEqual(result['services'][22]['service'], 'ssh')
            self.assertEqual(result['services'][22]['product'], 'OpenSSH')
            self.assertEqual(result['services'][80]['product'], 'Apache httpd')
            self.assertEqual(result['services'][80]['scripts'].get('http-title'), 'Test Page')
            self.assertEqual(result['os'][0]['name'], 'Linux 4.15')
        finally:
            tmp.unlink(missing_ok=True)


class TestResolveTarget(unittest.TestCase):
    def test_ip_input(self):
        ip, host = smartnmap.resolve_target('1.2.3.4')
        self.assertEqual(ip, '1.2.3.4')
        self.assertIsNone(host)


class TestConfigVulns(unittest.TestCase):
    def test_smbv1(self):
        services = {}
        host_scripts = {'smb-protocols': 'SMBv1 enabled'}
        vulns = smartnmap.check_config_vulns(services, host_scripts)
        self.assertTrue(any('SMBv1' in v['desc'] for v in vulns))

    def test_signing_disabled(self):
        services = {}
        host_scripts = {'smb-security-mode': 'message signing disabled'}
        vulns = smartnmap.check_config_vulns(services, host_scripts)
        self.assertTrue(any('relay' in v['desc'].lower() for v in vulns))


class TestGetScriptsFor(unittest.TestCase):
    def test_ftp(self):
        svc = {'service': 'ftp', 'product': 'vsftpd', 'version': '3.0'}
        existing, missing = smartnmap.get_scripts_for(svc)
        total = existing + missing
        self.assertTrue(any('ftp' in s for s in total))

    def test_http(self):
        svc = {'service': 'http', 'product': 'Apache', 'version': '2.4.7'}
        existing, missing = smartnmap.get_scripts_for(svc)
        total = existing + missing
        self.assertTrue(any('http' in s for s in total))


class TestLootTracker(unittest.TestCase):
    def test_basic(self):
        loot = smartnmap.LootTracker()
        loot.add('creds', 'admin:password123')
        loot.add('urls', 'http://example.com/admin')
        loot.add('flags', 'HTB{test}')
        self.assertEqual(len(loot.creds), 1)
        self.assertEqual(len(loot.urls), 1)
        self.assertEqual(len(loot.flags), 1)

    def test_dedup(self):
        loot = smartnmap.LootTracker()
        loot.add('creds', 'admin:password123')
        loot.add('creds', 'admin:password123')
        self.assertEqual(len(loot.creds), 1)

    def test_scan_output_flag(self):
        loot = smartnmap.LootTracker()
        loot.scan_output("Here is a flag: HTB{sample_flag_123}")
        flag_found = any('HTB{' in f or 'flag{' in f.lower() for f in loot.flags)
        self.assertTrue(flag_found, f"Expected HTB flag in {loot.flags}")


if __name__ == '__main__':
    unittest.main(verbosity=2)
