"""Offline tests for the parsers and checks: python3 -m unittest discover tests"""
import unittest
from pathlib import Path
from types import SimpleNamespace

from lanrecce import intel
from lanrecce.model import State
from lanrecce.profiles import PROFILES
from lanrecce.scope import Scope, ScopeError
from lanrecce.stages import checks
from lanrecce.stages.nuclei import _to_finding

VULNERS = """
  cpe:/a:openbsd:openssh:7.4:
    \tCVE-2023-38408\t9.8\thttps://vulners.com/cve/CVE-2023-38408\t*EXPLOIT*
    \tPACKETSTORM:173661\t9.8\thttps://vulners.com/packetstorm/PACKETSTORM:173661\t*EXPLOIT*
    \tCVE-2020-15778\t7.8\thttps://vulners.com/cve/CVE-2020-15778
    \tCVE-2021-41617\t7.0\thttps://vulners.com/cve/CVE-2021-41617
    \tCVE-2016-20012\t5.3\thttps://vulners.com/cve/CVE-2016-20012
    \tCVE-2018-15473\t5.3\thttps://vulners.com/cve/CVE-2018-15473\t*EXPLOIT*
    \tCVE-2019-6110\t4.0\thttps://vulners.com/cve/CVE-2019-6110
"""


def ctx_for(state, **args):
    a = SimpleNamespace(min_cvss=None, **args)
    return SimpleNamespace(state=state, args=a, profile=PROFILES["standard"])


class ScopeTests(unittest.TestCase):
    def test_private_only(self):
        with self.assertRaises(ScopeError):
            Scope.build(["8.8.8.0/24"], [], False)
        Scope.build(["8.8.8.0/24"], [], True)

    def test_allows_and_excludes(self):
        s = Scope.build(["10.0.0.0/24", "192.168.1.10-20"], ["10.0.0.1"], False)
        self.assertTrue(s.allows("10.0.0.5"))
        self.assertFalse(s.allows("10.0.0.1"))
        self.assertTrue(s.allows("192.168.1.15"))
        self.assertFalse(s.allows("192.168.1.21"))
        self.assertFalse(s.allows("evil.example.com"))  # hostnames fail closed


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.st = State(Path("/nonexistent"))

    def test_vulners(self):
        p = self.st.port("10.0.0.5", 22)
        p.update(service="ssh", product="OpenSSH", version="7.4", scripts={"vulners": VULNERS})
        checks.run_stage(ctx_for(self.st))
        rules = {f.rule: f for f in self.st.findings.values()}
        self.assertIn("CVE-2023-38408", rules)
        self.assertTrue(rules["CVE-2023-38408"].exploit)
        self.assertEqual(rules["CVE-2023-38408"].severity, "critical")
        self.assertIn("CVE-2018-15473", rules)        # below 7.0 but has exploit
        self.assertNotIn("PACKETSTORM:173661", rules)  # non-CVE ids ignored
        self.assertIn("2 lower-severity", rules["vulners-low"].title)

    def test_smb_and_cleartext(self):
        h = self.st.host("10.0.0.6")
        h["scripts"] = {"smb2-security-mode": "\n  3:1:1: \n    Message signing enabled but not required"}
        self.st.port("10.0.0.6", 445).update(service="microsoft-ds",
                                             scripts={"smb-protocols": "dialects: \n    NT LM 0.12 (SMBv1) [dangerous, but default]\n    2:0:2"})
        self.st.port("10.0.0.6", 23).update(service="telnet")
        checks.run_stage(ctx_for(self.st))
        rules = {f.rule for f in self.st.findings.values()}
        self.assertTrue({"smb-signing", "smbv1", "cleartext-telnet"} <= rules)

    def test_nuclei_supersedes_check(self):
        self.st.port("10.0.0.7", 6379).update(service="redis", scripts={"redis-info": "Version: 7.4\n"})
        f = _to_finding({"template-id": "exposed-redis", "ip": "10.0.0.7", "port": "6379",
                         "info": {"name": "Redis unauth", "severity": "high"}},
                        Scope.build(["10.0.0.0/24"], [], False))
        self.st.add(f)
        checks.run_stage(ctx_for(self.st))
        self.assertEqual({x.rule for x in self.st.findings.values()}, {"exposed-redis"})

    def test_nuclei_out_of_scope_dropped(self):
        s = Scope.build(["10.0.0.0/24"], [], False)
        self.assertIsNone(_to_finding({"template-id": "x", "matched-at": "http://10.9.9.9/",
                                       "info": {"severity": "high"}}, s))


class IntelTests(unittest.TestCase):
    def test_tiers(self):
        self.assertEqual(intel.tier(True, None, False, 5.0), "fire")
        self.assertEqual(intel.tier(False, 0.6, False, 5.0), "fire")
        self.assertEqual(intel.tier(False, 0.2, True, 5.0), "fire")
        self.assertEqual(intel.tier(False, 0.01, False, 8.0), "smoke")
        self.assertEqual(intel.tier(False, 0.01, False, 5.0), "ice")


if __name__ == "__main__":
    unittest.main()


class WebValidationTests(unittest.TestCase):
    def setUp(self):
        from lanrecce.web import build_scan_argv
        self.build = build_scan_argv
        self.runs = Path("/nonexistent-runs")

    def test_public_refused(self):
        with self.assertRaises(ValueError):
            self.build({"targets": "8.8.8.0/24"}, "x", self.runs, False)

    def test_option_injection_refused(self):
        for bad in ("--allow-public 10.0.0.1", "@/etc/passwd", "-oX /tmp/x"):
            with self.assertRaises(ValueError):
                self.build({"targets": bad}, "x", self.runs, False)
        with self.assertRaises(ValueError):
            self.build({"targets": "10.0.0.1", "options": {"ports": "80 --script x"}}, "x", self.runs, False)
        with self.assertRaises(ValueError):
            self.build({"targets": "10.0.0.1", "options": {"severity": "high;rm"}}, "x", self.runs, False)

    def test_size_cap(self):
        with self.assertRaises(ValueError):
            self.build({"targets": "10.0.0.0/8"}, "x", self.runs, False)

    def test_good(self):
        argv = self.build({"targets": "10.0.0.0/24\n10.0.1.5", "exclude": "10.0.0.1", "profile": "quick",
                           "options": {"default_logins": True, "ports": "22,80,8000-8100"}}, "run1", self.runs, False)
        self.assertEqual(argv[:3], ["scan", "10.0.0.0/24", "10.0.1.5"])
        self.assertIn("--default-logins", argv)
        self.assertEqual(argv[argv.index("-x") + 1], "10.0.0.1")
        self.assertNotIn("--allow-public", argv)


class DossierExportTests(unittest.TestCase):
    def test_nessus_roundtrip(self):
        import xml.etree.ElementTree as ET
        from lanrecce import dossier
        from lanrecce.model import Finding
        st = State(Path("/nonexistent"))
        st.port("10.0.0.5", 443).update(service="https", product="nginx", version="1.18")
        st.port("10.0.0.5", 8443).update(service="https")
        for port in (443, 8443):  # same title on one host -> must not collapse in Dossier
            st.add(Finding(title="Self-signed TLS certificate", severity="info", host="10.0.0.5",
                           port=port, source="check", rule=f"tls-selfsigned-{port}",
                           evidence="bad bytes \x00\x07 here", cwe="CWE-295"))
        st.add(Finding(title="Thing", severity="critical", host="10.0.0.5", port=443, source="nuclei",
                       rule="CVE-2024-1", cve_id="CVE-2024-1", cvss_score=9.8, kev=True, priority="fire"))
        root = ET.fromstring(dossier.to_nessus(st))  # parses => no illegal XML chars
        items = root.findall(".//ReportItem")
        names = sorted(i.get("pluginName") for i in items)
        self.assertIn("Self-signed TLS certificate (443/tcp)", names)
        self.assertIn("Self-signed TLS certificate (8443/tcp)", names)
        crit = next(i for i in items if i.get("severity") == "4")
        self.assertEqual(crit.findtext("cve"), "CVE-2024-1")
        self.assertIn("CISA KEV: YES", crit.findtext("plugin_output"))
        hosts = ET.fromstring(dossier.to_nmap_xml(st))
        svc = hosts.find(".//port[@portid='443']/service")
        self.assertEqual((svc.get("product"), svc.get("version")), ("nginx", "1.18"))
