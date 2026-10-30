import unittest

from core.core import NemesisScanner, QUICK_TCP, QUICK_UDP


class ScanModeTests(unittest.TestCase):
    def test_quick_mode_uses_fast_common_ports(self):
        scanner = NemesisScanner("127.0.0.1", scan_mode="quick", vuln_check=True)
        port_spec = scanner._build_port_spec()

        self.assertIn(f"T:{','.join(map(str, QUICK_TCP))}", port_spec)
        self.assertIn(f"U:{','.join(map(str, QUICK_UDP))}", port_spec)
        self.assertNotIn("T:1-1000", port_spec)

    def test_quick_mode_keeps_fast_scan_profile(self):
        scanner = NemesisScanner("127.0.0.1", scan_mode="quick", vuln_check=True)
        args = scanner._nmap_arguments()

        self.assertIn("-sV", args)
        self.assertIn("--script vuln", args)
        self.assertIn("-T5", args)
        self.assertNotIn("-p T:1-1000", args)


if __name__ == "__main__":
    unittest.main()
