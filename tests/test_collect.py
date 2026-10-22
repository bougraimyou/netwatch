"""Live capture argument handling.

Actually opening a raw socket needs privileges the test runner should not have,
so this covers the parts that must fail clearly rather than the capture itself:
a platform check and a missing interface, both of which are decided before any
privileged call.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from netwatch.collect import CaptureNotPermitted, collect, iface_exists


class TestCollectGuards(unittest.TestCase):
    def test_missing_interface_is_reported_with_the_known_names(self):
        with self.assertRaises(CaptureNotPermitted) as caught:
            collect("definitely-not-an-interface", Path(tempfile.mkdtemp()) / "out.pcap", duration=0.1)
        message = str(caught.exception)
        self.assertIn("does not exist", message)
        self.assertIn("known interfaces", message)

    def test_non_linux_platform_is_reported_plainly(self):
        if sys.platform.startswith("linux"):
            self.skipTest("Linux supports AF_PACKET; this guard is for other platforms")
        with self.assertRaises(CaptureNotPermitted) as caught:
            collect("eth0", Path(tempfile.mkdtemp()) / "out.pcap", duration=0.1)
        self.assertIn("Linux", str(caught.exception))

    def test_iface_exists_matches_the_sysfs_view(self):
        self.assertTrue(iface_exists("lo"))
        self.assertFalse(iface_exists("lo-but-not-really"))

    def test_collect_exists_in_the_cli(self):
        from netwatch.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["collect", "--iface", "lo", "--out", "x.pcap"])
        self.assertEqual(args.iface, "lo")
        self.assertIsNone(args.duration)


if __name__ == "__main__":
    unittest.main()
