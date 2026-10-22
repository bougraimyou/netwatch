"""DNS decoding.

The compression pointer is the part worth testing: a decoder that ignores it
still returns a plausible-looking name for the first question and garbage for
everything after, which is the kind of bug that survives casual reading.
"""

from __future__ import annotations

import struct
import unittest

from netwatch import dns
from netwatch.demo import dns_query, dns_response


class TestParse(unittest.TestCase):
    def test_query(self):
        message = dns.parse(dns_query(0x1234, "www.example.com"))
        self.assertEqual(message.txid, 0x1234)
        self.assertFalse(message.is_response)
        self.assertEqual(message.qname, "www.example.com")
        self.assertEqual(message.qtype, 1)
        self.assertEqual(message.questions[0].type_name, "A")

    def test_response_with_compressed_answer(self):
        # The answer name is a pointer back to offset 12, where the question
        # name starts. Ignoring the pointer would produce an empty name.
        message = dns.parse(dns_response(0x2222, "mail.example.com", address="93.184.216.35"))
        self.assertTrue(message.is_response)
        self.assertEqual(message.rcode, 0)
        self.assertEqual(message.answer_count, 1)
        self.assertEqual(message.qname, "mail.example.com")

    def test_nxdomain(self):
        message = dns.parse(dns_response(1, "nope.example.com", rcode=3))
        self.assertTrue(message.is_nxdomain)
        self.assertEqual(message.rcode_name, "NXDOMAIN")

    def test_name_is_lower_cased_and_unrooted(self):
        message = dns.parse(dns_query(1, "WWW.Example.COM."))
        self.assertEqual(message.qname, "www.example.com")

    def test_truncated_header(self):
        with self.assertRaises(dns.DnsError):
            dns.parse(b"\x00" * 6)

    def test_compression_loop_is_rejected(self):
        header = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
        # A pointer at offset 12 that points at itself.
        loop = header + b"\xc0\x0c"
        with self.assertRaises(dns.DnsError):
            dns.parse(loop)

    def test_label_past_end_is_rejected(self):
        header = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
        with self.assertRaises(dns.DnsError):
            dns.parse(header + b"\x3f" + b"abc")

    def test_tcp_length_prefix(self):
        body = dns_query(7, "example.com")
        message = dns.parse_tcp(struct.pack("!H", len(body)) + body)
        self.assertEqual(message.qname, "example.com")

    def test_tcp_prefix_longer_than_payload(self):
        with self.assertRaises(dns.DnsError):
            dns.parse_tcp(struct.pack("!H", 500) + b"short")


class TestHelpers(unittest.TestCase):
    def test_base_domain(self):
        self.assertEqual(dns.base_domain("a.b.example.com"), "example.com")
        self.assertEqual(dns.base_domain("example.com"), "example.com")
        self.assertEqual(dns.base_domain("x.example.com.dz"), "example.com.dz")
        self.assertEqual(dns.base_domain(""), "")

    def test_entropy_separates_words_from_generated_labels(self):
        self.assertLess(dns.shannon_entropy("www"), 2.0)
        generated = "a7f3k2m9q1z8"
        self.assertGreater(dns.shannon_entropy(generated), 3.0)

    def test_ip_literals(self):
        self.assertTrue(dns.is_ip_literal("4.3.2.1.in-addr.arpa"))
        self.assertTrue(dns.is_ip_literal("192.168.1.1"))
        self.assertFalse(dns.is_ip_literal("example.com"))


if __name__ == "__main__":
    unittest.main()
