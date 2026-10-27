"""Tests for destination lookups, with the network replaced by fakes."""

import unittest

from panos_decrypt_bypass.web.lookup import DemoLookup, Lookup, names_match, parse_target

DOMAIN = {
    "ldhName": "example.co.uk",
    "entities": [
        {"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar Ltd"]]]},
        {
            "roles": ["technical"],
            "entities": [
                {
                    "roles": ["registrant"],
                    "vcardArray": ["vcard", [["org", {}, "text", "Example Holdings"], ["adr", {"cc": "GB"}, "text", ["", "", "", "", "", "", ""]]]],
                }
            ],
        },
    ],
    "events": [
        {"eventAction": "registration", "eventDate": "2001-02-03T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2030-02-03T00:00:00Z"},
    ],
    "nameservers": [{"ldhName": "NS2.EXAMPLE.NET."}, {"ldhName": "ns1.example.net"}],
}
REGISTRY = {"ldhName": "co.uk", "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "The Registry"]]]}]}
NETWORK = {
    "name": "EXAMPLE-CDN",
    "country": "US",
    "cidr0_cidrs": [{"v4prefix": "198.18.0.0", "length": 15}],
    "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Example CDN, Inc."]]]}],
}
CERT = {
    "subject": ((("countryName", "GB"),), (("organizationName", "Example Holdings"),), (("commonName", "www.example.co.uk"),)),
    "issuer": ((("organizationName", "Example CA"),), (("commonName", "Example OV CA"),)),
    "subjectAltName": (("DNS", "www.example.co.uk"), ("DNS", "*.example-static.net")),
    "notAfter": "Jan  1 00:00:00 2027 GMT",
}


class FakeNet:
    def __init__(self, addresses=("8.8.4.4",)):
        self.urls, self.connected = [], []
        self.addresses = list(addresses)

    def fetch_json(self, url):
        self.urls.append(url)
        return {
            "https://rdap.org/domain/example.co.uk": DOMAIN,
            "https://rdap.org/domain/co.uk": REGISTRY,  # a registry record: must never win
            "https://rdap.org/ip/8.8.4.4": NETWORK,
        }.get(url)

    def resolve(self, host):
        return {"canonical": "edge.example-cdn.net", "addresses": self.addresses}

    def get_certificate(self, address, host):
        self.connected.append((address, host))
        return CERT

    def lookup(self):
        return Lookup(
            fetch_json=self.fetch_json, resolve=self.resolve, reverse_dns=lambda a: "edge-1.example-cdn.net", get_certificate=self.get_certificate
        )


class ParseTest(unittest.TestCase):
    def test_targets(self):
        self.assertEqual(parse_target("API.Example.com."), ("host", "api.example.com"))
        self.assertEqual(parse_target("*.example.com"), ("host", "example.com"))
        self.assertEqual(parse_target("2001:DB8::1"), ("ip", "2001:db8::1"))
        for bad in ("not a host", "http://x.com/", "localhost", "a..b.com", "x" * 300 + ".com", "1.2.3"):
            with self.assertRaises(ValueError, msg=bad):
                parse_target(bad)

    def test_names_match(self):
        self.assertTrue(names_match("api.example.com", ["*.example.com"]))
        self.assertFalse(names_match("a.b.example.com", ["*.example.com"]))
        self.assertFalse(names_match("example.com", ["*.example.com"]))


class LookupTest(unittest.TestCase):
    def test_hostname(self):
        net = FakeNet()
        r = net.lookup().lookup("www.example.co.uk")
        self.assertEqual(
            r["registration"],
            {
                "domain": "example.co.uk",
                "registrar": "Example Registrar Ltd",
                "registrant": "Example Holdings (GB)",
                "registered": "2001-02-03",
                "expires": "2030-02-03",
                "nameservers": ["ns1.example.net", "ns2.example.net"],
            },
        )
        # Longest name first, so the registry's own co.uk record never wins.
        self.assertEqual(net.urls, ["https://rdap.org/domain/www.example.co.uk", "https://rdap.org/domain/example.co.uk"])
        self.assertEqual(r["dns"]["canonical"], "edge.example-cdn.net")
        cert = r["certificate"]
        self.assertEqual((cert["organization"], cert["issuer"], cert["matches"]), ("Example Holdings", "Example CA · Example OV CA", True))
        self.assertEqual(net.connected, [("8.8.4.4", "www.example.co.uk")])
        self.assertEqual([link["label"] for link in r["links"]], ["VirusTotal", "urlscan.io", "crt.sh", "Web search"])
        self.assertIn("example.co.uk", r["links"][0]["url"])

    def test_never_connects_to_private_addresses(self):
        net = FakeNet(addresses=["10.1.2.3", "127.0.0.1"])
        r = net.lookup().lookup("intranet.example.co.uk")
        self.assertIn("skipped", r["certificate"])
        self.assertEqual(net.connected, [])

    def test_ip(self):
        net = FakeNet()
        r = net.lookup().lookup("8.8.4.4")
        self.assertEqual(r["network"], {"network": "EXAMPLE-CDN", "range": "198.18.0.0/15", "owner": "Example CDN, Inc.", "country": "US"})
        self.assertEqual(r["dns"], {"reverse": "edge-1.example-cdn.net"})
        self.assertNotIn("matches", r["certificate"])
        self.assertIn("error", net.lookup().lookup("192.168.1.10")["network"])

    def test_one_failing_source_does_not_hide_the_others(self):
        net = FakeNet()

        def broken(address, host):
            raise OSError("connection refused")

        lookup = Lookup(fetch_json=net.fetch_json, resolve=net.resolve, get_certificate=broken)
        r = lookup.lookup("www.example.co.uk")
        self.assertEqual(r["certificate"], {"error": "connection refused"})
        self.assertEqual(r["registration"]["domain"], "example.co.uk")

    def test_results_are_cached(self):
        net = FakeNet()
        lookup = net.lookup()
        lookup.lookup("www.example.co.uk")
        lookup.lookup("WWW.example.co.uk")
        self.assertEqual(len(net.connected), 1)

    def test_demo_needs_no_network(self):
        r = DemoLookup().lookup("api.pinnedapp.example")
        self.assertEqual(r["registration"]["registrant"], "Example Corp (US)")
        self.assertTrue(r["certificate"]["matches"])


if __name__ == "__main__":
    unittest.main()
