"""The public-dataset label logic and the CrowdSec IP remap."""

import pytest

from benchmarks.public.crowdsec import _publicize, _restore
from benchmarks.public.zanbil import verified_engine


class TestCrowdSecIPMap:
    @pytest.mark.parametrize("private,public", [
        ("10.66.30.2", "45.66.30.2"),
        ("10.99.1.5", "45.99.1.5"),
    ])
    def test_round_trip(self, private, public):
        line = f"{private} - - [x] \"GET / HTTP/1.1\" 200 5"
        assert _publicize(line).startswith(public)
        assert _restore(public) == private

    def test_public_ips_untouched(self):
        assert _publicize("66.249.66.1 - - x") == "66.249.66.1 - - x"
        assert _restore("66.249.66.1") == "66.249.66.1"

    def test_only_line_start_is_rewritten(self):
        # A 10.66 appearing inside a URL must not be rewritten.
        line = '10.66.0.1 - - [x] "GET /r?to=10.66.0.9 HTTP/1.1" 200 5'
        assert _publicize(line) == '45.66.0.1 - - [x] "GET /r?to=10.66.0.9 HTTP/1.1" 200 5'


class TestVerifiedEngine:
    def setup_method(self):
        # A tiny stand-in for the published ranges and the reverse-DNS file.
        self.ranges = [("google", __import__("ipaddress").ip_network("66.249.64.0/19"))]

    def test_ip_in_published_range_verifies(self):
        assert verified_engine("66.249.66.1", self.ranges, {}) == "google"

    def test_ip_outside_range_is_not_verified(self):
        assert verified_engine("45.66.0.1", self.ranges, {}) is None

    def test_reverse_dns_with_matching_forward_verifies(self):
        hostnames = {"1.2.3.4": ("crawl-1-2-3-4.googlebot.com", {"1.2.3.4"})}
        assert verified_engine("1.2.3.4", [], hostnames) == "google"

    def test_reverse_dns_without_forward_confirmation_fails(self):
        # A PTR that claims googlebot but whose forward lookup does not
        # contain the IP is a spoof, not a verification.
        hostnames = {"1.2.3.4": ("crawl.googlebot.com", {"9.9.9.9"})}
        assert verified_engine("1.2.3.4", [], hostnames) is None

    def test_lookalike_domain_does_not_verify(self):
        hostnames = {"1.2.3.4": ("googlebot.com.evil.example", {"1.2.3.4"})}
        assert verified_engine("1.2.3.4", [], hostnames) is None
