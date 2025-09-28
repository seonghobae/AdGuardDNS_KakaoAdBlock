#!/usr/bin/env python3
"""
Test DNS Validation Server
TDD approach for validating AdGuard DNS filter behavior
"""

import unittest
import socket
import threading
import time
from unittest.mock import patch, MagicMock
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestDNSValidator(unittest.TestCase):
    """Test DNS validation server functionality"""

    @classmethod
    def setUpClass(cls):
        """Set up test class - load filter file"""
        cls.filter_file = "kakao-adblock-filter.txt"
        cls.blocked_domains = set()
        cls.allowed_domains = set()

        # Parse filter file
        if os.path.exists(cls.filter_file):
            with open(cls.filter_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('||') and line.endswith('^'):
                        domain = line[2:-1]  # Remove || and ^
                        cls.blocked_domains.add(domain)

    def setUp(self):
        """Set up each test"""
        self.server = None

    def tearDown(self):
        """Clean up after each test"""
        if self.server:
            self.server.stop()

    def test_filter_file_exists(self):
        """Test that filter file exists and is readable"""
        self.assertTrue(os.path.exists(self.filter_file),
                       f"Filter file {self.filter_file} should exist")

        with open(self.filter_file, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn('||ad.kakao.com^', content,
                         "Filter should contain ad.kakao.com")
            self.assertIn('||ads.kakao.com^', content,
                         "Filter should contain ads.kakao.com")

    def test_blocked_domains_parsed(self):
        """Test that blocked domains are correctly parsed from filter"""
        self.assertGreater(len(self.blocked_domains), 0,
                          "Should have parsed some blocked domains")

        # Check known ad domains are in blocked list
        expected_blocked = [
            'ad.kakao.com',
            'ads.kakao.com',
            'track.kakao.com',
            'ad.daum.net',
            'ads.daum.net'
        ]

        for domain in expected_blocked:
            self.assertIn(domain, self.blocked_domains,
                         f"{domain} should be in blocked domains")

    def test_essential_services_not_blocked(self):
        """Test that essential Kakao services are NOT blocked"""
        essential_services = [
            'kakao.com',
            'accounts.kakao.com',
            'kauth.kakao.com',
            'pay.kakao.com',
            'map.kakao.com',
            'talk.kakao.com',
            'developers.kakao.com',
            'api.kakao.com',
            'melon.com',
            'brunch.co.kr',
            'daum.net'
        ]

        for domain in essential_services:
            self.assertNotIn(domain, self.blocked_domains,
                           f"Essential service {domain} should NOT be blocked")

    def test_dns_validator_initialization(self):
        """Test DNS validator server initialization"""
        from scripts.dns_validator import DNSValidator

        validator = DNSValidator(self.filter_file)
        self.assertIsNotNone(validator)
        self.assertEqual(len(validator.blocked_domains), len(self.blocked_domains))

    def test_dns_query_blocked_domain(self):
        """Test DNS query for blocked domain returns NXDOMAIN"""
        from scripts.dns_validator import DNSValidator

        validator = DNSValidator(self.filter_file)

        # Test blocked domains
        blocked_test_cases = [
            'ad.kakao.com',
            'ads.kakao.com',
            'track.kakao.com',
            'pixel.kakao.com'
        ]

        for domain in blocked_test_cases:
            result = validator.resolve(domain)
            self.assertIsNone(result,
                            f"Blocked domain {domain} should return None (NXDOMAIN)")

    def test_dns_query_allowed_domain(self):
        """Test DNS query for allowed domain returns mock IP"""
        from scripts.dns_validator import DNSValidator

        validator = DNSValidator(self.filter_file)

        # Test allowed domains
        allowed_test_cases = [
            ('kakao.com', '127.0.0.1'),  # Mock IP for testing
            ('accounts.kakao.com', '127.0.0.1'),
            ('pay.kakao.com', '127.0.0.1'),
            ('google.com', '127.0.0.1'),  # Non-Kakao domain
        ]

        for domain, expected_ip in allowed_test_cases:
            result = validator.resolve(domain)
            self.assertIsNotNone(result,
                               f"Allowed domain {domain} should return an IP")
            self.assertEqual(result, expected_ip,
                           f"Allowed domain {domain} should return {expected_ip}")

    def test_subdomain_blocking(self):
        """Test that subdomains of blocked domains are also blocked"""
        from scripts.dns_validator import DNSValidator

        validator = DNSValidator(self.filter_file)

        # Test subdomains of blocked domains
        subdomain_test_cases = [
            'sub.ad.kakao.com',
            'test.ads.kakao.com',
            'analytics.track.kakao.com'
        ]

        for domain in subdomain_test_cases:
            result = validator.resolve(domain)
            self.assertIsNone(result,
                            f"Subdomain {domain} of blocked domain should be blocked")

    def test_pattern_matching(self):
        """Test pattern-based blocking (domains with ad keywords)"""
        from scripts.dns_validator import DNSValidator

        validator = DNSValidator(self.filter_file)

        # These should be blocked based on patterns
        pattern_blocked = [
            'ad.kakao.com',
            'ads.daum.net',
            'track.kakao.com',
            'pixel.kakao.com',
            'analytics.kakao.com'
        ]

        for domain in pattern_blocked:
            if domain in self.blocked_domains:
                result = validator.resolve(domain)
                self.assertIsNone(result,
                                f"Pattern-matched domain {domain} should be blocked")

    def test_dns_server_start_stop(self):
        """Test DNS server can start and stop properly"""
        from scripts.dns_validator import DNSValidatorServer

        server = DNSValidatorServer(self.filter_file, port=15353)

        # Start server in thread
        server_thread = threading.Thread(target=server.start)
        server_thread.daemon = True
        server_thread.start()

        # Give server time to start
        time.sleep(0.5)

        self.assertTrue(server.is_running, "Server should be running")

        # Stop server
        server.stop()
        time.sleep(0.5)

        self.assertFalse(server.is_running, "Server should be stopped")

    def test_concurrent_queries(self):
        """Test DNS validator handles concurrent queries correctly"""
        from scripts.dns_validator import DNSValidator
        import concurrent.futures

        validator = DNSValidator(self.filter_file)

        # Mix of blocked and allowed domains
        test_domains = [
            ('ad.kakao.com', None),
            ('kakao.com', '127.0.0.1'),
            ('ads.daum.net', None),
            ('daum.net', '127.0.0.1'),
            ('track.kakao.com', None),
            ('map.kakao.com', '127.0.0.1'),
        ] * 10  # Repeat for more concurrent tests

        def query_domain(domain_tuple):
            domain, expected = domain_tuple
            result = validator.resolve(domain)
            return result == expected

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(query_domain, test_domains))

        self.assertTrue(all(results),
                       "All concurrent queries should return expected results")

    def test_statistics_tracking(self):
        """Test that validator tracks statistics correctly"""
        from scripts.dns_validator import DNSValidator

        validator = DNSValidator(self.filter_file)

        # Reset stats
        validator.reset_stats()

        # Make some queries
        validator.resolve('ad.kakao.com')  # Blocked
        validator.resolve('kakao.com')  # Allowed
        validator.resolve('ads.kakao.com')  # Blocked
        validator.resolve('pay.kakao.com')  # Allowed

        stats = validator.get_stats()

        self.assertEqual(stats['total_queries'], 4, "Should have 4 total queries")
        self.assertEqual(stats['blocked_queries'], 2, "Should have 2 blocked queries")
        self.assertEqual(stats['allowed_queries'], 2, "Should have 2 allowed queries")
        self.assertEqual(stats['block_rate'], 50.0, "Block rate should be 50%")


class TestDNSValidatorIntegration(unittest.TestCase):
    """Integration tests for DNS validator with actual DNS queries"""

    def setUp(self):
        """Set up integration test"""
        self.filter_file = "kakao-adblock-filter.txt"
        self.server = None

    def tearDown(self):
        """Clean up after test"""
        if self.server:
            self.server.stop()

    @unittest.skipIf(not os.path.exists("kakao-adblock-filter.txt"),
                     "Filter file not found")
    def test_end_to_end_dns_validation(self):
        """Test end-to-end DNS validation flow"""
        from scripts.dns_validator import DNSValidatorServer

        # Start test DNS server
        server = DNSValidatorServer(self.filter_file, port=15353)
        self.server = server

        server_thread = threading.Thread(target=server.start)
        server_thread.daemon = True
        server_thread.start()

        time.sleep(1)  # Wait for server to start

        # Test with mock DNS client
        test_cases = [
            ('ad.kakao.com', False),  # Should be blocked
            ('kakao.com', True),  # Should be allowed
            ('ads.daum.net', False),  # Should be blocked
            ('daum.net', True),  # Should be allowed
        ]

        for domain, should_resolve in test_cases:
            # In real implementation, would use DNS client
            # For now, directly test validator
            result = server.validator.resolve(domain)

            if should_resolve:
                self.assertIsNotNone(result,
                                   f"{domain} should resolve")
            else:
                self.assertIsNone(result,
                                f"{domain} should be blocked")

        # Check server stats
        stats = server.get_stats()
        self.assertGreater(stats['total_queries'], 0,
                          "Should have processed some queries")


if __name__ == '__main__':
    unittest.main(verbosity=2)