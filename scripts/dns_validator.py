#!/usr/bin/env python3
"""
DNS Validation Server for AdGuard DNS Kakao AdBlock Filter
This is for testing/validation purposes only, not for production deployment.
"""

import os
import sys
import threading
import time
import socket
import struct
import logging
from typing import Optional, Set, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class DNSStats:
    """Statistics tracking for DNS queries"""
    total_queries: int = 0
    blocked_queries: int = 0
    allowed_queries: int = 0
    start_time: datetime = field(default_factory=datetime.now)

    @property
    def block_rate(self) -> float:
        """Calculate block rate percentage"""
        if self.total_queries == 0:
            return 0.0
        return (self.blocked_queries / self.total_queries) * 100

    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary"""
        return {
            'total_queries': self.total_queries,
            'blocked_queries': self.blocked_queries,
            'allowed_queries': self.allowed_queries,
            'block_rate': self.block_rate,
            'uptime_seconds': (datetime.now() - self.start_time).total_seconds()
        }


class DNSValidator:
    """DNS Validator that checks domains against AdGuard filter"""

    def __init__(self, filter_file: str):
        """Initialize DNS validator with filter file"""
        self.filter_file = filter_file
        self.blocked_domains: Set[str] = set()
        self.stats = DNSStats()
        self._load_filter()

    def _load_filter(self) -> None:
        """Load and parse AdGuard filter file"""
        if not os.path.exists(self.filter_file):
            logger.error(f"Filter file not found: {self.filter_file}")
            return

        with open(self.filter_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Parse AdGuard DNS format: ||domain.com^
                if line.startswith('||') and line.endswith('^'):
                    domain = line[2:-1]  # Remove || and ^
                    self.blocked_domains.add(domain.lower())

        logger.info(f"Loaded {len(self.blocked_domains)} blocked domains")

    def is_blocked(self, domain: str) -> bool:
        """Check if a domain should be blocked"""
        domain = domain.lower().rstrip('.')

        # Direct match
        if domain in self.blocked_domains:
            return True

        # Check if it's a subdomain of a blocked domain
        parts = domain.split('.')
        for i in range(len(parts)):
            parent_domain = '.'.join(parts[i:])
            if parent_domain in self.blocked_domains:
                return True

        return False

    def resolve(self, domain: str) -> Optional[str]:
        """
        Resolve a domain - return None if blocked, mock IP if allowed
        For testing purposes, returns 127.0.0.1 for allowed domains
        """
        self.stats.total_queries += 1

        if self.is_blocked(domain):
            self.stats.blocked_queries += 1
            logger.debug(f"BLOCKED: {domain}")
            return None
        else:
            self.stats.allowed_queries += 1
            logger.debug(f"ALLOWED: {domain}")
            return "127.0.0.1"  # Mock IP for testing

    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics"""
        return self.stats.to_dict()

    def reset_stats(self) -> None:
        """Reset statistics"""
        self.stats = DNSStats()


class DNSValidatorServer:
    """Simple DNS server for testing filter validation"""

    def __init__(self, filter_file: str, host: str = '127.0.0.1', port: int = 15353):
        """Initialize DNS validation server"""
        self.filter_file = filter_file
        self.host = host
        self.port = port
        self.validator = DNSValidator(filter_file)
        self.is_running = False
        self.socket = None
        self.thread = None

    def _parse_dns_query(self, data: bytes) -> Optional[str]:
        """Parse DNS query packet to extract domain name"""
        try:
            # Skip DNS header (12 bytes)
            pos = 12

            # Parse question section
            domain_parts = []
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    break
                pos += 1
                domain_parts.append(data[pos:pos + length].decode('ascii'))
                pos += length

            domain = '.'.join(domain_parts)
            return domain
        except Exception as e:
            logger.error(f"Error parsing DNS query: {e}")
            return None

    def _create_dns_response(self, query_data: bytes, domain: str, ip: Optional[str]) -> bytes:
        """Create DNS response packet"""
        # For simplicity, return a basic NXDOMAIN or A record response
        # In production, would need proper DNS packet construction

        # Copy transaction ID from query
        transaction_id = query_data[:2]

        if ip is None:
            # NXDOMAIN response
            flags = b'\x81\x83'  # Response with NXDOMAIN
            response = transaction_id + flags + b'\x00\x01\x00\x00\x00\x00\x00\x00'
            # Add question section from original query
            response += query_data[12:]
        else:
            # Positive response with A record (simplified)
            flags = b'\x81\x80'  # Standard response
            response = transaction_id + flags + b'\x00\x01\x00\x01\x00\x00\x00\x00'
            # Add question section from original query
            question_end = query_data.find(b'\x00\x00\x01\x00\x01', 12) + 5
            response += query_data[12:question_end]

            # Add answer section (simplified A record)
            response += b'\xc0\x0c'  # Compression pointer
            response += b'\x00\x01'  # Type A
            response += b'\x00\x01'  # Class IN
            response += b'\x00\x00\x00\x3c'  # TTL 60 seconds
            response += b'\x00\x04'  # Data length

            # Add IP address
            ip_bytes = socket.inet_aton(ip)
            response += ip_bytes

        return response

    def start(self) -> None:
        """Start the DNS validation server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.settimeout(1.0)  # 1 second timeout for checking stop flag
            self.is_running = True

            logger.info(f"DNS Validation Server started on {self.host}:{self.port}")

            while self.is_running:
                try:
                    data, addr = self.socket.recvfrom(512)
                    domain = self._parse_dns_query(data)

                    if domain:
                        ip = self.validator.resolve(domain)
                        response = self._create_dns_response(data, domain, ip)
                        self.socket.sendto(response, addr)

                        log_msg = f"Query from {addr[0]}: {domain} -> "
                        log_msg += "BLOCKED" if ip is None else f"ALLOWED ({ip})"
                        logger.info(log_msg)

                except socket.timeout:
                    continue  # Check if still running
                except Exception as e:
                    logger.error(f"Error handling query: {e}")

        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            if self.socket:
                self.socket.close()
            self.is_running = False
            logger.info("DNS Validation Server stopped")

    def stop(self) -> None:
        """Stop the DNS validation server"""
        self.is_running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)

    def get_stats(self) -> Dict[str, Any]:
        """Get server statistics"""
        stats = self.validator.get_stats()
        stats['server_running'] = self.is_running
        stats['server_address'] = f"{self.host}:{self.port}"
        return stats


def main():
    """Main function for running DNS validation server"""
    import argparse

    parser = argparse.ArgumentParser(description='DNS Validation Server for AdGuard Filter')
    parser.add_argument('filter_file', nargs='?', default='kakao-adblock-filter.txt',
                       help='Path to AdGuard filter file')
    parser.add_argument('--host', default='127.0.0.1',
                       help='Host to bind to (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=15353,
                       help='Port to bind to (default: 15353)')
    parser.add_argument('--test', action='store_true',
                       help='Run in test mode with sample queries')

    args = parser.parse_args()

    if args.test:
        # Test mode - validate some domains
        logger.info("Running in test mode...")
        validator = DNSValidator(args.filter_file)

        test_domains = [
            # Blocked domains
            'ad.kakao.com',
            'ads.kakao.com',
            'track.kakao.com',
            'pixel.kakao.com',
            'ad.daum.net',
            'ads.daum.net',
            # Allowed domains
            'kakao.com',
            'accounts.kakao.com',
            'pay.kakao.com',
            'map.kakao.com',
            'daum.net',
            'google.com'
        ]

        print("\n" + "=" * 50)
        print("DNS Validation Test Results")
        print("=" * 50)

        for domain in test_domains:
            result = validator.resolve(domain)
            status = "BLOCKED" if result is None else f"ALLOWED ({result})"
            symbol = "🚫" if result is None else "✅"
            print(f"{symbol} {domain:<30} -> {status}")

        print("\n" + "=" * 50)
        stats = validator.get_stats()
        print(f"Statistics:")
        print(f"  Total queries: {stats['total_queries']}")
        print(f"  Blocked: {stats['blocked_queries']}")
        print(f"  Allowed: {stats['allowed_queries']}")
        print(f"  Block rate: {stats['block_rate']:.1f}%")
        print("=" * 50)

    else:
        # Server mode
        server = DNSValidatorServer(args.filter_file, args.host, args.port)

        try:
            print(f"Starting DNS Validation Server on {args.host}:{args.port}")
            print(f"Using filter file: {args.filter_file}")
            print("Press Ctrl+C to stop...")
            print("\nTo test, use: dig @127.0.0.1 -p 15353 ad.kakao.com")
            print("=" * 50)

            server.start()
        except KeyboardInterrupt:
            print("\n\nShutting down...")
            server.stop()
            stats = server.get_stats()
            print("\nFinal Statistics:")
            print(f"  Total queries: {stats['total_queries']}")
            print(f"  Blocked: {stats['blocked_queries']}")
            print(f"  Allowed: {stats['allowed_queries']}")
            print(f"  Block rate: {stats['block_rate']:.1f}%")
            print(f"  Uptime: {stats['uptime_seconds']:.1f} seconds")


if __name__ == '__main__':
    main()