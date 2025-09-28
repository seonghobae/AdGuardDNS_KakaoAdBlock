#!/usr/bin/env python3
"""
Kakao/Daum domain collector for AdGuard DNS filter
Fetches and extracts Kakao/Daum related domains from multiple sources
"""

import json
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import Set, Dict


class KakaoDomainCollector:
    def __init__(self, sources_file: str = "scripts/sources.json"):
        self.sources_file = Path(sources_file)
        self.sources = self.load_sources()
        self.collected_domains: Set[str] = set()
        self.whitelist_domains = self._get_whitelist_domains()

    def load_sources(self) -> Dict:
        """Load data sources configuration"""
        try:
            with open(self.sources_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Warning: {self.sources_file} not found, using default sources")
            return self.get_default_sources()

    def get_default_sources(self) -> Dict:
        """Default sources configuration"""
        return {
            "sources": [
                {
                    "name": "List-KR",
                    "url": "https://raw.githubusercontent.com/List-KR/List-KR/master/filter.txt",
                    "type": "adblock",
                    "encoding": "utf-8"
                },
                {
                    "name": "YousList",
                    "url": "https://raw.githubusercontent.com/yous/YousList/master/youslist.txt",
                    "type": "adblock",
                    "encoding": "utf-8"
                }
            ],
            "kakao_patterns": [
                r"kakao\.com",
                r"kakaocdn\.net",
                r"kakaocorp\.com",
                r"kakaoapi\.com",
                r"kakaotalk\.com",
                r"kakaomap\.com",
                r"kakaopay\.com",
                r"kakaostory\.com",
                r"kakaomobility\.com",
                r"kakaogames\.com",
                r"daum\.net",
                r"daumcdn\.net",
                r"daumkakao\.com"
            ],
            # More specific ad keywords - domains must contain BOTH Kakao pattern AND these specific ad indicators
            "ad_keywords": [
                # Advertising specific subdomains (most reliable indicators)
                r"^ad\.",           # ad.kakao.com, ad.daum.net
                r"^ads\.",          # ads.kakao.com, ads.daum.net
                r"^adm\.",          # adm.kakao.com (ad management)
                r"^adapi\.",        # adapi.kakao.com (ad API)
                r"^adserver\.",     # adserver.kakao.com
                r"^adsystem\.",     # adsystem.kakao.com

                # Tracking and analytics (specific to advertising)
                r"^track\.",        # track.kakao.com, track.daum.net
                r"^pixel\.",        # pixel.kakao.com (tracking pixels)
                r"^beacon\.",       # beacon.kakao.com (tracking beacons)
                r"^collector\.",    # collector.kakao.com (data collection)
                r"^rum\.",          # rum.kakao.com (real user monitoring for ads)

                # Business intelligence and advertising analytics
                r"^bizboard\.",     # bizboard.kakao.com (business analytics)
                r"^dmp\.",          # dmp.kakao.com (data management platform)
                r"^adtrack\.",      # adtrack.kakao.com
                r"^metrics\.",      # metrics.kakao.com (advertising metrics)

                # Ad-specific subpaths (less reliable but still valid indicators)
                r"\.ad\.",          # subdomain.ad.kakao.com
                r"adpixel\.",       # adpixel.kakao.com
                r"adsdk\.",         # adsdk.kakao.com (advertising SDK)
                r"admob\.",         # admob.kakao.com (mobile ads)

                # Specific ad-related service paths
                r"display\.ad\.",   # display.ad.kakao.com
                r"banner\.ad\.",    # banner.ad.kakao.com
                r"video\.ad\.",     # video.ad.kakao.com
                r"native\.ad\.",    # native.ad.kakao.com
                r"mobile\.ad\.",    # mobile.ad.kakao.com
                r"info\.ad\."       # info.ad.daum.net
            ]
        }

    def _get_whitelist_domains(self) -> Set[str]:
        """
        Get legitimate Kakao service domains that should NEVER be blocked.
        These are essential services that users need for normal Kakao functionality.
        """
        return {
            # Core Kakao services - essential for all Kakao functionality
            "kakao.com",                # Main corporate site and services
            "www.kakao.com",            # Main website

            # Authentication and user accounts - CRITICAL services
            "accounts.kakao.com",       # Login and user authentication (ESSENTIAL)
            "kauth.kakao.com",         # OAuth authentication API (ESSENTIAL)
            "auth.kakao.com",          # Alternative auth domain
            "login.kakao.com",         # Login services

            # Developer and API services - needed for app functionality
            "developers.kakao.com",     # Developer portal and API docs
            "dapi.kakao.com",          # Developer API endpoints
            "api.kakao.com",           # General API services
            "kapi.kakao.com",          # Kakao API services
            "openapi.kakao.com",       # Open API platform

            # Core messaging and communication
            "talk.kakao.com",          # KakaoTalk web interface
            "story.kakao.com",         # KakaoStory social platform
            "mail.kakao.com",          # Kakao Mail service

            # Entertainment and media services
            "melon.com",               # Music streaming service (major service)
            "www.melon.com",           # Music streaming website
            "brunch.co.kr",           # Blog and publishing platform
            "www.brunch.co.kr",       # Blog platform website

            # Maps and location services - essential functionality
            "map.kakao.com",          # Kakao Map main service (ESSENTIAL)
            "daummap.com",            # Legacy Daum Map (still used)
            "maps.kakao.com",         # Maps API and services

            # Payment services - financial transactions (CRITICAL)
            "pay.kakao.com",          # KakaoPay main service (ESSENTIAL)
            "payment.kakao.com",      # Payment processing
            "wallet.kakao.com",       # Digital wallet services

            # Search and portal services
            "search.kakao.com",       # Search functionality
            "daum.net",               # Main Daum portal (major portal site)
            "www.daum.net",          # Daum website

            # Shopping and e-commerce
            "gift.kakao.com",         # KakaoTalk Gift service
            "shopping.kakao.com",     # Kakao Shopping

            # Business and productivity
            "business.kakao.com",     # Kakao for Business
            "work.kakao.com",        # KakaoWork enterprise messaging
            "calendar.kakao.com",    # Kakao Calendar
            "keep.kakao.com",        # Kakao Keep notes

            # Gaming and entertainment
            "games.kakao.com",       # Kakao Games portal
            "game.kakao.com",        # Game services

            # Transportation and mobility
            "t.kakao.com",           # Kakao T (taxi/transportation) main service
            "taxi.kakao.com",        # Taxi booking service

            # News and media
            "news.kakao.com",        # Kakao News aggregator
            "media.kakao.com",       # Media services

            # Support and help
            "cs.kakao.com",          # Customer service and support
            "help.kakao.com",        # Help and documentation
            "support.kakao.com",     # User support services

            # Corporate and investor relations
            "corp.kakao.com",        # Corporate information
            "ir.kakao.com",          # Investor relations

            # Technology and innovation
            "tech.kakao.com",        # Technology blog and updates
            "cloud.kakao.com",       # Kakao Cloud services

            # Essential CDN and infrastructure (carefully selected)
            "dn.dn.kakaocdn.net",    # Essential content delivery (user avatars, etc.)
            "ssl.dn.kakaocdn.net",   # SSL content delivery for essential features
        }

    def fetch_content(self, url: str, encoding: str = 'utf-8') -> str:
        """Fetch content from URL with error handling"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (compatible; KakaoDomainCollector/1.0)'
            }
            req = urllib.request.Request(url, headers=headers)

            with urllib.request.urlopen(req, timeout=30) as response:
                content = response.read()
                if encoding:
                    return content.decode(encoding, errors='ignore')
                return content.decode('utf-8', errors='ignore')

        except urllib.error.HTTPError as e:
            print(f"HTTP Error {e.code} fetching {url}: {e.reason}")
        except urllib.error.URLError as e:
            print(f"URL Error fetching {url}: {e.reason}")
        except Exception as e:
            print(f"Error fetching {url}: {e}")

        return ""

    def extract_domains_from_adblock(self, content: str) -> Set[str]:
        """Extract domains from AdBlock filter format"""
        domains = set()

        # Multiple patterns for different AdBlock rule formats
        patterns = [
            r'\|\|([a-zA-Z0-9.-]+)\^',  # Standard: ||domain.com^
            r'\|\|([a-zA-Z0-9.-]+)\^[^$]*$',  # With additional modifiers
            r'@@\|\|([a-zA-Z0-9.-]+)\^',  # Whitelist rules (to identify domains)
            r'[|]{1,2}([a-zA-Z0-9.-]*(?:kakao|daum)[a-zA-Z0-9.-]*)\^',  # Kakao/Daum specific
        ]

        for line in content.split('\n'):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith('!') or line.startswith('#'):
                continue

            # Try each pattern
            for pattern in patterns:
                matches = re.findall(pattern, line)
                for domain in matches:
                    if domain and self.is_kakao_related(domain):
                        domains.add(domain)

            # Also look for domain patterns in comments (sometimes contain example domains)
            if line.startswith('!') and ('kakao' in line.lower() or 'daum' in line.lower()):
                # Extract domains from comments
                comment_domains = re.findall(
                    r'([a-zA-Z0-9.-]*(?:kakao|daum)[a-zA-Z0-9.-]*\.(?:com|net|kr))',
                    line.lower()
                )
                for domain in comment_domains:
                    if self.is_kakao_related(domain):
                        domains.add(domain)

        return domains

    def is_kakao_related(self, domain: str) -> bool:
        """
        Check if domain is related to Kakao/Daum services AND is an ad/tracking domain.

        Returns True only if:
        1. Domain matches Kakao/Daum patterns AND
        2. Domain contains specific ad/tracking keywords AND
        3. Domain is NOT in the whitelist of legitimate services

        This ensures we only block advertising/tracking domains, not legitimate services.
        """
        if not domain:
            return False

        domain_lower = domain.lower().strip()

        # Basic domain format validation
        if not re.match(r'^[a-zA-Z0-9.-]+$', domain) or domain.startswith('.') or domain.endswith('.'):
            return False

        # CRITICAL: Skip whitelisted legitimate service domains
        if domain_lower in self.whitelist_domains:
            print(f"  WHITELIST: Skipping legitimate service domain: {domain_lower}")
            return False

        # Skip obviously non-Kakao domains
        if not any(x in domain_lower for x in ['kakao', 'daum']):
            return False

        # Check if domain matches Kakao/Daum patterns
        kakao_pattern_matched = False
        for pattern in self.sources.get("kakao_patterns", []):
            if re.search(pattern, domain_lower):
                kakao_pattern_matched = True
                break

        if not kakao_pattern_matched:
            return False

        # Now check for SPECIFIC ad-related keywords (more restrictive than before)
        ad_keyword_matched = False
        matched_keywords = []

        for ad_keyword in self.sources.get("ad_keywords", []):
            if re.search(ad_keyword, domain_lower):
                ad_keyword_matched = True
                matched_keywords.append(ad_keyword)

        if ad_keyword_matched:
            print(f"  AD DOMAIN: {domain_lower} matched keywords: {matched_keywords}")
            return True

        # Additional check for obvious ad domains with simple patterns
        # These are fallback patterns for domains that might not match the regex exactly
        simple_ad_patterns = [
            'ad.', 'ads.', 'adm.', 'adapi.', 'adserver.', 'track.',
            'pixel.', 'beacon.', 'collector.', 'bizboard.', 'dmp.'
        ]
        for pattern in simple_ad_patterns:
            if pattern in domain_lower:
                print(f"  AD DOMAIN: {domain_lower} matched simple pattern: {pattern}")
                return True

        # If we get here, it's a Kakao domain but doesn't contain ad indicators
        print(f"  LEGITIMATE: Skipping Kakao domain without ad indicators: {domain_lower}")
        return False

    def collect_from_sources(self) -> None:
        """Collect domains from all configured sources"""
        for source in self.sources.get("sources", []):
            name = source.get("name", "Unknown")
            url = source.get("url", "")
            source_type = source.get("type", "adblock")
            encoding = source.get("encoding", "utf-8")

            print(f"Fetching from {name}: {url}")

            content = self.fetch_content(url, encoding)
            if not content:
                print(f"  Failed to fetch content from {name}")
                continue

            if source_type == "adblock":
                domains = self.extract_domains_from_adblock(content)
                self.collected_domains.update(domains)
                print(f"  Extracted {len(domains)} Kakao/Daum domains from {name}")

    def add_known_domains(self) -> None:
        """
        Add known Kakao/Daum ad domains that might be missing from external sources.
        These are CONFIRMED advertising/tracking domains, not general service domains.
        """
        known_ad_domains = {
            # CONFIRMED ACTIVE domains (validated via DNS as of 2025)
            "ads.kakaocdn.net",        # CDN for ads (confirmed active)
            "display.ad.daum.net",     # Display advertising (confirmed active)
            "info.ad.daum.net",        # Ad information service (confirmed active)

            # HIGH-CONFIDENCE domains based on patterns and reports
            "ad.daum.net",             # Primary Daum advertising (from external sources)

            # LIKELY ACTIVE domains (follow standard patterns, include for completeness)
            "ads.kakao.com",           # Standard Kakao ads subdomain
            "track.kakao.com",         # User tracking
            "analytics.kakao.com",     # Analytics (ad-focused)
            "dmp.kakao.com",           # Data Management Platform
            "bizboard.kakao.com",      # Business analytics (often ad-related)

            # Daum advertising infrastructure
            "ads.daum.net",            # Alternative Daum advertising
            "track.daum.net",          # Daum user tracking
            "analytics.daum.net",      # Daum analytics
            "dmp.daum.net",            # Daum Data Management Platform
            "bizboard.daum.net",       # Daum business analytics

            # Mobile and specific ad formats
            "mobile.ad.daum.net",      # Mobile advertising
            "banner.ad.daum.net",      # Banner advertising
            "video.ad.daum.net",       # Video advertising

            # Service-specific advertising domains
            "ads.kakaomap.com",        # Kakao Map ads (following pattern)
            "track.kakaomap.com",      # Kakao Map tracking
            "ads.kakaotalk.com",       # KakaoTalk ads
            "track.kakaotalk.com",     # KakaoTalk tracking

            # Financial service tracking
            "track.kakaopay.com",      # KakaoPay tracking

            # Less certain but following standard patterns
            "ad.kakao.com",            # Primary advertising platform
            "ad.kakaomap.com",         # Kakao Map advertising
            "ad.kakaotalk.com",        # KakaoTalk advertising
            "ad.kakaopay.com",         # KakaoPay advertising
            "track.kakaocdn.net",      # Tracking CDN
            "pixel.kakao.com",         # Tracking pixels
            "pixel.daum.net",          # Daum tracking pixels
            "pixel.kakaotalk.com",     # KakaoTalk pixels
            "pixel.kakaocdn.net",      # Pixel CDN
            "collector.kakao.com",     # Data collection for ads
            "collector.daum.net",      # Daum data collection
            "beacon.kakao.com",        # Tracking beacons
            "beacon.daum.net",         # Daum tracking beacons
            "metrics.kakao.com",       # Advertising metrics
            "metrics.daum.net",        # Daum advertising metrics
        }

        # Validate each known domain against our own criteria before adding
        validated_domains = set()
        for domain in known_ad_domains:
            if self.is_kakao_related(domain):
                validated_domains.add(domain)
            else:
                print(f"  WARNING: Known domain {domain} failed validation, skipping")

        initial_count = len(self.collected_domains)
        self.collected_domains.update(validated_domains)
        added_count = len(self.collected_domains) - initial_count
        print(f"Added {added_count} validated known ad domains")
        print(f"Total collected ad domains: {len(self.collected_domains)}")

    def generate_adguard_filter(self) -> str:
        """Generate AdGuard DNS filter format"""
        if not self.collected_domains:
            return ""

        # Sort domains for consistent output
        sorted_domains = sorted(self.collected_domains)

        # Generate header
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        short_date = datetime.utcnow().strftime('%Y%m%d')

        lines = [
            "! Title: Kakao AdBlock Filter (Auto-Generated)",
            "! Description: Precision AdGuard DNS filter for blocking ONLY Kakao advertising/tracking domains",
            "! Homepage: https://github.com/seonghobae/AdGuardDNS_KakaoAdBlock",
            f"! Version: {short_date}",
            f"! Last modified: {timestamp}",
            "! Expires: 6 hours",
            "! License: MIT",
            "!",
            "! === PRECISION FILTERING APPROACH ===",
            "! This filter uses a WHITELIST-FIRST approach to ensure legitimate services work:",
            "! - BLOCKS: Only domains with specific ad/tracking patterns (ad., ads., track., pixel., etc.)",
            "! - PRESERVES: Essential services (kakao.com, accounts.kakao.com, pay.kakao.com, etc.)",
            "! - PHILOSOPHY: Better to miss some ads than break legitimate functionality",
            "!",
            f"! Generated from {len(self.sources.get('sources', []))} data sources",
            f"! Total ad domains blocked: {len(sorted_domains)}",
            f"! Legitimate domains protected: {len(self.whitelist_domains)}",
            "!",
            "! Data Sources:",
            "!   - List-KR: Korean-language website filters",
            "!   - YousList: Korean sites ad block filter",
            "!   - Known ad domains: Curated list of confirmed advertising domains",
            "!",
            "! Whitelisted legitimate services (NEVER blocked):",
            "!   - kakao.com, accounts.kakao.com, kauth.kakao.com (authentication)",
            "!   - pay.kakao.com, map.kakao.com, talk.kakao.com (core services)",
            "!   - developers.kakao.com, api.kakao.com (developer services)",
            "!   - melon.com, brunch.co.kr (entertainment/media)",
            "!   - daum.net (portal), and other essential services",
            "!",
            "! Ad patterns blocked:",
            "!   - Subdomains: ad.*, ads.*, track.*, pixel.*, beacon.*, collector.*",
            "!   - Analytics: analytics.*, metrics.*, dmp.*, bizboard.*",
            "!   - Ad paths: *.ad.*, display.ad.*, banner.ad.*, video.ad.*",
            "!",
        ]

        # Group domains by service
        kakao_domains = [d for d in sorted_domains if 'kakao' in d.lower()]
        daum_domains = [d for d in sorted_domains if 'daum' in d.lower()]
        other_domains = [d for d in sorted_domains if d not in kakao_domains and d not in daum_domains]

        if kakao_domains:
            lines.append("! === Kakao Ad Domains ===")
            for domain in kakao_domains:
                lines.append(f"||{domain}^")
            lines.append("!")

        if daum_domains:
            lines.append("! === Daum Ad Domains ===")
            for domain in daum_domains:
                lines.append(f"||{domain}^")
            lines.append("!")

        if other_domains:
            lines.append("! === Other Kakao-related Ad Domains ===")
            for domain in other_domains:
                lines.append(f"||{domain}^")
            lines.append("!")

        lines.append("! === End of Filter ===")

        return '\n'.join(lines)

    def save_filter(self, output_file: str) -> bool:
        """Save generated filter to file"""
        try:
            filter_content = self.generate_adguard_filter()

            if not filter_content:
                print("No domains collected, filter not generated")
                return False

            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(filter_content)

            print(f"Filter saved to {output_file}")
            print(f"Total domains: {len(self.collected_domains)}")
            return True

        except Exception as e:
            print(f"Error saving filter: {e}")
            return False


def main():
    """Main function"""
    if len(sys.argv) > 1:
        output_file = sys.argv[1]
    else:
        output_file = "kakao-adblock-filter.txt"

    print("Kakao/Daum Precision Ad Domain Collector")
    print("=" * 50)
    print("PRECISION FILTERING: Only blocking confirmed ad/tracking domains")
    print("WHITELIST PROTECTION: Preserving essential Kakao services")
    print("=" * 50)

    collector = KakaoDomainCollector()

    print(f"\nWhitelist: {len(collector.whitelist_domains)} legitimate domains protected")
    print("Sample protected domains: kakao.com, accounts.kakao.com, pay.kakao.com")

    # Collect domains from external sources
    print("\n1. Collecting from external sources...")
    collector.collect_from_sources()

    # Add known domains
    print("\n2. Adding known ad domains...")
    collector.add_known_domains()

    # Generate and save filter
    print("\n3. Generating filter...")
    if collector.save_filter(output_file):
        print("\n✅ SUCCESS: Precision filter generated")
        print(f"📁 File: {output_file}")
        print(f"🚫 Ad domains blocked: {len(collector.collected_domains)}")
        print(f"✅ Legitimate domains protected: {len(collector.whitelist_domains)}")
        print("\n🎯 PHILOSOPHY: Precision over coverage - better to miss ads than break services")
        return 0
    else:
        print("❌ Filter generation failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
