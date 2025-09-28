#!/usr/bin/env python3
"""
Domain validation script for Kakao AdBlock filter
Validates domains using DNS lookups and checks if they are actually active
"""

import dns.resolver
import socket
import sys
import time
import concurrent.futures
from pathlib import Path
from typing import Set, Dict, List, Tuple
import argparse
import json
from datetime import datetime


class DomainValidator:
    def __init__(self, max_workers: int = 10, timeout: float = 5.0):
        self.max_workers = max_workers
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

        # Configure resolver with public DNS servers for reliability
        self.resolver.nameservers = [
            '8.8.8.8',     # Google DNS
            '1.1.1.1',     # Cloudflare DNS
            '208.67.222.222'  # OpenDNS
        ]

        self.validation_results: Dict[str, Dict] = {}

    def validate_single_domain(self, domain: str) -> Dict:
        """
        Validate a single domain using multiple methods.
        Returns detailed validation results.
        """
        result = {
            'domain': domain,
            'valid': False,
            'has_a_record': False,
            'has_aaaa_record': False,
            'has_cname_record': False,
            'has_mx_record': False,
            'ip_addresses': [],
            'cname_target': None,
            'mx_records': [],
            'error': None,
            'response_time': None,
            'status': 'unknown'
        }

        start_time = time.time()

        try:
            # Test A records (IPv4)
            try:
                a_records = self.resolver.resolve(domain, 'A')
                result['has_a_record'] = True
                result['ip_addresses'] = [str(record) for record in a_records]
                result['valid'] = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except Exception as e:
                result['error'] = f"A record error: {str(e)}"

            # Test AAAA records (IPv6)
            try:
                aaaa_records = self.resolver.resolve(domain, 'AAAA')
                result['has_aaaa_record'] = True
                if not result['ip_addresses']:
                    result['ip_addresses'] = []
                result['ip_addresses'].extend([str(record) for record in aaaa_records])
                result['valid'] = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except Exception as e:
                if not result['error']:
                    result['error'] = f"AAAA record error: {str(e)}"

            # Test CNAME records
            try:
                cname_records = self.resolver.resolve(domain, 'CNAME')
                result['has_cname_record'] = True
                result['cname_target'] = str(cname_records[0])
                result['valid'] = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except Exception as e:
                if not result['error']:
                    result['error'] = f"CNAME record error: {str(e)}"

            # Test MX records (for completeness)
            try:
                mx_records = self.resolver.resolve(domain, 'MX')
                result['has_mx_record'] = True
                result['mx_records'] = [str(record) for record in mx_records]
                result['valid'] = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except Exception:
                pass  # MX records are optional for ad domains

            # Calculate response time
            result['response_time'] = round((time.time() - start_time) * 1000, 2)  # ms

            # Determine status
            if result['valid']:
                if result['has_a_record'] or result['has_aaaa_record']:
                    result['status'] = 'active'
                elif result['has_cname_record']:
                    result['status'] = 'redirected'
                else:
                    result['status'] = 'exists'
            else:
                result['status'] = 'not_found'

        except dns.resolver.NXDOMAIN:
            result['status'] = 'not_found'
            result['error'] = 'Domain does not exist (NXDOMAIN)'
        except dns.resolver.Timeout:
            result['status'] = 'timeout'
            result['error'] = f'DNS timeout after {self.timeout}s'
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)

        return result

    def validate_domains_batch(self, domains: List[str]) -> Dict[str, Dict]:
        """
        Validate multiple domains in parallel.
        """
        print(f"Validating {len(domains)} domains using {self.max_workers} workers...")

        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all validation tasks
            future_to_domain = {
                executor.submit(self.validate_single_domain, domain): domain
                for domain in domains
            }

            # Collect results as they complete
            completed = 0
            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    result = future.result()
                    results[domain] = result
                except Exception as exc:
                    results[domain] = {
                        'domain': domain,
                        'valid': False,
                        'status': 'error',
                        'error': f'Validation failed: {exc}'
                    }

                completed += 1
                if completed % 10 == 0 or completed == len(domains):
                    print(f"  Progress: {completed}/{len(domains)} domains validated")

        return results

    def load_domains_from_filter(self, filter_file: str) -> List[str]:
        """
        Load domains from AdGuard filter file.
        """
        domains = []
        try:
            with open(filter_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if not line or line.startswith('!'):
                        continue

                    # Extract domain from AdGuard format ||domain.com^
                    if line.startswith('||') and line.endswith('^'):
                        domain = line[2:-1]  # Remove || and ^
                        if domain and '/' not in domain and ':' not in domain:
                            domains.append(domain)
        except FileNotFoundError:
            print(f"Error: Filter file {filter_file} not found")
            return []
        except Exception as e:
            print(f"Error reading filter file: {e}")
            return []

        return sorted(set(domains))  # Remove duplicates and sort

    def generate_validation_report(self, results: Dict[str, Dict]) -> Dict:
        """
        Generate summary report from validation results.
        """
        total = len(results)
        active = sum(1 for r in results.values() if r['status'] == 'active')
        redirected = sum(1 for r in results.values() if r['status'] == 'redirected')
        not_found = sum(1 for r in results.values() if r['status'] == 'not_found')
        timeout = sum(1 for r in results.values() if r['status'] == 'timeout')
        error = sum(1 for r in results.values() if r['status'] == 'error')

        # Calculate average response time for successful validations
        valid_response_times = [
            r['response_time'] for r in results.values()
            if r.get('response_time') is not None and r['status'] in ['active', 'redirected', 'exists']
        ]
        avg_response_time = sum(valid_response_times) / len(valid_response_times) if valid_response_times else 0

        return {
            'summary': {
                'total_domains': total,
                'active_domains': active,
                'redirected_domains': redirected,
                'not_found_domains': not_found,
                'timeout_domains': timeout,
                'error_domains': error,
                'valid_domains': active + redirected,
                'invalid_domains': not_found + timeout + error,
                'success_rate': round((active + redirected) / total * 100, 2) if total > 0 else 0,
                'average_response_time_ms': round(avg_response_time, 2)
            },
            'details': results,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'validation_settings': {
                'max_workers': self.max_workers,
                'timeout_seconds': self.timeout,
                'dns_servers': self.resolver.nameservers
            }
        }

    def save_report(self, report: Dict, output_file: str) -> None:
        """
        Save validation report to JSON file.
        """
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"Validation report saved to: {output_file}")
        except Exception as e:
            print(f"Error saving report: {e}")

    def print_summary(self, report: Dict) -> None:
        """
        Print validation summary to console.
        """
        summary = report['summary']

        print("\n" + "="*60)
        print("DOMAIN VALIDATION SUMMARY")
        print("="*60)
        print(f"Total domains tested: {summary['total_domains']}")
        print(f"Active domains (A/AAAA records): {summary['active_domains']}")
        print(f"Redirected domains (CNAME only): {summary['redirected_domains']}")
        print(f"Not found domains (NXDOMAIN): {summary['not_found_domains']}")
        print(f"Timeout/Error domains: {summary['timeout_domains'] + summary['error_domains']}")
        print(f"Success rate: {summary['success_rate']}%")
        print(f"Average response time: {summary['average_response_time_ms']}ms")

        print("\n" + "-"*40)
        print("DOMAIN STATUS BREAKDOWN:")
        print("-"*40)

        # Group domains by status
        status_groups = {}
        for domain, result in report['details'].items():
            status = result['status']
            if status not in status_groups:
                status_groups[status] = []
            status_groups[status].append(domain)

        for status, domains in sorted(status_groups.items()):
            print(f"\n{status.upper()} ({len(domains)} domains):")
            for domain in sorted(domains)[:10]:  # Show first 10
                result = report['details'][domain]
                if result.get('ip_addresses'):
                    print(f"  {domain} -> {', '.join(result['ip_addresses'][:2])}")
                elif result.get('cname_target'):
                    print(f"  {domain} -> CNAME: {result['cname_target']}")
                else:
                    print(f"  {domain} -> {result.get('error', 'No records')}")

            if len(domains) > 10:
                print(f"  ... and {len(domains) - 10} more")

        print("\n" + "="*60)

    def filter_valid_domains(self, results: Dict[str, Dict]) -> List[str]:
        """
        Return list of domains that have valid DNS records.
        """
        return [
            domain for domain, result in results.items()
            if result['status'] in ['active', 'redirected', 'exists']
        ]

    def filter_invalid_domains(self, results: Dict[str, Dict]) -> List[str]:
        """
        Return list of domains that should be removed (no valid DNS records).
        """
        return [
            domain for domain, result in results.items()
            if result['status'] in ['not_found', 'timeout', 'error']
        ]


def main():
    parser = argparse.ArgumentParser(description='Validate Kakao ad domains using DNS lookups')
    parser.add_argument('filter_file', help='AdGuard filter file to validate')
    parser.add_argument('-o', '--output', help='Output JSON report file',
                       default='domain_validation_report.json')
    parser.add_argument('-w', '--workers', type=int, default=10,
                       help='Number of parallel DNS lookup workers (default: 10)')
    parser.add_argument('-t', '--timeout', type=float, default=5.0,
                       help='DNS lookup timeout in seconds (default: 5.0)')
    parser.add_argument('--clean-filter', help='Output file for cleaned filter (valid domains only)')
    parser.add_argument('--removed-domains', help='Output file for invalid domains list')
    parser.add_argument('--quiet', action='store_true', help='Suppress progress output')

    args = parser.parse_args()

    if not Path(args.filter_file).exists():
        print(f"Error: Filter file '{args.filter_file}' not found")
        return 1

    # Initialize validator
    validator = DomainValidator(max_workers=args.workers, timeout=args.timeout)

    # Load domains from filter file
    print(f"Loading domains from: {args.filter_file}")
    domains = validator.load_domains_from_filter(args.filter_file)

    if not domains:
        print("No domains found in filter file")
        return 1

    print(f"Found {len(domains)} domains to validate")

    # Validate domains
    results = validator.validate_domains_batch(domains)

    # Generate report
    report = validator.generate_validation_report(results)

    # Save report
    validator.save_report(report, args.output)

    # Print summary
    if not args.quiet:
        validator.print_summary(report)

    # Generate cleaned filter if requested
    if args.clean_filter:
        valid_domains = validator.filter_valid_domains(results)
        print(f"\nGenerating cleaned filter with {len(valid_domains)} valid domains...")

        # Read original filter and recreate with only valid domains
        try:
            with open(args.filter_file, 'r', encoding='utf-8') as f:
                original_lines = f.readlines()

            with open(args.clean_filter, 'w', encoding='utf-8') as f:
                # Copy header comments
                for line in original_lines:
                    if line.strip().startswith('!') or not line.strip():
                        f.write(line)
                    elif line.strip().startswith('||') and line.strip().endswith('^'):
                        domain = line.strip()[2:-1]
                        if domain in valid_domains:
                            f.write(line)
                    else:
                        f.write(line)  # Other format lines

            print(f"Cleaned filter saved to: {args.clean_filter}")
        except Exception as e:
            print(f"Error generating cleaned filter: {e}")

    # Save removed domains list if requested
    if args.removed_domains:
        invalid_domains = validator.filter_invalid_domains(results)
        try:
            with open(args.removed_domains, 'w', encoding='utf-8') as f:
                f.write(f"# Invalid domains removed from filter\n")
                f.write(f"# Generated: {datetime.utcnow().isoformat()}Z\n")
                f.write(f"# Total removed: {len(invalid_domains)}\n\n")
                for domain in sorted(invalid_domains):
                    result = results[domain]
                    f.write(f"{domain}  # {result['status']}: {result.get('error', 'No DNS records')}\n")

            print(f"Removed domains list saved to: {args.removed_domains}")
        except Exception as e:
            print(f"Error saving removed domains list: {e}")

    # Return exit code based on success rate
    success_rate = report['summary']['success_rate']
    if success_rate >= 80:
        return 0  # Good success rate
    elif success_rate >= 60:
        print(f"Warning: Low success rate ({success_rate}%), many domains may be invalid")
        return 0
    else:
        print(f"Error: Very low success rate ({success_rate}%), filter may need review")
        return 1


if __name__ == '__main__':
    sys.exit(main())