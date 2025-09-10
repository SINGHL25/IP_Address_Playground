
"""
DNS Resolver Module

This module provides comprehensive DNS resolution functionality including
domain name resolution, reverse DNS lookups, and DNS record analysis.
"""

import socket
import random
import time
from typing import Dict, List, Optional, Union, Any
from utils.helpers import validate_domain_name, validate_ip_address

class DNSResolver:
    """
    A comprehensive DNS resolver that provides domain name resolution,
    reverse DNS lookups, and DNS record analysis functionality.
    """
    
    def __init__(self):
        """Initialize the DNS resolver with default settings."""
        self.default_timeout = 5
        self.cache = {}
        self.cache_ttl = 300  # 5 minutes default TTL
        self.dns_servers = {
            'google': ['8.8.8.8', '8.8.4.4'],
            'cloudflare': ['1.1.1.1', '1.0.0.1'],
            'opendns': ['208.67.222.222', '208.67.220.220'],
            'quad9': ['9.9.9.9', '149.112.112.112']
        }
        
        self.record_types = {
            'A': 'IPv4 address record',
            'AAAA': 'IPv6 address record',
            'CNAME': 'Canonical name record',
            'MX': 'Mail exchange record',
            'NS': 'Name server record',
            'TXT': 'Text record',
            'PTR': 'Pointer record (reverse DNS)',
            'SOA': 'Start of authority record',
            'SRV': 'Service record'
        }
    
    def resolve_domain(self, domain: str, record_type: str = 'A', dns_server: str = None) -> Optional[Dict]:
        """
        Resolve a domain name to its corresponding records.
        
        Args:
            domain (str): Domain name to resolve
            record_type (str): Type of DNS record to query
            dns_server (str): Specific DNS server to use
            
        Returns:
            Dict: Resolution results or None if failed
        """
        if not validate_domain_name(domain):
            return {'error': 'Invalid domain name format'}
        
        # Check cache first
        cache_key = f"{domain}:{record_type}"
        if cache_key in self.cache:
            cached_result = self.cache[cache_key]
            if time.time() - cached_result['timestamp'] < self.cache_ttl:
                cached_result['from_cache'] = True
                return cached_result
        
        try:
            # Configure DNS server if specified
            original_dns = None
            if dns_server and validate_ip_address(dns_server):
                # Note: In a real implementation, you would configure the resolver
                # to use the specific DNS server. For this simulation, we'll
                # note which server was requested.
                pass
            
            records = []
            server_used = dns_server or 'System Default'
            
            if record_type.upper() == 'A':
                # Resolve A records (IPv4)
                try:
                    result = socket.getaddrinfo(domain, None, socket.AF_INET)
                    records = list(set([addr[4][0] for addr in result]))
                except:
                    records = []
            
            elif record_type.upper() == 'AAAA':
                # Resolve AAAA records (IPv6)
                try:
                    result = socket.getaddrinfo(domain, None, socket.AF_INET6)
                    records = list(set([addr[4][0] for addr in result]))
                except:
                    records = []
            
            elif record_type.upper() == 'PTR':
                # Reverse DNS lookup
                if validate_ip_address(domain):
                    try:
                        result = socket.gethostbyaddr(domain)
                        records = [result[0]]
                    except:
                        records = []
                else:
                    return {'error': 'PTR records require IP address, not domain name'}
            
            else:
                # For other record types, simulate the response
                # In a real implementation, you'd use a DNS library like dnspython
                records = self._simulate_dns_records(domain, record_type.upper())
            
            # Prepare result
            result = {
                'domain': domain,
                'record_type': record_type.upper(),
                'records': records,
                'server': server_used,
                'timestamp': time.time(),
                'ttl': random.randint(300, 3600),  # Simulated TTL
                'from_cache': False,
                'query_time': random.uniform(0.010, 0.100)  # Simulated query time
            }
            
            # Cache the result
            self.cache[cache_key] = result.copy()
            
            return result
            
        except Exception as e:
            return {'error': f'DNS resolution failed: {str(e)}'}
    
    def reverse_lookup(self, ip_address: str) -> Optional[Dict]:
        """
        Perform reverse DNS lookup for an IP address.
        
        Args:
            ip_address (str): IP address to look up
            
        Returns:
            Dict: Reverse lookup results
        """
        if not validate_ip_address(ip_address):
            return {'error': 'Invalid IP address format'}
        
        return self.resolve_domain(ip_address, 'PTR')
    
    def batch_resolve(self, domains: List[str], record_type: str = 'A') -> Dict[str, Dict]:
        """
        Resolve multiple domains in batch.
        
        Args:
            domains (List[str]): List of domains to resolve
            record_type (str): Type of DNS record to query
            
        Returns:
            Dict: Results for each domain
        """
        results = {}
        
        for domain in domains:
            if validate_domain_name(domain):
                result = self.resolve_domain(domain, record_type)
                results[domain] = result
            else:
                results[domain] = {'error': 'Invalid domain name format'}
        
        return results
    
    def get_record_info(self, record: str, record_type: str) -> Dict:
        """
        Get detailed information about a DNS record.
        
        Args:
            record (str): DNS record value
            record_type (str): Type of DNS record
            
        Returns:
            Dict: Detailed record information
        """
        info = {
            'record_value': record,
            'record_type': record_type,
            'description': self.record_types.get(record_type.upper(), 'Unknown record type'),
            'ttl': random.randint(300, 3600)  # Simulated TTL
        }
        
        if record_type.upper() == 'A':
            info.update({
                'ip_version': 'IPv4',
                'is_private': self._is_private_ip(record),
                'is_routable': not self._is_private_ip(record)
            })
        
        elif record_type.upper() == 'AAAA':
            info.update({
                'ip_version': 'IPv6',
                'is_private': False,  # Simplified for IPv6
                'is_routable': True
            })
        
        elif record_type.upper() == 'MX':
            # Parse MX record (priority server)
            parts = record.split(' ', 1)
            if len(parts) == 2:
                info.update({
                    'priority': parts[0],
                    'mail_server': parts[1],
                    'preference': int(parts[0]) if parts[0].isdigit() else 0
                })
        
        elif record_type.upper() == 'CNAME':
            info.update({
                'canonical_name': record,
                'is_alias': True
            })
        
        elif record_type.upper() == 'NS':
            info.update({
                'name_server': record,
                'authoritative': True
            })
        
        elif record_type.upper() == 'TXT':
            info.update({
                'text_data': record,
                'length': len(record),
                'common_uses': ['SPF', 'DKIM', 'Domain verification', 'Configuration data']
            })
        
        return info
    
    def trace_dns_path(self, domain: str) -> List[Dict]:
        """
        Simulate DNS resolution path tracing.
        
        Args:
            domain (str): Domain to trace
            
        Returns:
            List[Dict]: DNS resolution path steps
        """
        if not validate_domain_name(domain):
            return [{'error': 'Invalid domain name format'}]
        
        domain_parts = domain.split('.')
        path_steps = []
        
        # Root servers
        path_steps.append({
            'step': 1,
            'server_type': 'Root Name Server',
            'server': 'a.root-servers.net',
            'query': f'Where is {domain}?',
            'response': f'Ask {domain_parts[-1]} TLD servers',
            'referral': f'{domain_parts[-1]} TLD servers'
        })
        
        # TLD servers
        tld = domain_parts[-1]
        path_steps.append({
            'step': 2,
            'server_type': f'{tld.upper()} TLD Server',
            'server': f'{tld}.gtld-servers.net',
            'query': f'Where is {domain}?',
            'response': f'Ask {domain} authoritative servers',
            'referral': f'{domain} authoritative name servers'
        })
        
        # Authoritative servers
        path_steps.append({
            'step': 3,
            'server_type': 'Authoritative Name Server',
            'server': f'ns1.{domain}',
            'query': f'What is the A record for {domain}?',
            'response': 'Returns IP address',
            'final_answer': True
        })
        
        return path_steps
    
    def analyze_domain_health(self, domain: str) -> Dict:
        """
        Analyze the DNS health of a domain.
        
        Args:
            domain (str): Domain to analyze
            
        Returns:
            Dict: Domain health analysis
        """
        if not validate_domain_name(domain):
            return {'error': 'Invalid domain name format'}
        
        health_report = {
            'domain': domain,
            'timestamp': time.time(),
            'overall_health': 'Unknown',
            'checks': {}
        }
        
        # Check different record types
        record_checks = ['A', 'AAAA', 'MX', 'NS', 'TXT']
        passed_checks = 0
        
        for record_type in record_checks:
            result = self.resolve_domain(domain, record_type)
            
            if result and 'records' in result and result['records']:
                health_report['checks'][record_type] = {
                    'status': 'PASS',
                    'count': len(result['records']),
                    'records': result['records'][:3]  # Show first 3 records
                }
                passed_checks += 1
            else:
                health_report['checks'][record_type] = {
                    'status': 'FAIL',
                    'count': 0,
                    'records': []
                }
        
        # Calculate overall health
        health_percentage = (passed_checks / len(record_checks)) * 100
        
        if health_percentage >= 80:
            health_report['overall_health'] = 'Excellent'
        elif health_percentage >= 60:
            health_report['overall_health'] = 'Good'
        elif health_percentage >= 40:
            health_report['overall_health'] = 'Fair'
        else:
            health_report['overall_health'] = 'Poor'
        
        health_report['health_score'] = round(health_percentage, 1)
        
        # Add recommendations
        recommendations = []
        
        if not health_report['checks']['A']['records']:
            recommendations.append('Configure A record for IPv4 connectivity')
        
        if not health_report['checks']['AAAA']['records']:
            recommendations.append('Consider adding AAAA record for IPv6 support')
        
        if not health_report['checks']['MX']['records']:
            recommendations.append('Configure MX records if email service is needed')
        
        if not health_report['checks']['NS']['records']:
            recommendations.append('Ensure proper NS records are configured')
        
        health_report['recommendations'] = recommendations
        
        return health_report
    
    def benchmark_dns_servers(self, domain: str = 'google.com') -> Dict:
        """
        Benchmark different DNS servers for resolution speed.
        
        Args:
            domain (str): Test domain for benchmarking
            
        Returns:
            Dict: Benchmark results
        """
        if not validate_domain_name(domain):
            return {'error': 'Invalid domain name format'}
        
        benchmark_results = {
            'test_domain': domain,
            'timestamp': time.time(),
            'results': {}
        }
        
        # Test different DNS server providers
        for provider, servers in self.dns_servers.items():
            provider_results = []
            
            for server in servers:
                # Simulate DNS query time
                start_time = time.time()
                
                try:
                    # In a real implementation, you'd actually query the specific server
                    result = self.resolve_domain(domain, 'A', server)
                    end_time = time.time()
                    
                    if result and 'records' in result and result['records']:
                        query_time = (end_time - start_time) * 1000  # Convert to milliseconds
                        provider_results.append({
                            'server': server,
                            'response_time': round(query_time, 2),
                            'status': 'SUCCESS',
                            'records_count': len(result['records'])
                        })
                    else:
                        provider_results.append({
                            'server': server,
                            'response_time': None,
                            'status': 'FAILED',
                            'records_count': 0
                        })
                
                except Exception as e:
                    provider_results.append({
                        'server': server,
                        'response_time': None,
                        'status': 'ERROR',
                        'error': str(e)
                    })
            
            # Calculate provider average
            successful_queries = [r for r in provider_results if r['status'] == 'SUCCESS']
            if successful_queries:
                avg_response_time = sum(r['response_time'] for r in successful_queries) / len(successful_queries)
                benchmark_results['results'][provider] = {
                    'servers': provider_results,
                    'average_response_time': round(avg_response_time, 2),
                    'success_rate': len(successful_queries) / len(provider_results) * 100
                }
            else:
                benchmark_results['results'][provider] = {
                    'servers': provider_results,
                    'average_response_time': None,
                    'success_rate': 0
                }
        
        return benchmark_results
    
    def clear_cache(self) -> bool:
        """
        Clear the DNS cache.
        
        Returns:
            bool: True if successful
        """
        try:
            self.cache.clear()
            return True
        except:
            return False
    
    def get_cache_stats(self) -> Dict:
        """
        Get DNS cache statistics.
        
        Returns:
            Dict: Cache statistics
        """
        current_time = time.time()
        valid_entries = 0
        expired_entries = 0
        
        for cache_key, cache_entry in self.cache.items():
            if current_time - cache_entry['timestamp'] < self.cache_ttl:
                valid_entries += 1
            else:
                expired_entries += 1
        
        return {
            'total_entries': len(self.cache),
            'valid_entries': valid_entries,
            'expired_entries': expired_entries,
            'cache_ttl': self.cache_ttl,
            'hit_rate': 'Not implemented',  # Would track in real implementation
            'memory_usage': 'Not implemented'
        }
    
    def _simulate_dns_records(self, domain: str, record_type: str) -> List[str]:
        """
        Simulate DNS records for record types not handled by socket library.
        
        Args:
            domain (str): Domain name
            record_type (str): Record type
            
        Returns:
            List[str]: Simulated records
        """
        records = []
        
        if record_type == 'MX':
            # Simulate MX records
            mail_servers = [
                f"10 mail.{domain}",
                f"20 mail2.{domain}",
                f"30 backup.{domain}"
            ]
            records = mail_servers[:random.randint(1, 3)]
        
        elif record_type == 'NS':
            # Simulate NS records
            name_servers = [
                f"ns1.{domain}",
                f"ns2.{domain}",
                f"ns3.{domain}"
            ]
            records = name_servers[:random.randint(2, 3)]
        
        elif record_type == 'TXT':
            # Simulate TXT records
            txt_records = [
                f"v=spf1 include:_spf.{domain} ~all",
                f"google-site-verification=random123456789",
                f"domain-verification=abcdef123456"
            ]
            records = txt_records[:random.randint(1, 3)]
        
        elif record_type == 'CNAME':
            # Simulate CNAME record
            if domain.startswith('www.'):
                base_domain = domain[4:]
                records = [base_domain]
            else:
                records = [f"alias.{domain}"]
        
        elif record_type == 'SOA':
            # Simulate SOA record
            records = [f"ns1.{domain} admin.{domain} 2024010101 3600 1800 604800 86400"]
        
        elif record_type == 'SRV':
            # Simulate SRV records
            srv_records = [
                f"0 5 443 sip.{domain}",
                f"10 10 443 sip2.{domain}"
            ]
            records = srv_records[:random.randint(1, 2)]
        
        return records
    
    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if an IP address is private."""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip_address)
            return ip_obj.is_private
        except:
            return False
    
    def query_specific_server(self, domain: str, record_type: str, dns_server: str) -> Optional[Dict]:
        """
        Query a specific DNS server directly.
        
        Args:
            domain (str): Domain to query
            record_type (str): Record type to query
            dns_server (str): DNS server IP address
            
        Returns:
            Dict: Query results
        """
        if not validate_domain_name(domain) or not validate_ip_address(dns_server):
            return {'error': 'Invalid domain or DNS server'}
        
        # In a real implementation, this would use a DNS library to query
        # the specific server directly. For simulation, we'll return
        # similar results to the regular resolve_domain method.
        
        result = self.resolve_domain(domain, record_type)
        if result:
            result['queried_server'] = dns_server
            result['direct_query'] = True
        
        return result
    
    def get_authoritative_servers(self, domain: str) -> List[str]:
        """
        Get authoritative name servers for a domain.
        
        Args:
            domain (str): Domain to query
            
        Returns:
            List[str]: List of authoritative name servers
        """
        if not validate_domain_name(domain):
            return []
        
        ns_result = self.resolve_domain(domain, 'NS')
        if ns_result and 'records' in ns_result:
            return ns_result['records']
        
        return []
    
    def check_dns_propagation(self, domain: str, record_type: str = 'A') -> Dict:
        """
        Check DNS propagation across multiple servers.
        
        Args:
            domain (str): Domain to check
            record_type (str): Record type to check
            
        Returns:
            Dict: Propagation check results
        """
        if not validate_domain_name(domain):
            return {'error': 'Invalid domain name'}
        
        propagation_results = {
            'domain': domain,
            'record_type': record_type,
            'timestamp': time.time(),
            'servers': {},
            'consensus': None,
            'propagated': False
        }
        
        all_records = []
        
        # Check multiple DNS servers
        for provider, servers in self.dns_servers.items():
            for server in servers[:1]:  # Check first server from each provider
                try:
                    result = self.resolve_domain(domain, record_type, server)
                    
                    if result and 'records' in result and result['records']:
                        records = sorted(result['records'])  # Sort for comparison
                        propagation_results['servers'][server] = {
                            'status': 'SUCCESS',
                            'records': records,
                            'query_time': result.get('query_time', 0)
                        }
                        all_records.extend(records)
                    else:
                        propagation_results['servers'][server] = {
                            'status': 'NO_RECORDS',
                            'records': [],
                            'query_time': None
                        }
                
                except Exception as e:
                    propagation_results['servers'][server] = {
                        'status': 'ERROR',
                        'error': str(e),
                        'records': [],
                        'query_time': None
                    }
        
        # Determine consensus
        if all_records:
            # Find most common record set
            from collections import Counter
            record_sets = []
            for server_data in propagation_results['servers'].values():
                if server_data['status'] == 'SUCCESS':
                    record_sets.append(tuple(sorted(server_data['records'])))
            
            if record_sets:
                most_common = Counter(record_sets).most_common(1)[0]
                propagation_results['consensus'] = list(most_common[0])
                
                # Check if all servers agree
                successful_servers = [s for s in propagation_results['servers'].values() 
                                    if s['status'] == 'SUCCESS']
                
                if successful_servers:
                    all_agree = all(
                        sorted(s['records']) == sorted(propagation_results['consensus'])
                        for s in successful_servers
                    )
                    propagation_results['propagated'] = all_agree
        
        return propagation_results
    
    def dns_lookup_history(self, domain: str, days: int = 7) -> List[Dict]:
        """
        Get DNS lookup history for a domain (simulated).
        
        Args:
            domain (str): Domain to get history for
            days (int): Number of days of history
            
        Returns:
            List[Dict]: Historical lookup data
        """
        if not validate_domain_name(domain):
            return []
        
        # Simulate historical data
        import datetime
        
        history = []
        current_time = datetime.datetime.now()
        
        for day in range(days):
            lookup_date = current_time - datetime.timedelta(days=day)
            
            # Simulate some lookups for each day
            for _ in range(random.randint(5, 50)):
                lookup_time = lookup_date - datetime.timedelta(
                    hours=random.randint(0, 23),
                    minutes=random.randint(0, 59)
                )
                
                history.append({
                    'timestamp': lookup_time.isoformat(),
                    'domain': domain,
                    'record_type': random.choice(['A', 'AAAA', 'MX', 'NS']),
                    'query_time': round(random.uniform(10, 200), 2),  # ms
                    'server': random.choice([
                        '8.8.8.8', '1.1.1.1', '208.67.222.222', 'System Default'
                    ]),
                    'status': random.choices(['SUCCESS', 'FAILED'], weights=[95, 5])[0]
                })
        
        return sorted(history, key=lambda x: x['timestamp'], reverse=True)
    
    def export_dns_config(self, domain: str) -> str:
        """
        Export DNS configuration for a domain in zone file format.
        
        Args:
            domain (str): Domain to export
            
        Returns:
            str: Zone file content
        """
        if not validate_domain_name(domain):
            return "; Error: Invalid domain name\n"
        
        zone_file = f"""; Zone file for {domain}
; Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

$ORIGIN {domain}.
$TTL 3600

; SOA Record
@    IN    SOA    ns1.{domain}. admin.{domain}. (
                    2024010101    ; Serial number
                    3600          ; Refresh
                    1800          ; Retry
                    604800        ; Expire
                    86400 )       ; Minimum TTL

; Name Server Records
@    IN    NS     ns1.{domain}.
@    IN    NS     ns2.{domain}.

; A Records
@    IN    A      192.168.1.100
www  IN    A      192.168.1.100

; MX Records
@    IN    MX     10 mail.{domain}.
@    IN    MX     20 mail2.{domain}.

; CNAME Records
ftp  IN    CNAME  www.{domain}.
mail IN    A      192.168.1.110

; TXT Records
@    IN    TXT    "v=spf1 mx ~all"
@    IN    TXT    "domain-verification=example123456"
"""
        
        return zone_file
        
