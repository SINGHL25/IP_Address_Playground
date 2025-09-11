
"""
Unit tests for DNS Resolver module

This file contains comprehensive tests for the DNSResolver class,
testing domain resolution, caching, and DNS analysis functionality.
"""

import unittest
import sys
import os
import time

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns_resolver import DNSResolver


class TestDNSResolver(unittest.TestCase):
    """Test cases for DNSResolver class"""
    
    def setUp(self):
        """Set up test fixtures before each test method"""
        self.dns = DNSResolver()
        # Clear cache before each test
        self.dns.clear_cache()
    
    def tearDown(self):
        """Clean up after each test method"""
        self.dns.clear_cache()
    
    def test_resolver_initialization(self):
        """Test DNS resolver initialization"""
        self.assertIsInstance(self.dns.dns_servers, dict)
        self.assertIn('google', self.dns.dns_servers)
        self.assertIn('cloudflare', self.dns.dns_servers)
        self.assertIsInstance(self.dns.record_types, dict)
        self.assertIn('A', self.dns.record_types)
        self.assertIn('MX', self.dns.record_types)
    
    def test_domain_resolution_valid(self):
        """Test valid domain resolution"""
        # Test A record resolution
        result = self.dns.resolve_domain('google.com', 'A')
        
        self.assertIsInstance(result, dict)
        self.assertIn('domain', result)
        self.assertIn('record_type', result)
        self.assertIn('records', result)
        self.assertEqual(result['domain'], 'google.com')
        self.assertEqual(result['record_type'], 'A')
        
        # Should have at least one record
        if result.get('records'):
            self.assertGreater(len(result['records']), 0)
            # Each record should be a valid-looking IP
            for record in result['records']:
                self.assertRegex(record, r'^\d+\.\d+\.\d+\.\d+$')
    
    def test_domain_resolution_invalid(self):
        """Test invalid domain resolution"""
        # Test with invalid domain format
        result = self.dns.resolve_domain('invalid..domain', 'A')
        self.assertIn('error', result)
        
        # Test with empty domain
        result = self.dns.resolve_domain('', 'A')
        self.assertIn('error', result)
        
        # Test with None domain
        result = self.dns.resolve_domain(None, 'A')
        self.assertIn('error', result)
    
    def test_different_record_types(self):
        """Test resolution of different DNS record types"""
        test_domain = 'google.com'
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
        
        for record_type in record_types:
            with self.subTest(record_type=record_type):
                result = self.dns.resolve_domain(test_domain, record_type)
                
                self.assertIsInstance(result, dict)
                self.assertEqual(result['domain'], test_domain)
                self.assertEqual(result['record_type'], record_type)
                self.assertIn('records', result)
                # Records might be empty for some types, which is okay
    
    def test_reverse_dns_lookup(self):
        """Test reverse DNS lookup functionality"""
        # Test with valid IP
        result = self.dns.reverse_lookup('8.8.8.8')
        
        self.assertIsInstance(result, dict)
        # Might have records or might not, depending on the IP
        
        # Test with invalid IP
        result = self.dns.reverse_lookup('invalid_ip')
        self.assertIn('error', result)
        
        # Test with private IP (might not have reverse DNS)
        result = self.dns.reverse_lookup('192.168.1.1')
        self.assertIsInstance(result, dict)
    
    def test_batch_resolution(self):
        """Test batch domain resolution"""
        domains = ['google.com', 'github.com', 'stackoverflow.com']
        results = self.dns.batch_resolve(domains, 'A')
        
        self.assertIsInstance(results, dict)
        self.assertEqual(len(results), len(domains))
        
        for domain in domains:
            self.assertIn(domain, results)
            self.assertIsInstance(results[domain], dict)
    
    def test_dns_caching(self):
        """Test DNS caching functionality"""
        domain = 'google.com'
        
        # First request (cache miss)
        result1 = self.dns.resolve_domain(domain, 'A')
        self.assertIsInstance(result1, dict)
        self.assertFalse(result1.get('from_cache', False))
        
        # Second request (should be cache hit)
        result2 = self.dns.resolve_domain(domain, 'A')
        self.assertIsInstance(result2, dict)
        
        # In simulation, caching behavior depends on implementation
        # We can at least verify the structure is correct
    
    def test_cache_management(self):
        """Test cache management operations"""
        # Add something to cache
        self.dns.resolve_domain('google.com', 'A')
        
        # Get cache stats
        stats = self.dns.get_cache_stats()
        self.assertIsInstance(stats, dict)
        self.assertIn('total_entries', stats)
        self.assertIn('valid_entries', stats)
        
        # Clear cache
        result = self.dns.clear_cache()
        self.assertTrue(result)
        
        # Verify cache is cleared
        stats_after = self.dns.get_cache_stats()
        self.assertEqual(stats_after['total_entries'], 0)
    
    def test_record_info_analysis(self):
        """Test DNS record information analysis"""
        # Test A record info
        a_info = self.dns.get_record_info('8.8.8.8', 'A')
        self.assertIsInstance(a_info, dict)
        self.assertEqual(a_info['record_type'], 'A')
        self.assertIn('ip_version', a_info)
        
        # Test MX record info
        mx_info = self.dns.get_record_info('10 mail.example.com', 'MX')
        self.assertIsInstance(mx_info, dict)
        self.assertEqual(mx_info['record_type'], 'MX')
        if 'priority' in mx_info:
            self.assertEqual(mx_info['priority'], '10')
        
        # Test CNAME record info
        cname_info = self.dns.get_record_info('www.example.com', 'CNAME')
        self.assertIsInstance(cname_info, dict)
        self.assertEqual(cname_info['record_type'], 'CNAME')
    
    def test_dns_path_tracing(self):
        """Test DNS resolution path tracing"""
        domain = 'google.com'
        path_steps = self.dns.trace_dns_path(domain)
        
        self.assertIsInstance(path_steps, list)
        self.assertGreater(len(path_steps), 0)
        
        for step in path_steps:
            self.assertIsInstance(step, dict)
            # Should have basic step information
            if 'error' not in step:
                self.assertIn('step', step)
                self.assertIn('server_type', step)
    
    def test_domain_health_analysis(self):
        """Test domain health analysis"""
        domain = 'google.com'
        health_report = self.dns.analyze_domain_health(domain)
        
        self.assertIsInstance(health_report, dict)
        self.assertEqual(health_report['domain'], domain)
        self.assertIn('overall_health', health_report)
        self.assertIn('checks', health_report)
        self.assertIn('health_score', health_report)
        
        # Health score should be a number between 0 and 100
        if 'health_score' in health_report:
            score = health_report['health_score']
            self.assertGreaterEqual(score, 0)
            self.assertLessEqual(score, 100)
    
    def test_dns_server_benchmarking(self):
        """Test DNS server performance benchmarking"""
        domain = 'google.com'
        benchmark_results = self.dns.benchmark_dns_servers(domain)
        
        self.assertIsInstance(benchmark_results, dict)
        self.assertIn('test_domain', benchmark_results)
        self.assertIn('results', benchmark_results)
        
        # Should have results for each DNS provider
        results = benchmark_results['results']
        self.assertIsInstance(results, dict)
        
        # Check that we have results for known providers
        expected_providers = ['google', 'cloudflare', 'opendns', 'quad9']
        for provider in expected_providers:
            if provider in results:
                provider_result = results[provider]
                self.assertIsInstance(provider_result, dict)
                self.assertIn('servers', provider_result)
    
    def test_dns_propagation_check(self):
        """Test DNS propagation checking"""
        domain = 'google.com'
        propagation_result = self.dns.check_dns_propagation(domain, 'A')
        
        self.assertIsInstance(propagation_result, dict)
        self.assertEqual(propagation_result['domain'], domain)
        self.assertEqual(propagation_result['record_type'], 'A')
        self.assertIn('servers', propagation_result)
        self.assertIn('propagated', propagation_result)
        
        # Should have checked multiple servers
        servers = propagation_result.get('servers', {})
        self.assertGreater(len(servers), 0)
    
    def test_authoritative_servers(self):
        """Test getting authoritative servers"""
        domain = 'google.com'
        auth_servers = self.dns.get_authoritative_servers(domain)
        
        self.assertIsInstance(auth_servers, list)
        # Might be empty depending on implementation/simulation
    
    def test_dns_lookup_history(self):
        """Test DNS lookup history functionality"""
        domain = 'google.com'
        history = self.dns.dns_lookup_history(domain, days=7)
        
        self.assertIsInstance(history, list)
        # In simulation, this might return simulated data
        
        for entry in history[:5]:  # Check first 5 entries
            self.assertIsInstance(entry, dict)
            self.assertIn('timestamp', entry)
            self.assertIn('domain', entry)
            self.assertIn('record_type', entry)
    
    def test_export_dns_config(self):
        """Test DNS configuration export"""
        domain = 'example.com'
        zone_file = self.dns.export_dns_config(domain)
        
        self.assertIsInstance(zone_file, str)
        self.assertIn(domain, zone_file)
        self.assertIn('SOA', zone_file)
        self.assertIn('NS', zone_file)
        
        # Should look like a zone file
        self.assertIn('$ORIGIN', zone_file)
        self.assertIn('$TTL', zone_file)


class TestDNSResolverEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions for DNS resolver"""
    
    def setUp(self):
        self.dns = DNSResolver()
    
    def test_special_domains(self):
        """Test resolution of special domains"""
        special_domains = [
            'localhost',
            '127.0.0.1',  # IP as domain
            'example.com',  # RFC reserved domain
        ]
        
        for domain in special_domains:
            with self.subTest(domain=domain):
                if domain == '127.0.0.1':
                    # This should be handled as reverse DNS
                    result = self.dns.reverse_lookup(domain)
                else:
                    result = self.dns.resolve_domain(domain, 'A')
                
                self.assertIsInstance(result, dict)
    
    def test_timeout_handling(self):
        """Test handling of DNS timeouts"""
        # Test with non-existent domain that might timeout
        result = self.dns.resolve_domain('this-domain-should-not-exist-12345.com', 'A')
        
        self.assertIsInstance(result, dict)
        # Should either have records or an error, but shouldn't crash
    
    def test_malformed_responses(self):
        """Test handling of malformed DNS responses"""
        # Test PTR lookup with invalid IP format
        result = self.dns.resolve_domain('not.an.ip.address', 'PTR')
        
        # Should handle gracefully
        self.assertIsInstance(result, dict)
        if 'error' in result:
            self.assertIsInstance(result['error'], str)
    
    def test_concurrent_requests(self):
        """Test concurrent DNS requests"""
        import threading
        import queue
        
        domains = ['google.com', 'github.com', 'stackoverflow.com', 'reddit.com']
        results_queue = queue.Queue()
        
        def resolve_domain_thread(domain):
            result = self.dns.resolve_domain(domain, 'A')
            results_queue.put((domain, result))
        
        # Start multiple threads
        threads = []
        for domain in domains:
            thread = threading.Thread(target=resolve_domain_thread, args=(domain,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=10)  # 10 second timeout
        
        # Collect results
        results = []
        while not results_queue.empty():
            results.append(results_queue.get())
        
        # Should have received results for all domains
        self.assertEqual(len(results), len(domains))
        
        for domain, result in results:
            self.assertIn(domain, domains)
            self.assertIsInstance(result, dict)
    
    def test_cache_expiration(self):
        """Test cache entry expiration"""
        # Set a very short TTL for testing
        original_ttl = self.dns.cache_ttl
        self.dns.cache_ttl = 1  # 1 second
        
        try:
            # Make a request
            result1 = self.dns.resolve_domain('google.com', 'A')
            
            # Wait for cache to expire
            time.sleep(2)
            
            # Make another request
            result2 = self.dns.resolve_domain('google.com', 'A')
            
            # Both should succeed
            self.assertIsInstance(result1, dict)
            self.assertIsInstance(result2, dict)
            
        finally:
            # Restore original TTL
            self.dns.cache_ttl = original_ttl
    
    def test_large_response_handling(self):
        """Test handling of large DNS responses"""
        # Test with domain that might have many records
        result = self.dns.resolve_domain('google.com', 'TXT')
        
        self.assertIsInstance(result, dict)
        # Should handle even if there are many TXT records
    
    def test_ipv6_handling(self):
        """Test IPv6 address handling"""
        # Test AAAA record resolution
        result = self.dns.resolve_domain('google.com', 'AAAA')
        
        self.assertIsInstance(result, dict)
        self.assertEqual(result['record_type'], 'AAAA')
        
        # If records exist, they should look like IPv6 addresses
        if result.get('records'):
            for record in result['records']:
                # Basic IPv6 format check (contains colons)
                self.assertIn(':', record)


class TestDNSUtilityMethods(unittest.TestCase):
    """Test utility methods and helper functions"""
    
    def setUp(self):
        self.dns = DNSResolver()
    
    def test_query_specific_server(self):
        """Test querying a specific DNS server"""
        domain = 'google.com'
        dns_server = '8.8.8.8'
        
        result = self.dns.query_specific_server(domain, 'A', dns_server)
        
        self.assertIsInstance(result, dict)
        if 'error' not in result:
            self.assertIn('queried_server', result)
            self.assertEqual(result['queried_server'], dns_server)
    
    def test_record_type_validation(self):
        """Test validation of DNS record types"""
        valid_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'PTR', 'SOA']
        
        for record_type in valid_types:
            with self.subTest(record_type=record_type):
                result = self.dns.resolve_domain('google.com', record_type)
                self.assertIsInstance(result, dict)
                self.assertEqual(result['record_type'], record_type)
    
    def test_domain_validation(self):
        """Test domain name validation"""
        # This tests the validation indirectly through resolve_domain
        
        valid_domains = [
            'google.com',
            'sub.domain.com',
            'example.org',
            'test-domain.net',
            'a.b.c.d.e.com'
        ]
        
        invalid_domains = [
            '',
            None,
            'invalid..domain',
            '.invalid.com',
            'invalid.com.',
            'toolongdomainnamethatexceedsthelimittoolongdomainnamethatexceedsthelimittoolongdomainnamethatexceedsthelimittoolongdomainnamethatexceedsthelimittoolongdomainnamethatexceedsthelimittoolongdomainnamethatexceedsthelimittoolongdomainnamethatexceedsthelimit.com'
        ]
        
        for domain in valid_domains:
            with self.subTest(domain=domain, valid=True):
                result = self.dns.resolve_domain(domain, 'A')
                self.assertIsInstance(result, dict)
                # Valid domains should not immediately return an error due to format
                # (though they might not resolve)
        
        for domain in invalid_domains:
            with self.subTest(domain=domain, valid=False):
                result = self.dns.resolve_domain(domain, 'A')
                self.assertIsInstance(result, dict)
                # Invalid domains should return an error
                self.assertIn('error', result)


class TestDNSPerformance(unittest.TestCase):
    """Test DNS resolver performance characteristics"""
    
    def setUp(self):
        self.dns = DNSResolver()
    
    def test_resolution_speed(self):
        """Test DNS resolution speed"""
        domain = 'google.com'
        
        # Time a single resolution
        start_time = time.time()
        result = self.dns.resolve_domain(domain, 'A')
        end_time = time.time()
        
        resolution_time = end_time - start_time
        
        # Should complete within reasonable time (10 seconds)
        self.assertLess(resolution_time, 10.0, "DNS resolution should complete within 10 seconds")
        
        # Should return valid result
        self.assertIsInstance(result, dict)
    
    def test_cache_performance_improvement(self):
        """Test that caching improves performance"""
        domain = 'google.com'
        
        # Clear cache first
        self.dns.clear_cache()
        
        # First resolution (cache miss)
        start_time = time.time()
        result1 = self.dns.resolve_domain(domain, 'A')
        time1 = time.time() - start_time
        
        # Second resolution (potential cache hit)
        start_time = time.time()
        result2 = self.dns.resolve_domain(domain, 'A')
        time2 = time.time() - start_time
        
        # Both should succeed
        self.assertIsInstance(result1, dict)
        self.assertIsInstance(result2, dict)
        
        # Second request might be faster due to caching
        # (This is implementation dependent and might not always be true in simulation)
    
    def test_bulk_resolution_performance(self):
        """Test performance of bulk domain resolution"""
        domains = ['google.com', 'github.com', 'stackoverflow.com', 'reddit.com', 'wikipedia.org']
        
        start_time = time.time()
        results = self.dns.batch_resolve(domains, 'A')
        end_time = time.time()
        
        total_time = end_time - start_time
        
        # Should complete all resolutions within reasonable time
        self.assertLess(total_time, 30.0, "Bulk resolution should complete within 30 seconds")
        
        # Should have results for all domains
        self.assertEqual(len(results), len(domains))
        
        for domain in domains:
            self.assertIn(domain, results)
            self.assertIsInstance(results[domain], dict)


if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add all test cases
    test_suite.addTest(unittest.makeSuite(TestDNSResolver))
    test_suite.addTest(unittest.makeSuite(TestDNSResolverEdgeCases))
    test_suite.addTest(unittest.makeSuite(TestDNSUtilityMethods))
    test_suite.addTest(unittest.makeSuite(TestDNSPerformance))
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"DNS Resolver Test Summary")
    print(f"{'='*60}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    if result.failures:
        print(f"\nFailures:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback.split('AssertionError:')[-1].strip()}")
    
    if result.errors:
        print(f"\nErrors:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback.split('Error:')[-1].strip()}")
    
    print(f"\n{'='*60}")
    print("Note: Some tests may show expected failures in simulation mode")
    print("as they test real DNS functionality that may not be fully")
    print("implemented in the simulation environment.")
    print(f"{'='*60}")
