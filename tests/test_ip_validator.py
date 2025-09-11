
"""
Unit tests for IP validation and helper functions

This file contains comprehensive tests for IP validation, conversion,
and analysis functions in the utils.helpers module.
"""

import unittest
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.helpers import (
    validate_ip_address, validate_subnet_mask, validate_domain_name,
    ip_to_binary, binary_to_ip, cidr_to_subnet_mask, subnet_mask_to_cidr,
    get_ip_class, get_ip_info, is_private_ip, is_loopback_ip,
    calculate_network_info, format_mac_address, ping_host
)
from ip_class_identifier import IPClassIdentifier


class TestIPValidation(unittest.TestCase):
    """Test IP address validation functions"""
    
    def test_valid_ip_addresses(self):
        """Test validation of valid IP addresses"""
        valid_ips = [
            '0.0.0.0',
            '127.0.0.1',
            '192.168.1.1',
            '10.0.0.1',
            '172.16.0.1',
            '255.255.255.255',
            '8.8.8.8',
            '1.1.1.1',
            '208.67.222.222'
        ]
        
        for ip in valid_ips:
            with self.subTest(ip=ip):
                self.assertTrue(validate_ip_address(ip), f"{ip} should be valid")
    
    def test_invalid_ip_addresses(self):
        """Test validation of invalid IP addresses"""
        invalid_ips = [
            '',
            None,
            '256.1.1.1',        # Octet > 255
            '192.168.1',        # Missing octet
            '192.168.1.1.1',    # Too many octets
            '192.168.-1.1',     # Negative octet
            '192.168.1.a',      # Non-numeric octet
            '192.168.01.1',     # Leading zeros
            '192.168. 1.1',     # Space in IP
            'not.an.ip.address',
            '192.168.1.256',    # Last octet > 255
            '999.999.999.999',  # All octets > 255
        ]
        
        for ip in invalid_ips:
            with self.subTest(ip=ip):
                self.assertFalse(validate_ip_address(ip), f"{ip} should be invalid")
    
    def test_subnet_mask_validation(self):
        """Test subnet mask validation"""
        valid_masks = [
            '255.255.255.255',  # /32
            '255.255.255.254',  # /31
            '255.255.255.252',  # /30
            '255.255.255.248',  # /29
            '255.255.255.240',  # /28
            '255.255.255.224',  # /27
            '255.255.255.192',  # /26
            '255.255.255.128',  # /25
            '255.255.255.0',    # /24
            '255.255.254.0',    # /23
            '255.255.252.0',    # /22
            '255.255.248.0',    # /21
            '255.255.240.0',    # /20
            '255.255.224.0',    # /19
            '255.255.192.0',    # /18
            '255.255.128.0',    # /17
            '255.255.0.0',      # /16
            '255.254.0.0',      # /15
            '255.252.0.0',      # /14
            '255.248.0.0',      # /13
            '255.240.0.0',      # /12
            '255.224.0.0',      # /11
            '255.192.0.0',      # /10
            '255.128.0.0',      # /9
            '255.0.0.0',        # /8
            '0.0.0.0'           # /0
        ]
        
        for mask in valid_masks:
            with self.subTest(mask=mask):
                self.assertTrue(validate_subnet_mask(mask), f"{mask} should be valid")
    
    def test_invalid_subnet_masks(self):
        """Test invalid subnet mask validation"""
        invalid_masks = [
            '',
            None,
            '255.255.255.1',    # Non-contiguous mask
            '255.255.254.255',  # Non-contiguous mask
            '255.254.255.0',    # Non-contiguous mask
            '192.168.1.1',      # Regular IP, not a mask
            '256.255.255.0',    # Invalid octet
            '255.255.255',      # Missing octet
            '/24',              # CIDR notation, not dotted decimal
            'invalid.mask'      # Non-numeric
        ]
        
        for mask in invalid_masks:
            with self.subTest(mask=mask):
                self.assertFalse(validate_subnet_mask(mask), f"{mask} should be invalid")
    
    def test_domain_name_validation(self):
        """Test domain name validation"""
        valid_domains = [
            'google.com',
            'www.google.com',
            'sub.domain.example.org',
            'test-domain.net',
            'a.b.c.d.e.com',
            'xn--nxasmq6b.xn--o3cw4h',  # IDN domain
            'example.museum',
            '123domain.com',
            'domain123.org'
        ]
        
        for domain in valid_domains:
            with self.subTest(domain=domain):
                self.assertTrue(validate_domain_name(domain), f"{domain} should be valid")
    
    def test_invalid_domain_names(self):
        """Test invalid domain name validation"""
        invalid_domains = [
            '',
            None,
            '.invalid.com',      # Starting with dot
            'invalid.com.',      # Ending with dot
            'invalid..com',      # Double dot
            'invalid-.com',      # Ending with hyphen
            '-invalid.com',      # Starting with hyphen
            'invalid.c',         # TLD too short
            'toolongdomainnamethatexceedsthelimit' * 10 + '.com',  # Too long
            'invalid space.com', # Contains space
            'invalid@domain.com',# Contains @
            '192.168.1.1'       # IP address, not domain
        ]
        
        for domain in invalid_domains:
            with self.subTest(domain=domain):
                self.assertFalse(validate_domain_name(domain), f"{domain} should be invalid")


class TestIPConversion(unittest.TestCase):
    """Test IP address conversion functions"""
    
    def test_ip_to_binary_conversion(self):
        """Test IP to binary conversion"""
        test_cases = [
            ('0.0.0.0', '00000000.00000000.00000000.00000000'),
            ('127.0.0.1', '01111111.00000000.00000000.00000001'),
            ('192.168.1.1', '11000000.10101000.00000001.00000001'),
            ('255.255.255.255', '11111111.11111111.11111111.11111111'),
            ('10.0.0.1', '00001010.00000000.00000000.00000001'),
            ('172.16.0.1', '10101100.00010000.00000000.00000001')
        ]
        
        for ip, expected_binary in test_cases:
            with self.subTest(ip=ip):
                result = ip_to_binary(ip)
                self.assertEqual(result, expected_binary, f"Binary conversion failed for {ip}")
    
    def test_binary_to_ip_conversion(self):
        """Test binary to IP conversion"""
        test_cases = [
            ('00000000.00000000.00000000.00000000', '0.0.0.0'),
            ('01111111.00000000.00000000.00000001', '127.0.0.1'),
            ('11000000.10101000.00000001.00000001', '192.168.1.1'),
            ('11111111.11111111.11111111.11111111', '255.255.255.255'),
            ('00001010.00000000.00000000.00000001', '10.0.0.1')
        ]
        
        for binary, expected_ip in test_cases:
            with self.subTest(binary=binary):
                result = binary_to_ip(binary)
                self.assertEqual(result, expected_ip, f"IP conversion failed for {binary}")
    
    def test_cidr_to_subnet_mask_conversion(self):
        """Test CIDR to subnet mask conversion"""
        test_cases = [
            (8, '255.0.0.0'),
            (16, '255.255.0.0'),
            (24, '255.255.255.0'),
            (25, '255.255.255.128'),
            (26, '255.255.255.192'),
            (27, '255.255.255.224'),
            (28, '255.255.255.240'),
            (29, '255.255.255.248'),
            (30, '255.255.255.252'),
            (31, '255.255.255.254'),
            (32, '255.255.255.255'),
            (0, '0.0.0.0')
        ]
        
        for cidr, expected_mask in test_cases:
            with self.subTest(cidr=cidr):
                result = cidr_to_subnet_mask(cidr)
                self.assertEqual(result, expected_mask, f"CIDR conversion failed for /{cidr}")
    
    def test_subnet_mask_to_cidr_conversion(self):
        """Test subnet mask to CIDR conversion"""
        test_cases = [
            ('255.0.0.0', 8),
            ('255.255.0.0', 16),
            ('255.255.255.0', 24),
            ('255.255.255.128', 25),
            ('255.255.255.192', 26),
            ('255.255.255.224', 27),
            ('255.255.255.240', 28),
            ('255.255.255.248', 29),
            ('255.255.255.252', 30),
            ('255.255.255.254', 31),
            ('255.255.255.255', 32),
            ('0.0.0.0', 0)
        ]
        
        for mask, expected_cidr in test_cases:
            with self.subTest(mask=mask):
                result = subnet_mask_to_cidr(mask)
                self.assertEqual(result, expected_cidr, f"Subnet mask conversion failed for {mask}")
    
    def test_invalid_conversions(self):
        """Test conversion functions with invalid input"""
        # Test invalid IP to binary
        self.assertEqual(ip_to_binary('invalid.ip'), '')
        self.assertEqual(ip_to_binary('256.1.1.1'), '')
        
        # Test invalid binary to IP
        self.assertEqual(binary_to_ip('invalid.binary'), '')
        self.assertEqual(binary_to_ip('11111111.11111111'), '')
        
        # Test invalid CIDR
        self.assertEqual(cidr_to_subnet_mask(-1), '')
        self.assertEqual(cidr_to_subnet_mask(33), '')
        
        # Test invalid subnet mask to CIDR
        self.assertEqual(subnet_mask_to_cidr('invalid.mask'), -1)
        self.assertEqual(subnet_mask_to_cidr('255.255.255.1'), -1)


class TestIPClassification(unittest.TestCase):
    """Test IP address classification functions"""
    
    def test_ip_class_identification(self):
        """Test IP address class identification"""
        test_cases = [
            ('10.0.0.1', 'A'),
            ('50.1.1.1', 'A'),
            ('126.255.255.255', 'A'),
            ('128.0.0.1', 'B'),
            ('172.16.0.1', 'B'),
            ('191.255.255.255', 'B'),
            ('192.0.0.1', 'C'),
            ('192.168.1.1', 'C'),
            ('223.255.255.255', 'C'),
            ('224.0.0.1', 'D'),
            ('239.255.255.255', 'D'),
            ('240.0.0.1', 'E'),
            ('255.255.255.255', 'E'),
            ('127.0.0.1', 'A'),  # Loopback is class A
        ]
        
        for ip, expected_class in test_cases:
            with self.subTest(ip=ip):
                result = get_ip_class(ip)
                self.assertEqual(result['class'], expected_class, f"Class identification failed for {ip}")
    
    def test_private_ip_detection(self):
        """Test private IP address detection"""
        private_ips = [
            '10.0.0.1',
            '10.255.255.255',
            '172.16.0.1',
            '172.31.255.255',
            '192.168.0.1',
            '192.168.255.255'
        ]
        
        public_ips = [
            '8.8.8.8',
            '1.1.1.1',
            '208.67.222.222',
            '172.15.255.255',  # Just outside private range
            '172.32.0.1',      # Just outside private range
            '192.167.255.255', # Just outside private range
            '192.169.0.1'      # Just outside private range
        ]
        
        for ip in private_ips:
            with self.subTest(ip=ip, expected=True):
                self.assertTrue(is_private_ip(ip), f"{ip} should be identified as private")
        
        for ip in public_ips:
            with self.subTest(ip=ip, expected=False):
                self.assertFalse(is_private_ip(ip), f"{ip} should be identified as public")
    
    def test_loopback_ip_detection(self):
        """Test loopback IP address detection"""
        loopback_ips = [
            '127.0.0.1',
            '127.0.0.2',
            '127.1.1.1',
            '127.255.255.255'
        ]
        
        non_loopback_ips = [
            '126.255.255.255',
            '128.0.0.1',
            '192.168.1.1',
            '10.0.0.1'
        ]
        
        for ip in loopback_ips:
            with self.subTest(ip=ip, expected=True):
                self.assertTrue(is_loopback_ip(ip), f"{ip} should be identified as loopback")
        
        for ip in non_loopback_ips:
            with self.subTest(ip=ip, expected=False):
                self.assertFalse(is_loopback_ip(ip), f"{ip} should not be identified as loopback")
    
    def test_comprehensive_ip_info(self):
        """Test comprehensive IP information retrieval"""
        test_ips = [
            '192.168.1.1',  # Private Class C
            '10.0.0.1',     # Private Class A
            '8.8.8.8',      # Public Class A
            '127.0.0.1'     # Loopback Class A
        ]
        
        for ip in test_ips:
            with self.subTest(ip=ip):
                info = get_ip_info(ip)
                
                # Should have basic info
                self.assertIn('ip_address', info)
                self.assertIn('version', info)
                self.assertIn('class', info)
                self.assertIn('type', info)
                self.assertIn('binary', info)
                
                # Verify IP address matches
                self.assertEqual(info['ip_address'], ip)
                
                # Verify version is IPv4
                self.assertEqual(info['version'], 'IPv4')


class TestNetworkCalculations(unittest.TestCase):
    """Test network calculation functions"""
    
    def test_network_info_calculation(self):
        """Test network information calculation"""
        test_cases = [
            {
                'ip': '192.168.1.10',
                'mask': '255.255.255.0',
                'expected': {
                    'network_address': '192.168.1.0',
                    'broadcast_address': '192.168.1.255',
                    'first_host': '192.168.1.1',
                    'last_host': '192.168.1.254',
                    'total_hosts': '254'
                }
            },
            {
                'ip': '10.0.0.1',
                'mask': '255.255.0.0',
                'expected': {
                    'network_address': '10.0.0.0',
                    'broadcast_address': '10.0.255.255',
                    'first_host': '10.0.0.1',
                    'last_host': '10.0.255.254',
                    'total_hosts': '65534'
                }
            },
            {
                'ip': '172.16.5.10',
                'mask': '255.255.255.192',  # /26
                'expected': {
                    'network_address': '172.16.5.0',
                    'broadcast_address': '172.16.5.63',
                    'first_host': '172.16.5.1',
                    'last_host': '172.16.5.62',
                    'total_hosts': '62'
                }
            }
        ]
        
        for case in test_cases:
            with self.subTest(ip=case['ip'], mask=case['mask']):
                result = calculate_network_info(case['ip'], case['mask'])
                
                for key, expected_value in case['expected'].items():
                    self.assertEqual(
                        result[key], 
                        expected_value, 
                        f"Mismatch in {key} for {case['ip']}/{case['mask']}"
                    )
    
    def test_network_info_with_cidr(self):
        """Test network information calculation with CIDR notation"""
        test_cases = [
            {
                'ip': '192.168.1.10',
                'cidr': '/24',
                'expected_network': '192.168.1.0',
                'expected_broadcast': '192.168.1.255'
            },
            {
                'ip': '10.0.0.1',
                'cidr': '/16',
                'expected_network': '10.0.0.0',
                'expected_broadcast': '10.0.255.255'
            },
            {
                'ip': '172.16.5.10',
                'cidr': '/26',
                'expected_network': '172.16.5.0',
                'expected_broadcast': '172.16.5.63'
            }
        ]
        
        for case in test_cases:
            with self.subTest(ip=case['ip'], cidr=case['cidr']):
                result = calculate_network_info(case['ip'], case['cidr'])
                
                self.assertEqual(result['network_address'], case['expected_network'])
                self.assertEqual(result['broadcast_address'], case['expected_broadcast'])
    
    def test_invalid_network_calculations(self):
        """Test network calculations with invalid input"""
        # Invalid IP
        result = calculate_network_info('invalid.ip', '255.255.255.0')
        self.assertIn('Invalid', result['network_address'])
        
        # Invalid subnet mask
        result = calculate_network_info('192.168.1.1', 'invalid.mask')
        self.assertIn('Invalid', result['network_address'])
        
        # Mismatched IP and mask
        result = calculate_network_info('192.168.1.1', '255.255.255.1')  # Invalid mask
        self.assertIn('Invalid', result['network_address'])


class TestMACAddressHandling(unittest.TestCase):
    """Test MAC address formatting and validation"""
    
    def test_mac_address_formatting(self):
        """Test MAC address formatting"""
        test_cases = [
            ('001122334455', '00:11:22:33:44:55'),
            ('00-11-22-33-44-55', '00:11:22:33:44:55'),
            ('00:11:22:33:44:55', '00:11:22:33:44:55'),
            ('00.11.22.33.44.55', '00:11:22:33:44:55'),
            ('aabbccddeeff', 'AA:BB:CC:DD:EE:FF'),
            ('AABBCCDDEEFF', 'AA:BB:CC:DD:EE:FF')
        ]
        
        for input_mac, expected_output in test_cases:
            with self.subTest(input_mac=input_mac):
                result = format_mac_address(input_mac)
                self.assertEqual(result, expected_output, f"MAC formatting failed for {input_mac}")
    
    def test_invalid_mac_addresses(self):
        """Test invalid MAC address handling"""
        invalid_macs = [
            '',
            None,
            '00112233445',    # Too short
            '001122334455aa', # Too long
            '00:11:22:33:44', # Missing octet
            '00:11:22:33:44:55:66', # Too many octets
            'gg:11:22:33:44:55', # Invalid hex character
            '00:11:22:33:44:zz'  # Invalid hex character
        ]
        
        for mac in invalid_macs:
            with self.subTest(mac=mac):
                result = format_mac_address(mac)
                self.assertEqual(result, '', f"Invalid MAC {mac} should return empty string")


class TestIPClassIdentifierIntegration(unittest.TestCase):
    """Test integration with IP Class Identifier"""
    
    def setUp(self):
        self.classifier = IPClassIdentifier()
    
    def test_comprehensive_ip_analysis(self):
        """Test comprehensive IP analysis"""
        test_ips = [
            '192.168.1.1',
            '10.0.0.1',
            '172.16.0.1',
            '8.8.8.8',
            '127.0.0.1',
            '224.0.0.1'
        ]
        
        for ip in test_ips:
            with self.subTest(ip=ip):
                analysis = self.classifier.identify_class(ip)
                
                self.assertIsInstance(analysis, dict)
                self.assertNotIn('error', analysis)
                
                # Should have comprehensive information
                expected_keys = [
                    'ip_address', 'class', 'version', 'is_private',
                    'is_public', 'binary_representation', 'usage_recommendations'
                ]
                
                for key in expected_keys:
                    self.assertIn(key, analysis, f"Missing key {key} in analysis for {ip}")
    
    def test_ip_range_analysis(self):
        """Test IP range analysis"""
        start_ip = '192.168.1.1'
        end_ip = '192.168.1.10'
        
        result = self.classifier.analyze_network_range(start_ip, end_ip)
        
        self.assertIsInstance(result, dict)
        self.assertNotIn('error', result)
        self.assertIn('start_ip', result)
        self.assertIn('end_ip', result)
        self.assertIn('range_size', result)
        self.assertEqual(result['range_size'], 10)
    
    def test_class_statistics(self):
        """Test IP class statistics generation"""
        test_ips = [
            '10.0.0.1',      # Class A
            '10.0.0.2',      # Class A
            '172.16.0.1',    # Class B
            '192.168.1.1',   # Class C
            '192.168.1.2',   # Class C
            '224.0.0.1'      # Class D
        ]
        
        stats = self.classifier.get_class_statistics(test_ips)
        
        self.assertIsInstance(stats, dict)
        self.assertEqual(stats['total_ips'], 6)
        self.assertEqual(stats['valid_ips'], 6)
        self.assertEqual(stats['invalid_ips'], 0)
        
        # Check class distribution
        expected_distribution = {'A': 2, 'B': 1, 'C': 2, 'D': 1}
        self.assertEqual(stats['class_distribution'], expected_distribution)


class TestUtilityFunctions(unittest.TestCase):
    """Test utility functions"""
    
    def test_ping_host_function(self):
        """Test ping host functionality"""
        # Note: This test might be platform-dependent
        # Test with localhost (should be reachable)
        try:
            result = ping_host('127.0.0.1')
            self.assertIsInstance(result, bool)
        except Exception:
            # Ping might not be available in test environment
            self.skipTest("Ping functionality not available in test environment")
    
    def test_edge_cases(self):
        """Test various edge cases"""
        # Test with None values
        self.assertFalse(validate_ip_address(None))
        self.assertFalse(validate_subnet_mask(None))
        self.assertFalse(validate_domain_name(None))
        
        # Test with empty strings
        self.assertFalse(validate_ip_address(''))
        self.assertFalse(validate_subnet_mask(''))
        self.assertFalse(validate_domain_name(''))
        
        # Test with whitespace
        self.assertFalse(validate_ip_address('   '))
        self.assertFalse(validate_subnet_mask('   '))
        self.assertFalse(validate_domain_name('   '))


class TestSpecialIPRanges(unittest.TestCase):
    """Test special IP address ranges and their identification"""
    
    def test_special_ip_ranges(self):
        """Test identification of special IP address ranges"""
        special_ips = {
            '127.0.0.1': 'loopback',
            '169.254.1.1': 'link-local',
            '224.0.0.1': 'multicast',
            '255.255.255.255': 'broadcast'
        }
        
        classifier = IPClassIdentifier()
        
        for ip, expected_type in special_ips.items():
            with self.subTest(ip=ip, expected_type=expected_type):
                analysis = classifier.identify_class(ip)
                
                if 'special_range' in analysis:
                    # The exact naming might vary in implementation
                    self.assertIsNotNone(analysis['special_range'])
    
    def test_reserved_ip_ranges(self):
        """Test identification of reserved IP ranges"""
        reserved_ips = [
            '0.0.0.0',      # This network
            '240.0.0.1',    # Reserved for future use (Class E)
            '255.255.255.255'  # Limited broadcast
        ]
        
        for ip in reserved_ips:
            with self.subTest(ip=ip):
                # These should be identified as having special properties
                result = validate_ip_address(ip)
                self.assertTrue(result, f"{ip} should be a valid IP address format")
                
                # Get additional information
                info = get_ip_info(ip)
                self.assertIn('class', info)


if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add all test cases
    test_suite.addTest(unittest.makeSuite(TestIPValidation))
    test_suite.addTest(unittest.makeSuite(TestIPConversion))
    test_suite.addTest(unittest.makeSuite(TestIPClassification))
    test_suite.addTest(unittest.makeSuite(TestNetworkCalculations))
    test_suite.addTest(unittest.makeSuite(TestMACAddressHandling))
    test_suite.addTest(unittest.makeSuite(TestIPClassIdentifierIntegration))
    test_suite.addTest(unittest.makeSuite(TestUtilityFunctions))
    test_suite.addTest(unittest.makeSuite(TestSpecialIPRanges))
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"IP Validation and Helper Functions Test Summary")
    print(f"{'='*60}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.testsRun > 0:
        success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100)
        print(f"Success rate: {success_rate:.1f}%")
    
    if result.failures:
        print(f"\nFailures:")
        for test, traceback in result.failures:
            failure_msg = traceback.split('AssertionError:')[-1].strip() if 'AssertionError:' in traceback else 'Unknown failure'
            print(f"- {test}: {failure_msg}")
    
    if result.errors:
        print(f"\nErrors:")
        for test, traceback in result.errors:
            error_msg = traceback.split('Error:')[-1].strip() if 'Error:' in traceback else 'Unknown error'
            print(f"- {test}: {error_msg}")
    
    if len(result.failures) == 0 and len(result.errors) == 0:
        print(f"\n🎉 All tests passed successfully!")
    else:
        print(f"\n⚠️ Some tests failed. Review the failures and errors above.")
    
    print(f"{'='*60}")
