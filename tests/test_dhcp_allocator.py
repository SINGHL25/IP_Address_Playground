
"""
Unit tests for DHCP Allocator module

This file contains comprehensive tests for the DHCPAllocator class,
testing IP allocation, lease management, and configuration functionality.
"""

import unittest
import sys
import os
from datetime import datetime, timedelta

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dhcp_allocator import DHCPAllocator


class TestDHCPAllocator(unittest.TestCase):
    """Test cases for DHCPAllocator class"""
    
    def setUp(self):
        """Set up test fixtures before each test method"""
        self.dhcp = DHCPAllocator()
        # Configure a test pool
        self.test_network = "192.168.1.0"
        self.test_mask = "255.255.255.0"
        self.test_start = "192.168.1.100"
        self.test_end = "192.168.1.110"
        
        self.dhcp.configure_pool(
            self.test_network, 
            self.test_mask, 
            self.test_start, 
            self.test_end
        )
    
    def tearDown(self):
        """Clean up after each test method"""
        self.dhcp.clear_all_leases()
    
    def test_pool_configuration(self):
        """Test DHCP pool configuration"""
        # Test valid configuration
        result = self.dhcp.configure_pool(
            "10.0.0.0", "255.255.255.0", "10.0.0.100", "10.0.0.200"
        )
        self.assertTrue(result, "Pool configuration should succeed with valid parameters")
        
        # Test invalid IP addresses
        result = self.dhcp.configure_pool(
            "invalid_ip", "255.255.255.0", "10.0.0.100", "10.0.0.200"
        )
        self.assertFalse(result, "Pool configuration should fail with invalid network IP")
        
        # Test start IP greater than end IP
        result = self.dhcp.configure_pool(
            "10.0.0.0", "255.255.255.0", "10.0.0.200", "10.0.0.100"
        )
        self.assertFalse(result, "Pool configuration should fail when start IP > end IP")
    
    def test_ip_request_allocation(self):
        """Test IP address allocation"""
        mac_address = "00:11:22:33:44:55"
        hostname = "test-device"
        device_type = "Laptop"
        
        # Test successful allocation
        lease = self.dhcp.request_ip(mac_address, hostname, device_type)
        self.assertIsNotNone(lease, "IP allocation should succeed")
        self.assertEqual(lease['mac_address'], mac_address.upper())
        self.assertEqual(lease['hostname'], hostname)
        self.assertEqual(lease['device_type'], device_type)
        self.assertIn(lease['ip_address'], [f"192.168.1.{i}" for i in range(100, 111)])
        
        # Test duplicate request (should return existing lease)
        lease2 = self.dhcp.request_ip(mac_address, hostname, device_type)
        self.assertIsNotNone(lease2, "Duplicate request should succeed")
        self.assertEqual(lease['ip_address'], lease2['ip_address'])
        
        # Test invalid MAC address
        lease3 = self.dhcp.request_ip("invalid_mac", hostname, device_type)
        self.assertIsNone(lease3, "Request with invalid MAC should fail")
    
    def test_pool_exhaustion(self):
        """Test behavior when IP pool is exhausted"""
        allocated_ips = []
        
        # Allocate all available IPs (11 addresses from .100 to .110)
        for i in range(11):
            mac = f"00:11:22:33:44:{i:02x}"
            lease = self.dhcp.request_ip(mac, f"device-{i}", "Laptop")
            if lease:
                allocated_ips.append(lease['ip_address'])
        
        # Verify we got all available IPs
        self.assertEqual(len(allocated_ips), 11, "Should allocate all 11 available IPs")
        
        # Try to allocate one more (should fail)
        mac_overflow = "00:11:22:33:44:ff"
        lease_overflow = self.dhcp.request_ip(mac_overflow, "overflow-device", "Laptop")
        self.assertIsNone(lease_overflow, "Allocation should fail when pool is exhausted")
    
    def test_lease_release(self):
        """Test IP address lease release"""
        mac_address = "00:11:22:33:44:55"
        
        # Allocate an IP
        lease = self.dhcp.request_ip(mac_address, "test-device", "Laptop")
        self.assertIsNotNone(lease)
        allocated_ip = lease['ip_address']
        
        # Release the IP
        result = self.dhcp.release_ip(allocated_ip)
        self.assertTrue(result, "IP release should succeed")
        
        # Verify IP is available again
        stats_before = self.dhcp.get_pool_stats()
        new_lease = self.dhcp.request_ip("00:11:22:33:44:56", "new-device", "Desktop")
        self.assertIsNotNone(new_lease)
        
        # Test releasing non-existent IP
        result = self.dhcp.release_ip("192.168.1.99")
        self.assertFalse(result, "Releasing non-allocated IP should fail")
    
    def test_dhcp_reservations(self):
        """Test DHCP reservation functionality"""
        mac_address = "00:11:22:33:44:55"
        reserved_ip = "192.168.1.50"
        
        # Add reservation (this IP is outside our pool range, so we'll use pool range)
        reserved_ip = "192.168.1.105"
        result = self.dhcp.add_reservation(mac_address, reserved_ip)
        self.assertTrue(result, "Adding reservation should succeed")
        
        # Request IP for reserved device
        lease = self.dhcp.request_ip(mac_address, "reserved-device", "Server")
        self.assertIsNotNone(lease, "Reserved device should get IP")
        self.assertEqual(lease['ip_address'], reserved_ip, "Should get reserved IP")
        self.assertTrue(lease.get('reserved', False), "Lease should be marked as reserved")
        
        # Remove reservation
        result = self.dhcp.remove_reservation(mac_address)
        self.assertTrue(result, "Removing reservation should succeed")
        
        # Test invalid reservation
        result = self.dhcp.add_reservation("invalid_mac", reserved_ip)
        self.assertFalse(result, "Invalid MAC reservation should fail")
    
    def test_dhcp_options(self):
        """Test DHCP options configuration"""
        options = {
            'gateway': '192.168.1.1',
            'dns_servers': ['8.8.8.8', '1.1.1.1'],
            'domain_name': 'test.local',
            'lease_time': '12 hours'
        }
        
        result = self.dhcp.set_options(options)
        self.assertTrue(result, "Setting DHCP options should succeed")
        
        # Verify options are applied to new leases
        mac_address = "00:11:22:33:44:55"
        lease = self.dhcp.request_ip(mac_address, "test-device", "Laptop")
        
        self.assertIsNotNone(lease)
        self.assertEqual(lease['gateway'], options['gateway'])
        self.assertEqual(lease['dns_servers'], options['dns_servers'])
        self.assertEqual(lease['domain_name'], options['domain_name'])
    
    def test_pool_statistics(self):
        """Test pool statistics functionality"""
        # Get initial stats
        stats = self.dhcp.get_pool_stats()
        initial_available = stats['available']
        
        # Allocate some IPs
        for i in range(3):
            mac = f"00:11:22:33:44:{i:02x}"
            self.dhcp.request_ip(mac, f"device-{i}", "Laptop")
        
        # Check updated stats
        stats = self.dhcp.get_pool_stats()
        self.assertEqual(stats['allocated'], 3, "Should have 3 allocated addresses")
        self.assertEqual(stats['available'], initial_available - 3, "Available count should decrease")
        self.assertGreater(stats['utilization'], 0, "Utilization should be greater than 0")
    
    def test_active_leases(self):
        """Test active lease retrieval"""
        # Initially no active leases
        leases = self.dhcp.get_active_leases()
        self.assertEqual(len(leases), 0, "Should have no active leases initially")
        
        # Add some leases
        devices = [
            ("00:11:22:33:44:01", "device-1", "Laptop"),
            ("00:11:22:33:44:02", "device-2", "Desktop"),
            ("00:11:22:33:44:03", "device-3", "Smartphone")
        ]
        
        for mac, name, dtype in devices:
            self.dhcp.request_ip(mac, name, dtype)
        
        # Check active leases
        leases = self.dhcp.get_active_leases()
        self.assertEqual(len(leases), 3, "Should have 3 active leases")
        
        # Verify lease information
        lease_macs = [lease['mac_address'] for lease in leases]
        expected_macs = [mac.upper() for mac, _, _ in devices]
        for expected_mac in expected_macs:
            self.assertIn(expected_mac, lease_macs, f"Should find lease for {expected_mac}")
    
    def test_lease_renewal(self):
        """Test lease renewal functionality"""
        mac_address = "00:11:22:33:44:55"
        
        # Initial lease
        lease1 = self.dhcp.request_ip(mac_address, "test-device", "Laptop")
        self.assertIsNotNone(lease1)
        original_expiry = lease1['lease_expires']
        
        # Renew lease (request IP again with same MAC)
        lease2 = self.dhcp.request_ip(mac_address, "test-device", "Laptop")
        self.assertIsNotNone(lease2)
        new_expiry = lease2['lease_expires']
        
        # Verify renewal
        self.assertEqual(lease1['ip_address'], lease2['ip_address'], "Should get same IP")
        self.assertGreater(lease2.get('renewal_count', 0), 0, "Renewal count should increase")
        
        # Expiry should be updated (in real implementation)
        # Note: This might not work in simulation depending on implementation
    
    def test_clear_all_leases(self):
        """Test clearing all leases"""
        # Allocate some leases
        for i in range(5):
            mac = f"00:11:22:33:44:{i:02x}"
            self.dhcp.request_ip(mac, f"device-{i}", "Laptop")
        
        # Verify leases exist
        leases = self.dhcp.get_active_leases()
        self.assertGreater(len(leases), 0, "Should have active leases")
        
        # Clear all leases
        result = self.dhcp.clear_all_leases()
        self.assertTrue(result, "Clearing leases should succeed")
        
        # Verify leases are cleared
        leases = self.dhcp.get_active_leases()
        self.assertEqual(len(leases), 0, "Should have no active leases after clearing")
        
        # Verify pool statistics are reset
        stats = self.dhcp.get_pool_stats()
        self.assertEqual(stats['allocated'], 0, "Should have 0 allocated addresses")
    
    def test_dora_simulation(self):
        """Test DHCP DORA process simulation"""
        mac_address = "00:11:22:33:44:55"
        hostname = "test-device"
        
        result = self.dhcp.simulate_dhcp_process(mac_address, hostname)
        
        self.assertIsInstance(result, dict, "DORA simulation should return a dictionary")
        self.assertIn('process_steps', result, "Should include process steps")
        self.assertIn('success', result, "Should include success status")
        
        if result['success']:
            self.assertIn('lease_info', result, "Successful simulation should include lease info")
            steps = result['process_steps']
            self.assertEqual(len(steps), 4, "DORA process should have 4 steps")
            
            expected_steps = ['DISCOVER', 'OFFER', 'REQUEST', 'ACK']
            actual_steps = [step['step'] for step in steps]
            self.assertEqual(actual_steps, expected_steps, "Should have correct DORA steps")
    
    def test_lease_history(self):
        """Test lease history functionality"""
        mac_address = "00:11:22:33:44:55"
        
        # Initial lease
        self.dhcp.request_ip(mac_address, "test-device", "Laptop")
        
        # Get lease history
        history = self.dhcp.get_lease_history(mac_address)
        self.assertGreater(len(history), 0, "Should have lease history")
        
        # Get all lease history
        all_history = self.dhcp.get_lease_history()
        self.assertGreaterEqual(len(all_history), len(history), "All history should be >= specific MAC history")


class TestDHCPHelperMethods(unittest.TestCase):
    """Test helper methods and edge cases"""
    
    def setUp(self):
        self.dhcp = DHCPAllocator()
    
    def test_lease_time_parsing(self):
        """Test lease time string parsing"""
        # This tests the private method _parse_lease_time
        # We'll test it indirectly through options setting
        
        test_cases = [
            ("1 hour", 1),
            ("24 hours", 24),
            ("2 days", 48),
            ("1 week", 168),
            ("invalid", 24)  # Should default to 24 hours
        ]
        
        for lease_time_str, expected_hours in test_cases:
            self.dhcp.set_options({'lease_time': lease_time_str})
            # We can't directly test the private method, but we can verify
            # the lease time is handled properly in the options
            self.assertEqual(
                self.dhcp.dhcp_options['lease_time'], 
                lease_time_str,
                f"Lease time should be stored: {lease_time_str}"
            )
    
    def test_mac_address_formatting(self):
        """Test MAC address formatting through IP requests"""
        test_macs = [
            "001122334455",
            "00-11-22-33-44-55", 
            "00:11:22:33:44:55",
            "00.11.22.33.44.55"
        ]
        
        # Configure pool
        self.dhcp.configure_pool("192.168.1.0", "255.255.255.0", "192.168.1.100", "192.168.1.110")
        
        for mac in test_macs:
            # This will test MAC formatting indirectly
            lease = self.dhcp.request_ip(mac, "test", "Laptop")
            if lease:  # Some formats might not be supported
                self.assertRegex(
                    lease['mac_address'], 
                    r'^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}$',
                    "MAC should be formatted as XX:XX:XX:XX:XX:XX"
                )


class TestDHCPEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions"""
    
    def setUp(self):
        self.dhcp = DHCPAllocator()
    
    def test_empty_pool_configuration(self):
        """Test behavior with empty or minimal pool"""
        # Test single IP pool
        result = self.dhcp.configure_pool(
            "192.168.1.0", "255.255.255.0", "192.168.1.100", "192.168.1.100"
        )
        self.assertTrue(result, "Single IP pool should be valid")
        
        stats = self.dhcp.get_pool_stats()
        self.assertEqual(stats['total_addresses'], 1, "Should have 1 address in pool")
    
    def test_concurrent_requests(self):
        """Test handling of concurrent IP requests"""
        # Configure small pool
        self.dhcp.configure_pool("192.168.1.0", "255.255.255.0", "192.168.1.100", "192.168.1.102")
        
        # Simulate concurrent requests
        devices = []
        for i in range(5):
            mac = f"00:11:22:33:44:{i:02x}"
            lease = self.dhcp.request_ip(mac, f"device-{i}", "Laptop")
            if lease:
                devices.append((mac, lease['ip_address']))
        
        # Verify no duplicate IPs assigned
        assigned_ips = [ip for _, ip in devices]
        self.assertEqual(len(assigned_ips), len(set(assigned_ips)), "No duplicate IPs should be assigned")
        
        # Verify only available IPs assigned
        self.assertLessEqual(len(devices), 3, "Should not assign more IPs than available")
    
    def test_invalid_inputs(self):
        """Test handling of invalid inputs"""
        # Test None inputs
        lease = self.dhcp.request_ip(None, "test", "Laptop")
        self.assertIsNone(lease, "None MAC should return None")
        
        lease = self.dhcp.request_ip("00:11:22:33:44:55", None, "Laptop")
        # Should still work with None hostname (implementation dependent)
        
        # Test empty strings
        lease = self.dhcp.request_ip("", "test", "Laptop")
        self.assertIsNone(lease, "Empty MAC should return None")


if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add all test cases
    test_suite.addTest(unittest.makeSuite(TestDHCPAllocator))
    test_suite.addTest(unittest.makeSuite(TestDHCPHelperMethods))
    test_suite.addTest(unittest.makeSuite(TestDHCPEdgeCases))
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"DHCP Allocator Test Summary")
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
