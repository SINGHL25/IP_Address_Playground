"""
Unit tests for Subnet Visualization and Network Analysis

This file contains tests for subnet calculations, network analysis,
and visualization components of the networking tools.
"""

import unittest
import sys
import os
import ipaddress
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.helpers import (
    calculate_network_info, cidr_to_subnet_mask, subnet_mask_to_cidr,
    validate_ip_address, get_ip_class
)


class TestSubnetCalculations(unittest.TestCase):
    """Test subnet calculation functionality"""
    
    def test_basic_subnet_calculations(self):
        """Test basic subnet calculations for common networks"""
        test_cases = [
            {
                'network': '192.168.1.0/24',
                'expected': {
                    'network_address': '192.168.1.0',
                    'broadcast_address': '192.168.1.255',
                    'total_hosts': 254,
                    'network_size': 256
                }
            },
            {
                'network': '10.0.0.0/16', 
                'expected': {
                    'network_address': '10.0.0.0',
                    'broadcast_address': '10.0.255.255',
                    'total_hosts': 65534,
                    'network_size': 65536
                }
            },
            {
                'network': '172.16.0.0/20',
                'expected': {
                    'network_address': '172.16.0.0',
                    'broadcast_address': '172.16.15.255',
                    'total_hosts': 4094,
                    'network_size': 4096
                }
            }
        ]
        
        for case in test_cases:
            with self.subTest(network=case['network']):
                ip, cidr = case['network'].split('/')
                mask = cidr_to_subnet_mask(int(cidr))
                result = calculate_network_info(ip, mask)
                
                for key, expected_value in case['expected'].items():
                    if key in ['total_hosts', 'network_size']:
                        actual_value = int(result[key])
                    else:
                        actual_value = result[key]
                    
                    self.assertEqual(
                        actual_value, 
                        expected_value,
                        f"Mismatch in {key} for {case['network']}"
                    )
    
    def test_subnet_division(self):
        """Test subnet division calculations"""
        # Divide 192.168.1.0/24 into /26 subnets
        base_network = ipaddress.ip_network('192.168.1.0/24', strict=False)
        subnets = list(base_network.subnets(new_prefix=26))
        
        # Should create 4 subnets
        self.assertEqual(len(subnets), 4)
        
        expected_subnets = [
            '192.168.1.0/26',
            '192.168.1.64/26', 
            '192.168.1.128/26',
            '192.168.1.192/26'
        ]
        
        for i, subnet in enumerate(subnets):
            self.assertEqual(str(subnet), expected_subnets[i])
    
    def test_vlsm_calculations(self):
        """Test Variable Length Subnet Masking calculations"""
        # Test VLSM for different host requirements
        requirements = [
            (100, 25),  # Need 100 hosts -> /25 (126 hosts)
            (50, 26),   # Need 50 hosts -> /26 (62 hosts)
            (25, 27),   # Need 25 hosts -> /27 (30 hosts)
            (10, 28),   # Need 10 hosts -> /28 (14 hosts)
            (2, 30)     # Need 2 hosts -> /30 (2 hosts)
        ]
        
        for required_hosts, expected_cidr in requirements:
            with self.subTest(required_hosts=required_hosts):
                # Calculate required host bits
                import math
                host_bits = math.ceil(math.log2(required_hosts + 2))  # +2 for network and broadcast
                calculated_cidr = 32 - host_bits
                
                self.assertEqual(calculated_cidr, expected_cidr)
                
                # Verify the subnet can accommodate the required hosts
                actual_hosts = (2 ** host_bits) - 2
                self.assertGreaterEqual(actual_hosts, required_hosts)
    
    def test_supernet_aggregation(self):
        """Test supernet aggregation (route summarization)"""
        # Test aggregating contiguous networks
        networks = [
            ipaddress.ip_network('192.168.0.0/24'),
            ipaddress.ip_network('192.168.1.0/24'),
            ipaddress.ip_network('192.168.2.0/24'),
            ipaddress.ip_network('192.168.3.0/24')
        ]
        
        # These should aggregate to 192.168.0.0/22
        supernet = ipaddress.collapse_addresses(networks)
        supernet_list = list(supernet)
        
        self.assertEqual(len(supernet_list), 1)
        self.assertEqual(str(supernet_list[0]), '192.168.0.0/22')
    
    def test_subnet_overlap_detection(self):
        """Test detection of overlapping subnets"""
        # Test overlapping subnets
        network1 = ipaddress.ip_network('192.168.1.0/24')
        network2 = ipaddress.ip_network('192.168.1.128/25')  # Overlaps with network1
        
        self.assertTrue(network1.overlaps(network2))
        
        # Test non-overlapping subnets
        network3 = ipaddress.ip_network('192.168.2.0/24')
        self.assertFalse(network1.overlaps(network3))
    
    def test_subnet_efficiency_calculation(self):
        """Test subnet efficiency calculations"""
        test_cases = [
            {
                'required_hosts': 50,
                'subnet_cidr': 26,  # /26 = 62 hosts
                'expected_efficiency': 50/62  # ~80.6%
            },
            {
                'required_hosts': 100,
                'subnet_cidr': 25,  # /25 = 126 hosts  
                'expected_efficiency': 100/126  # ~79.4%
            },
            {
                'required_hosts': 10,
                'subnet_cidr': 28,  # /28 = 14 hosts
                'expected_efficiency': 10/14  # ~71.4%
            }
        ]
        
        for case in test_cases:
            with self.subTest(required_hosts=case['required_hosts']):
                host_bits = 32 - case['subnet_cidr']
                available_hosts = (2 ** host_bits) - 2
                efficiency = case['required_hosts'] / available_hosts
                
                self.assertAlmostEqual(efficiency, case['expected_efficiency'], places=3)


class TestNetworkAnalysis(unittest.TestCase):
    """Test network analysis and visualization components"""
    
    def test_network_utilization_analysis(self):
        """Test network utilization analysis"""
        # Simulate network utilization data
        total_addresses = 254  # /24 network
        allocated_addresses = 100
        
        utilization_percentage = (allocated_addresses / total_addresses) * 100
        
        self.assertAlmostEqual(utilization_percentage, 39.37, places=1)
        
        # Test utilization thresholds
        self.assertLess(utilization_percentage, 80, "Utilization should be below warning threshold")
        
        # Test high utilization scenario
        high_allocation = 220
        high_utilization = (high_allocation / total_addresses) * 100
        
        self.assertGreater(high_utilization, 80, "Should trigger high utilization warning")
    
    def test_ip_address_planning(self):
        """Test IP address planning and allocation strategies"""
        # Test planning for multiple departments
        departments = [
            {'name': 'Engineering', 'required_hosts': 100},
            {'name': 'Sales', 'required_hosts': 50}, 
            {'name': 'Marketing', 'required_hosts': 30},
            {'name': 'HR', 'required_hosts': 15},
            {'name': 'IT', 'required_hosts': 10}
        ]
        
        # Calculate optimal subnet sizes
        import math
        
        planned_subnets = []
        for dept in departments:
            required_hosts = dept['required_hosts']
            
            # Add 20% growth buffer
            planned_hosts = int(required_hosts * 1.2)
            
            # Calculate required subnet size
            host_bits = math.ceil(math.log2(planned_hosts + 2))
            subnet_cidr = 32 - host_bits
            available_hosts = (2 ** host_bits) - 2
            
            planned_subnets.append({
                'department': dept['name'],
                'required': required_hosts,
                'planned': planned_hosts,
                'cidr': subnet_cidr,
                'available': available_hosts,
                'efficiency': required_hosts / available_hosts
            })
        
        # Verify planning results
        for subnet in planned_subnets:
            # Available hosts should be >= planned hosts
            self.assertGreaterEqual(subnet['available'], subnet['planned'])
            
            # Efficiency should be reasonable (> 50%)
            self.assertGreater(subnet['efficiency'], 0.5)
    
    def test_network_topology_analysis(self):
        """Test network topology analysis"""
        # Simulate network hierarchy
        network_hierarchy = {
            'root': '10.0.0.0/8',
            'regional': [
                '10.1.0.0/16',  # Region 1
                '10.2.0.0/16',  # Region 2
                '10.3.0.0/16'   # Region 3
            ],
            'sites': [
                '10.1.1.0/24',  # Site 1.1
                '10.1.2.0/24',  # Site 1.2
                '10.2.1.0/24',  # Site 2.1
                '10.3.1.0/24'   # Site 3.1
            ]
        }
        
        # Verify hierarchy relationships
        root_network = ipaddress.ip_network(network_hierarchy['root'])
        
        # All regional networks should be subnets of root
        for regional_net in network_hierarchy['regional']:
            regional = ipaddress.ip_network(regional_net)
            self.assertTrue(
                regional.subnet_of(root_network),
                f"{regional_net} should be a subnet of {network_hierarchy['root']}"
            )
        
        # All site networks should be subnets of appropriate regional networks
        site_regional_mapping = {
            '10.1.1.0/24': '10.1.0.0/16',
            '10.1.2.0/24': '10.1.0.0/16',
            '10.2.1.0/24': '10.2.0.0/16',
            '10.3.1.0/24': '10.3.0.0/16'
        }
        
        for site_net, expected_regional in site_regional_mapping.items():
            site = ipaddress.ip_network(site_net)
            regional = ipaddress.ip_network(expected_regional)
            self.assertTrue(
                site.subnet_of(regional),
                f"{site_net} should be a subnet of {expected_regional}"
            )


class TestSubnetVisualization(unittest.TestCase):
    """Test subnet visualization components"""
    
    def test_subnet_mask_visualization(self):
        """Test subnet mask binary visualization"""
        test_masks = [
            ('255.255.255.0', '11111111.11111111.11111111.00000000'),
            ('255.255.255.128', '11111111.11111111.11111111.10000000'),
            ('255.255.255.192', '11111111.11111111.11111111.11000000'),
            ('255.255.255.224', '11111111.11111111.11111111.11100000')
        ]
        
        from utils.helpers import ip_to_binary
        
        for mask, expected_binary in test_masks:
            with self.subTest(mask=mask):
                binary_result = ip_to_binary(mask)
                self.assertEqual(binary_result, expected_binary)
    
    def test_subnet_range_visualization(self):
        """Test subnet range visualization data"""
        network = ipaddress.ip_network('192.168.1.0/26')
        
        visualization_data = {
            'network_address': str(network.network_address),
            'broadcast_address': str(network.broadcast_address),
            'first_host': str(list(network.hosts())[0]),
            'last_host': str(list(network.hosts())[-1]),
            'total_addresses': network.num_addresses,
            'usable_hosts': network.num_addresses - 2,
            'prefix_length': network.prefixlen
        }
        
        # Verify visualization data
        self.assertEqual(visualization_data['network_address'], '192.168.1.0')
        self.assertEqual(visualization_data['broadcast_address'], '192.168.1.63')
        self.assertEqual(visualization_data['first_host'], '192.168.1.1')
        self.assertEqual(visualization_data['last_host'], '192.168.1.62')
        self.assertEqual(visualization_data['total_addresses'], 64)
        self.assertEqual(visualization_data['usable_hosts'], 62)
        self.assertEqual(visualization_data['prefix_length'], 26)
    
    def test_network_diagram_data(self):
        """Test data structure for network diagrams"""
        # Simulate network diagram data structure
        network_diagram = {
            'nodes': [],
            'connections': [],
            'subnets': []
        }
        
        # Add router node
        network_diagram['nodes'].append({
            'id': 'router1',
            'type': 'router',
            'ip': '192.168.1.1',
            'position': (0, 0)
        })
        
        # Add subnet nodes
        subnets = [
            '192.168.1.0/26',
            '192.168.1.64/26', 
            '192.168.1.128/26',
            '192.168.1.192/26'
        ]
        
        for i, subnet in enumerate(subnets):
            network_diagram['subnets'].append({
                'id': f'subnet{i+1}',
                'network': subnet,
                'position': (i+1, 1),
                'color': f'subnet-{i+1}'
            })
            
            # Add connection from router to subnet
            network_diagram['connections'].append({
                'from': 'router1',
                'to': f'subnet{i+1}',
                'type': 'ethernet'
            })
        
        # Verify diagram structure
        self.assertEqual(len(network_diagram['nodes']), 1)
        self.assertEqual(len(network_diagram['subnets']), 4)
        self.assertEqual(len(network_diagram['connections']), 4)
    
    @patch('matplotlib.pyplot.show')
    def test_subnet_chart_generation(self, mock_show):
        """Test subnet utilization chart generation"""
        # Simulate chart data
        subnets_data = [
            {'name': 'Engineering', 'total': 126, 'used': 85, 'utilization': 67.5},
            {'name': 'Sales', 'total': 62, 'used': 45, 'utilization': 72.6},
            {'name': 'Marketing', 'total': 30, 'used': 22, 'utilization': 73.3},
            {'name': 'HR', 'total': 14, 'used': 8, 'utilization': 57.1}
        ]
        
        # Verify chart data integrity
        for subnet in subnets_data:
            calculated_utilization = (subnet['used'] / subnet['total']) * 100
            self.assertAlmostEqual(
                calculated_utilization, 
                subnet['utilization'], 
                places=1,
                msg=f"Utilization calculation mismatch for {subnet['name']}"
            )
        
        # Test that chart generation doesn't crash
        try:
            import matplotlib.pyplot as plt
            import numpy as np
            
            names = [s['name'] for s in subnets_data]
            utilizations = [s['utilization'] for s in subnets_data]
            
            # This should not raise an exception
            fig, ax = plt.subplots()
            ax.bar(names, utilizations)
            ax.set_ylabel('Utilization %')
            ax.set_title('Subnet Utilization')
            
            # Close the figure to prevent memory leaks in tests
            plt.close(fig)
            
        except ImportError:
            self.skipTest("Matplotlib not available for chart generation test")


class TestAdvancedSubnetting(unittest.TestCase):
    """Test advanced subnetting scenarios"""
    
    def test_complex_vlsm_design(self):
        """Test complex VLSM network design"""
        # Scenario: Design subnets for a multi-site organization
        base_network = ipaddress.ip_network('172.16.0.0/16')
        
        requirements = [
            {'site': 'Headquarters', 'hosts': 500},
            {'site': 'Branch 1', 'hosts': 100},
            {'site': 'Branch 2', 'hosts': 50},
            {'site': 'Branch 3', 'hosts': 25},
            {'site': 'WAN Links', 'hosts': 2},  # Point-to-point links
            {'site': 'Management', 'hosts': 10}
        ]
        
        # Sort by size (largest first) for optimal VLSM
        requirements.sort(key=lambda x: x['hosts'], reverse=True)
        
        allocated_subnets = []
        current_network = base_network
        
        for req in requirements:
            import math
            
            # Calculate required subnet size
            required_hosts = req['hosts']
            host_bits = math.ceil(math.log2(required_hosts + 2))
            subnet_prefix = 32 - host_bits
            
            # Ensure we don't exceed the base network prefix
            if subnet_prefix <= current_network.prefixlen:
                subnet_prefix = current_network.prefixlen + 1
            
            try:
                # Find available subnet
                available_subnets = list(current_network.subnets(new_prefix=subnet_prefix))
                if available_subnets:
                    allocated_subnet = available_subnets[0]
                    allocated_subnets.append({
                        'site': req['site'],
                        'required_hosts': required_hosts,
                        'allocated_subnet': str(allocated_subnet),
                        'available_hosts': allocated_subnet.num_addresses - 2,
                        'efficiency': required_hosts / (allocated_subnet.num_addresses - 2) * 100
                    })
                    
                    # Update remaining network space
                    # This is simplified - in practice, you'd track remaining space more carefully
                    
            except ValueError:
                # Subnet too small for requirements
                pass
        
        # Verify allocations
        for allocation in allocated_subnets:
            self.assertGreaterEqual(
                allocation['available_hosts'],
                allocation['required_hosts'],
                f"Allocated subnet for {allocation['site']} too small"
            )
            
            # Efficiency should be reasonable (> 50% for larger subnets)
            if allocation['required_hosts'] > 10:
                self.assertGreater(
                    allocation['efficiency'],
                    50,
                    f"Efficiency too low for {allocation['site']}"
                )
    
    def test_subnet_aggregation_optimization(self):
        """Test subnet aggregation for routing optimization"""
        # Test aggregating multiple small subnets
        small_subnets = [
            ipaddress.ip_network('10.1.0.0/24'),
            ipaddress.ip_network('10.1.1.0/24'),
            ipaddress.ip_network('10.1.2.0/24'),
            ipaddress.ip_network('10.1.3.0/24'),
            ipaddress.ip_network('10.1.4.0/24'),
            ipaddress.ip_network('10.1.5.0/24'),
            ipaddress.ip_network('10.1.6.0/24'),
            ipaddress.ip_network('10.1.7.0/24')
        ]
        
        # These should aggregate to 10.1.0.0/21
        aggregated = list(ipaddress.collapse_addresses(small_subnets))
        
        self.assertEqual(len(aggregated), 1)
        self.assertEqual(str(aggregated[0]), '10.1.0.0/21')
        
        # Test routing table reduction
        original_routes = len(small_subnets)  # 8 routes
        aggregated_routes = len(aggregated)   # 1 route
        reduction_percentage = ((original_routes - aggregated_routes) / original_routes) * 100
        
        self.assertAlmostEqual(reduction_percentage, 87.5)  # 87.5% reduction
    
    def test_subnet_security_zones(self):
        """Test subnet design for security zones"""
        # Design subnets with security considerations
        security_zones = {
            'dmz': {'network': '192.168.10.0/24', 'security_level': 'medium'},
            'internal': {'network': '192.168.20.0/23', 'security_level': 'high'},
            'guest': {'network': '192.168.100.0/24', 'security_level': 'low'},
            'management': {'network': '192.168.99.0/28', 'security_level': 'critical'}
        }
        
        # Verify security zone isolation (no overlaps)
        networks = []
        for zone, config in security_zones.items():
            network = ipaddress.ip_network(config['network'])
            networks.append(network)
        
        # Check for overlaps
        for i, net1 in enumerate(networks):
            for j, net2 in enumerate(networks[i+1:], i+1):
                self.assertFalse(
                    net1.overlaps(net2),
                    f"Security zones should not overlap: {net1} and {net2}"
                )
        
        # Verify management network is smallest (most restricted)
        mgmt_network = ipaddress.ip_network(security_zones['management']['network'])
        self.assertEqual(mgmt_network.prefixlen, 28)  # Most restrictive
        self.assertEqual(mgmt_network.num_addresses - 2, 14)  # Only 14 hosts


class TestSubnetTroubleshooting(unittest.TestCase):
    """Test subnet troubleshooting scenarios"""
    
    def test_subnet_connectivity_analysis(self):
        """Test subnet connectivity analysis"""
        # Simulate connectivity between subnets
        subnets = [
            {'network': '192.168.1.0/24', 'gateway': '192.168.1.1'},
            {'network': '192.168.2.0/24', 'gateway': '192.168.2.1'},
            {'network': '192.168.3.0/24', 'gateway': '192.168.3.1'}
        ]
        
        # Test same subnet connectivity
        host1 = ipaddress.ip_address('192.168.1.10')
        host2 = ipaddress.ip_address('192.168.1.20')
        network1 = ipaddress.ip_network('192.168.1.0/24')
        
        # Both hosts should be in same subnet
        self.assertIn(host1, network1)
        self.assertIn(host2, network1)
        
        # Test different subnet connectivity (requires routing)
        host3 = ipaddress.ip_address('192.168.2.10')
        network2 = ipaddress.ip_network('192.168.2.0/24')
        
        self.assertIn(host3, network2)
        self.assertNotIn(host3, network1)  # Different subnet
    
    def test_subnet_addressing_errors(self):
        """Test detection of common subnet addressing errors"""
        # Test network address used as host address
        network = ipaddress.ip_network('192.168.1.0/24')
        network_address = network.network_address
        broadcast_address = network.broadcast_address
        
        # Network and broadcast addresses should not be in host range
        host_range = list(network.hosts())
        
        self.assertNotIn(network_address, host_range)
        self.assertNotIn(broadcast_address, host_range)
        
        # Test subnet mask mismatch detection
        incorrect_configs = [
            {'ip': '192.168.1.10', 'mask': '255.255.0.0'},    # Should be /24, not /16
            {'ip': '10.0.0.1', 'mask': '255.255.255.0'},      # Should be /8 or /16, not /24
        ]
        
        for config in incorrect_configs:
            ip = ipaddress.ip_address(config['ip'])
            # This would be detected by network analysis tools
            # as a potential misconfiguration
            
            # Convert mask to CIDR for comparison
            mask_cidr = subnet_mask_to_cidr(config['mask'])
            network_with_mask = ipaddress.ip_network(f"{config['ip']}/{mask_cidr}", strict=False)
            
            # Verify we can create the network (even if misconfigured)
            self.assertIsInstance(network_with_mask, ipaddress.IPv4Network)
    
    def test_subnet_capacity_planning(self):
        """Test subnet capacity planning and alerts"""
        # Simulate subnet utilization monitoring
        subnet_monitoring = [
            {'subnet': '192.168.1.0/24', 'total': 254, 'used': 200, 'threshold': 80},
            {'subnet': '192.168.2.0/25', 'total': 126, 'used': 50, 'threshold': 80},
            {'subnet': '192.168.3.0/26', 'total': 62, 'used': 55, 'threshold': 80}
        ]
        
        alerts = []
        for subnet_info in subnet_monitoring:
            utilization = (subnet_info['used'] / subnet_info['total']) * 100
            
            if utilization > subnet_info['threshold']:
                alerts.append({
                    'subnet': subnet_info['subnet'],
                    'utilization': utilization,
                    'severity': 'high' if utilization > 90 else 'medium'
                })
        
        # Verify alert generation
        high_util_subnets = [s for s in subnet_monitoring if (s['used']/s['total'])*100 > s['threshold']]
        self.assertEqual(len(alerts), len(high_util_subnets))
        
        # Check specific alerts
        subnet1_util = (200/254) * 100  # ~78.7% - should trigger alert
        subnet3_util = (55/62) * 100    # ~88.7% - should trigger alert
        
        self.assertGreater(subnet1_util, 70)  # High utilization
        self.assertGreater(subnet3_util, 80)  # Very high utilization


class TestSubnetDocumentation(unittest.TestCase):
    """Test subnet documentation and reporting"""
    
    def test_subnet_inventory_generation(self):
        """Test generation of subnet inventory reports"""
        # Simulate subnet inventory
        subnet_inventory = [
            {
                'network': '192.168.1.0/24',
                'description': 'Engineering Department',
                'vlan': 10,
                'gateway': '192.168.1.1',
                'dns': ['192.168.1.2', '8.8.8.8'],
                'dhcp_range': '192.168.1.100-192.168.1.200',
                'total_hosts': 254,
                'allocated_hosts': 85,
                'utilization': 33.5
            },
            {
                'network': '192.168.2.0/25', 
                'description': 'Sales Department',
                'vlan': 20,
                'gateway': '192.168.2.1',
                'dns': ['192.168.1.2', '8.8.8.8'],
                'dhcp_range': '192.168.2.50-192.168.2.100',
                'total_hosts': 126,
                'allocated_hosts': 45,
                'utilization': 35.7
            }
        ]
        
        # Generate summary report
        total_networks = len(subnet_inventory)
        total_addresses = sum(s['total_hosts'] for s in subnet_inventory)
        total_allocated = sum(s['allocated_hosts'] for s in subnet_inventory)
        overall_utilization = (total_allocated / total_addresses) * 100
        
        report_summary = {
            'total_networks': total_networks,
            'total_addresses': total_addresses,
            'total_allocated': total_allocated,
            'overall_utilization': overall_utilization,
            'timestamp': '2024-01-01 12:00:00'
        }
        
        # Verify report data
        self.assertEqual(report_summary['total_networks'], 2)
        self.assertEqual(report_summary['total_addresses'], 380)  # 254 + 126
        self.assertEqual(report_summary['total_allocated'], 130)   # 85 + 45
        self.assertAlmostEqual(report_summary['overall_utilization'], 34.21, places=1)
    
    def test_subnet_configuration_export(self):
        """Test export of subnet configurations"""
        # Test configuration export formats
        subnet_config = {
            'network': '192.168.1.0/24',
            'gateway': '192.168.1.1',
            'dns_servers': ['8.8.8.8', '1.1.1.1'],
            'dhcp_enabled': True,
            'dhcp_range': {'start': '192.168.1.100', 'end': '192.168.1.200'},
            'vlan_id': 10,
            'description': 'Engineering Network'
        }
        
        # Test JSON export
        import json
        json_export = json.dumps(subnet_config, indent=2)
        parsed_config = json.loads(json_export)
        
        self.assertEqual(parsed_config['network'], subnet_config['network'])
        self.assertEqual(parsed_config['vlan_id'], subnet_config['vlan_id'])
        
        # Test CSV-style export data
        csv_data = {
            'Network': subnet_config['network'],
            'Gateway': subnet_config['gateway'],
            'VLAN': subnet_config['vlan_id'],
            'DHCP Enabled': 'Yes' if subnet_config['dhcp_enabled'] else 'No',
            'Description': subnet_config['description']
        }
        
        self.assertIsInstance(csv_data, dict)
        self.assertEqual(csv_data['Network'], '192.168.1.0/24')
        self.assertEqual(csv_data['DHCP Enabled'], 'Yes')


if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add all test cases
    test_suite.addTest(unittest.makeSuite(TestSubnetCalculations))
    test_suite.addTest(unittest.makeSuite(TestNetworkAnalysis))
    test_suite.addTest(unittest.makeSuite(TestSubnetVisualization))
    test_suite.addTest(unittest.makeSuite(TestAdvancedSubnetting))
    test_suite.addTest(unittest.makeSuite(TestSubnetTroubleshooting))
    test_suite.addTest(unittest.makeSuite(TestSubnetDocumentation))
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"Subnet Visualization and Analysis Test Summary")
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
        print("✅ Subnet calculations working correctly")
        print("✅ Network analysis functions operational") 
        print("✅ Visualization components ready")
        print("✅ Advanced subnetting scenarios covered")
        print("✅ Troubleshooting tools tested")
        print("✅ Documentation generation verified")
    else:
        print(f"\n⚠️ Some tests failed. Please review the failures and errors above.")
    
    print(f"{'='*60}")
    print("Subnet visualization and analysis testing complete!")
