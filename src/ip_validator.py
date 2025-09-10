
#!/usr/bin/env python3
"""
IP Address Validator
Validates and analyzes both IPv4 and IPv6 addresses with detailed information.
"""

import ipaddress
import sys
import re
from typing import Dict, Union, Optional, Tuple


class IPValidator:
    """Comprehensive IP address validator and analyzer."""
    
    def __init__(self):
        """Initialize IP validator with private IP ranges."""
        self.private_ranges = {
            'Class A': ipaddress.IPv4Network('10.0.0.0/8'),
            'Class B': ipaddress.IPv4Network('172.16.0.0/12'),
            'Class C': ipaddress.IPv4Network('192.168.0.0/16'),
        }
        
        self.special_ranges = {
            'Loopback': ipaddress.IPv4Network('127.0.0.0/8'),
            'Link-Local': ipaddress.IPv4Network('169.254.0.0/16'),
            'Multicast': ipaddress.IPv4Network('224.0.0.0/4'),
            'Broadcast': ipaddress.IPv4Address('255.255.255.255'),
        }
    
    def validate_ip(self, ip_str: str) -> Dict[str, Union[str, bool, None]]:
        """
        Validate and analyze an IP address.
        
        Args:
            ip_str: String representation of IP address
            
        Returns:
            Dictionary containing validation results and IP details
        """
        result = {
            'input': ip_str,
            'valid': False,
            'version': None,
            'type': None,
            'binary': None,
            'hex': None,
            'integer': None,
            'is_private': False,
            'is_global': False,
            'is_multicast': False,
            'is_loopback': False,
            'is_link_local': False,
            'details': {}
        }
        
        try:
            # Try to create IP address object
            ip_obj = ipaddress.ip_address(ip_str)
            result['valid'] = True
            result['version'] = ip_obj.version
            
            if isinstance(ip_obj, ipaddress.IPv4Address):
                result.update(self._analyze_ipv4(ip_obj))
            else:  # IPv6
                result.update(self._analyze_ipv6(ip_obj))
                
        except ValueError as e:
            result['error'] = str(e)
            
        return result
    
    def _analyze_ipv4(self, ip: ipaddress.IPv4Address) -> Dict:
        """Analyze IPv4 address properties."""
        analysis = {
            'type': 'IPv4',
            'binary': format(int(ip), '032b'),
            'hex': hex(int(ip)),
            'integer': int(ip),
            'is_private': ip.is_private,
            'is_global': ip.is_global,
            'is_multicast': ip.is_multicast,
            'is_loopback': ip.is_loopback,
            'is_link_local': ip.is_link_local,
        }
        
        # Determine IP class
        first_octet = int(str(ip).split('.')[0])
        if 1 <= first_octet <= 126:
            ip_class = 'A'
        elif 128 <= first_octet <= 191:
            ip_class = 'B'
        elif 192 <= first_octet <= 223:
            ip_class = 'C'
        elif 224 <= first_octet <= 239:
            ip_class = 'D (Multicast)'
        else:
            ip_class = 'E (Experimental)'
            
        analysis['details'] = {
            'class': ip_class,
            'octets': str(ip).split('.'),
            'binary_octets': [format(int(octet), '08b') for octet in str(ip).split('.')],
            'reverse_dns': f"{'.'.join(reversed(str(ip).split('.')))}.in-addr.arpa"
        }
        
        # Check which private range it belongs to
        if ip.is_private:
            for range_name, network in self.private_ranges.items():
                if ip in network:
                    analysis['details']['private_range'] = range_name
                    break
                    
        return analysis
    
    def _analyze_ipv6(self, ip: ipaddress.IPv6Address) -> Dict:
        """Analyze IPv6 address properties."""
        analysis = {
            'type': 'IPv6',
            'binary': format(int(ip), '0128b'),
            'hex': hex(int(ip)),
            'integer': int(ip),
            'is_private': ip.is_private,
            'is_global': ip.is_global,
            'is_multicast': ip.is_multicast,
            'is_loopback': ip.is_loopback,
            'is_link_local': ip.is_link_local,
        }
        
        # IPv6 specific details
        analysis['details'] = {
            'compressed': ip.compressed,
            'exploded': ip.exploded,
            'is_site_local': ip.is_site_local,
            'is_unspecified': ip.is_unspecified,
            'scope_id': ip.scope_id if hasattr(ip, 'scope_id') else None,
            'teredo': ip.teredo if hasattr(ip, 'teredo') else None,
            'sixtofour': ip.sixtofour if hasattr(ip, 'sixtofour') else None,
        }
        
        return analysis
    
    def validate_subnet(self, subnet_str: str) -> Dict:
        """
        Validate and analyze a subnet in CIDR notation.
        
        Args:
            subnet_str: String representation of subnet (e.g., '192.168.1.0/24')
            
        Returns:
            Dictionary containing subnet analysis
        """
        result = {
            'input': subnet_str,
            'valid': False,
            'network': None,
            'broadcast': None,
            'netmask': None,
            'wildcard': None,
            'prefix_length': None,
            'num_addresses': None,
            'num_hosts': None,
            'first_host': None,
            'last_host': None,
        }
        
        try:
            network = ipaddress.ip_network(subnet_str, strict=False)
            result['valid'] = True
            result['network'] = str(network.network_address)
            result['broadcast'] = str(network.broadcast_address)
            result['netmask'] = str(network.netmask)
            result['wildcard'] = str(network.hostmask)
            result['prefix_length'] = network.prefixlen
            result['num_addresses'] = network.num_addresses
            
            # Calculate usable hosts (excluding network and broadcast)
            if network.num_addresses > 2:
                result['num_hosts'] = network.num_addresses - 2
                hosts = list(network.hosts())
                if hosts:
                    result['first_host'] = str(hosts[0])
                    result['last_host'] = str(hosts[-1])
            else:
                result['num_hosts'] = 0
                
        except ValueError as e:
            result['error'] = str(e)
            
        return result
    
    def check_ip_in_subnet(self, ip_str: str, subnet_str: str) -> Tuple[bool, str]:
        """
        Check if an IP address belongs to a subnet.
        
        Args:
            ip_str: IP address string
            subnet_str: Subnet string in CIDR notation
            
        Returns:
            Tuple of (is_in_subnet, message)
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            network = ipaddress.ip_network(subnet_str, strict=False)
            
            if ip in network:
                return True, f"{ip_str} is in subnet {subnet_str}"
            else:
                return False, f"{ip_str} is NOT in subnet {subnet_str}"
                
        except ValueError as e:
            return False, f"Error: {str(e)}"
    
    def calculate_summary_route(self, subnets: list) -> Optional[str]:
        """
        Calculate summary route for multiple subnets.
        
        Args:
            subnets: List of subnet strings
            
        Returns:
            Summary route in CIDR notation or None
        """
        try:
            networks = [ipaddress.ip_network(subnet, strict=False) for subnet in subnets]
            summary = ipaddress.collapse_addresses(networks)
            return str(list(summary)[0]) if summary else None
        except Exception as e:
            print(f"Error calculating summary: {e}")
            return None


def print_validation_result(result: Dict):
    """Pretty print validation results."""
    print("\n" + "="*60)
    print(f"IP Address Validation Report")
    print("="*60)
    
    print(f"Input: {result['input']}")
    print(f"Valid: {'✓' if result['valid'] else '✗'}")
    
    if result['valid']:
        print(f"Version: IPv{result['version']}")
        print(f"Type: {result['type']}")
        print(f"\nProperties:")
        print(f"  • Private: {result['is_private']}")
        print(f"  • Global: {result['is_global']}")
        print(f"  • Multicast: {result['is_multicast']}")
        print(f"  • Loopback: {result['is_loopback']}")
        print(f"  • Link-Local: {result['is_link_local']}")
        
        print(f"\nRepresentations:")
        print(f"  • Binary: {result['binary']}")
        print(f"  • Hex: {result['hex']}")
        print(f"  • Integer: {result['integer']}")
        
        if result['details']:
            print(f"\nAdditional Details:")
            for key, value in result['details'].items():
                if value is not None:
                    print(f"  • {key.replace('_', ' ').title()}: {value}")
    else:
        print(f"Error: {result.get('error', 'Invalid IP address format')}")
    
    print("="*60 + "\n")


def print_subnet_result(result: Dict):
    """Pretty print subnet validation results."""
    print("\n" + "="*60)
    print(f"Subnet Analysis Report")
    print("="*60)
    
    print(f"Input: {result['input']}")
    print(f"Valid: {'✓' if result['valid'] else '✗'}")
    
    if result['valid']:
        print(f"\nNetwork Information:")
        print(f"  • Network Address: {result['network']}")
        print(f"  • Broadcast Address: {result['broadcast']}")
        print(f"  • Subnet Mask: {result['netmask']}")
        print(f"  • Wildcard Mask: {result['wildcard']}")
        print(f"  • Prefix Length: /{result['prefix_length']}")
        
        print(f"\nCapacity:")
        print(f"  • Total Addresses: {result['num_addresses']:,}")
        print(f"  • Usable Hosts: {result['num_hosts']:,}")
        
        if result['first_host'] and result['last_host']:
            print(f"\nHost Range:")
            print(f"  • First Host: {result['first_host']}")
            print(f"  • Last Host: {result['last_host']}")
    else:
        print(f"Error: {result.get('error', 'Invalid subnet format')}")
    
    print("="*60 + "\n")


def main():
    """Main function for command-line usage."""
    validator = IPValidator()
    
    if len(sys.argv) < 2:
        print("Usage: python ip_validator.py <ip_address> [subnet]")
        print("\nExamples:")
        print("  python ip_validator.py 192.168.1.1")
        print("  python ip_validator.py 2001:db8::1")
        print("  python ip_validator.py 192.168.1.0/24")
        print("  python ip_validator.py 192.168.1.100 192.168.1.0/24")
        sys.exit(1)
    
    input_str = sys.argv[1]
    
    # Check if it's a subnet (contains /)
    if '/' in input_str:
        result = validator.validate_subnet(input_str)
        print_subnet_result(result)
    else:
        # It's an IP address
        result = validator.validate_ip(input_str)
        print_validation_result(result)
        
        # If a second argument is provided, check if IP is in that subnet
        if len(sys.argv) > 2:
            subnet_str = sys.argv[2]
            is_in, message = validator.check_ip_in_subnet(input_str, subnet_str)
            print(f"\nSubnet Membership Check:")
            print(f"  {message}")
    
    # Demo: Calculate summary route
    if len(sys.argv) == 2 and sys.argv[1] == 'demo':
        print("\n" + "="*60)
        print("Demo: Summary Route Calculation")
        print("="*60)
        subnets = [
            '192.168.1.0/24',
            '192.168.2.0/24',
            '192.168.3.0/24',
            '192.168.4.0/24'
        ]
        print(f"Subnets: {', '.join(subnets)}")
        summary = validator.calculate_summary_route(subnets)
        print(f"Summary Route: {summary}")


if __name__ == "__main__":
    main()
