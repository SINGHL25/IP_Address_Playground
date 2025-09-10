"""
IP Class Identifier Module

This module provides comprehensive IP address classification and analysis functionality.
It can identify IP address classes, determine network properties, and provide detailed
information about IP address characteristics.
"""

import ipaddress
import socket
from typing import Dict, List, Optional, Union, Tuple
from utils.helpers import validate_ip_address, get_ip_class

class IPClassIdentifier:
    """
    A comprehensive IP address classifier that provides detailed analysis
    of IP addresses including class identification, network properties,
    and special address range detection.
    """
    
    def __init__(self):
        """Initialize the IP Class Identifier with predefined ranges."""
        self.private_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255')
        ]
        
        self.special_ranges = {
            'loopback': [('127.0.0.0', '127.255.255.255')],
            'link_local': [('169.254.0.0', '169.254.255.255')],
            'multicast': [('224.0.0.0', '239.255.255.255')],
            'experimental': [('240.0.0.0', '255.255.255.255')],
            'broadcast': [('255.255.255.255', '255.255.255.255')]
        }
        
        self.class_ranges = {
            'A': {'start': 1, 'end': 126, 'default_mask': '255.0.0.0', 'cidr': 8},
            'B': {'start': 128, 'end': 191, 'default_mask': '255.255.0.0', 'cidr': 16},
            'C': {'start': 192, 'end': 223, 'default_mask': '255.255.255.0', 'cidr': 24},
            'D': {'start': 224, 'end': 239, 'default_mask': 'N/A', 'cidr': 'N/A'},
            'E': {'start': 240, 'end': 255, 'default_mask': 'N/A', 'cidr': 'N/A'}
        }
    
    def identify_class(self, ip_address: str) -> Optional[Dict]:
        """
        Identify the class of an IP address and return comprehensive information.
        
        Args:
            ip_address (str): The IP address to classify
            
        Returns:
            Dict: Comprehensive information about the IP address, or None if invalid
        """
        if not validate_ip_address(ip_address):
            return None
        
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            first_octet = int(str(ip_obj).split('.')[0])
            
            # Get basic class information
            basic_class_info = get_ip_class(ip_address)
            
            # Determine IP class based on first octet
            ip_class = self._determine_class_by_octet(first_octet)
            
            # Get detailed analysis
            detailed_info = {
                'ip_address': ip_address,
                'class': ip_class,
                'first_octet': first_octet,
                'version': f"IPv{ip_obj.version}",
                'is_private': self._is_private_ip(ip_address),
                'is_public': not self._is_private_ip(ip_address) and ip_class in ['A', 'B', 'C'],
                'is_loopback': ip_obj.is_loopback,
                'is_multicast': ip_obj.is_multicast,
                'is_reserved': ip_obj.is_reserved,
                'is_link_local': ip_obj.is_link_local,
                'special_range': self._get_special_range(ip_address),
                'binary_representation': self._get_binary_representation(ip_address),
                'class_info': basic_class_info,
                'subnetting_info': self._get_subnetting_info(ip_address, ip_class),
                'routing_info': self._get_routing_info(ip_address, ip_class),
                'usage_recommendations': self._get_usage_recommendations(ip_address, ip_class)
            }
            
            return detailed_info
            
        except Exception as e:
            return {'error': f"Error analyzing IP address: {str(e)}"}
    
    def _determine_class_by_octet(self, first_octet: int) -> str:
        """Determine IP class based on first octet value."""
        for class_name, range_info in self.class_ranges.items():
            if range_info['start'] <= first_octet <= range_info['end']:
                return class_name
        return 'Invalid'
    
    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if IP address is in private range."""
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            return ip_obj.is_private
        except:
            return False
    
    def _get_special_range(self, ip_address: str) -> Optional[str]:
        """Identify if IP address belongs to any special range."""
        try:
            ip_int = int(ipaddress.ip_address(ip_address))
            
            for range_name, ranges in self.special_ranges.items():
                for start_ip, end_ip in ranges:
                    start_int = int(ipaddress.ip_address(start_ip))
                    end_int = int(ipaddress.ip_address(end_ip))
                    
                    if start_int <= ip_int <= end_int:
                        return range_name
            
            return None
        except:
            return None
    
    def _get_binary_representation(self, ip_address: str) -> Dict[str, str]:
        """Get binary representation of IP address."""
        try:
            parts = ip_address.split('.')
            return {
                'dotted_binary': '.'.join([format(int(part), '08b') for part in parts]),
                'continuous_binary': ''.join([format(int(part), '08b') for part in parts]),
                'octet_breakdown': [
                    {
                        'decimal': int(part),
                        'binary': format(int(part), '08b'),
                        'hex': format(int(part), '02x').upper()
                    } for part in parts
                ]
            }
        except:
            return {'error': 'Unable to convert to binary'}
    
    def _get_subnetting_info(self, ip_address: str, ip_class: str) -> Dict:
        """Get subnetting information for the IP address."""
        if ip_class not in ['A', 'B', 'C']:
            return {'supported': False, 'reason': 'Subnetting not applicable for this class'}
        
        class_info = self.class_ranges[ip_class]
        default_mask_bits = class_info['cidr']
        
        subnetting_options = []
        
        # Calculate possible subnet divisions
        for additional_bits in range(1, 32 - default_mask_bits):
            new_cidr = default_mask_bits + additional_bits
            if new_cidr >= 30:  # Stop at /30 (practical limit)
                break
            
            num_subnets = 2 ** additional_bits
            hosts_per_subnet = (2 ** (32 - new_cidr)) - 2
            
            subnetting_options.append({
                'additional_bits': additional_bits,
                'new_cidr': new_cidr,
                'num_subnets': num_subnets,
                'hosts_per_subnet': hosts_per_subnet,
                'subnet_mask': self._cidr_to_mask(new_cidr)
            })
        
        return {
            'supported': True,
            'default_cidr': default_mask_bits,
            'default_mask': class_info['default_mask'],
            'subnetting_options': subnetting_options[:10],  # Limit to first 10 options
            'max_subnets': 2 ** (32 - default_mask_bits - 2),  # Leave at least 2 host bits
            'vlsm_capable': True
        }
    
    def _get_routing_info(self, ip_address: str, ip_class: str) -> Dict:
        """Get routing-related information."""
        is_private = self._is_private_ip(ip_address)
        
        routing_info = {
            'routable_on_internet': not is_private and ip_class in ['A', 'B', 'C'],
            'requires_nat': is_private,
            'default_route_summarization': ip_class in ['A', 'B', 'C'],
            'classful_routing': True,
            'classless_routing_cidr': True
        }
        
        if ip_class == 'A':
            routing_info['summary_route'] = f"{ip_address.split('.')[0]}.0.0.0/8"
        elif ip_class == 'B':
            parts = ip_address.split('.')
            routing_info['summary_route'] = f"{parts[0]}.{parts[1]}.0.0/16"
        elif ip_class == 'C':
            parts = ip_address.split('.')
            routing_info['summary_route'] = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        
        return routing_info
    
    def _get_usage_recommendations(self, ip_address: str, ip_class: str) -> List[str]:
        """Get usage recommendations based on IP characteristics."""
        recommendations = []
        
        is_private = self._is_private_ip(ip_address)
        special_range = self._get_special_range(ip_address)
        
        if special_range == 'loopback':
            recommendations.append("Use for local testing and diagnostics")
            recommendations.append("Not routable outside the local host")
        elif special_range == 'link_local':
            recommendations.append("Auto-configured when DHCP fails")
            recommendations.append("Not routable beyond local network segment")
        elif special_range == 'multicast':
            recommendations.append("Use for multicast communications")
            recommendations.append("Requires multicast-enabled network infrastructure")
        elif special_range == 'experimental':
            recommendations.append("Reserved for experimental use")
            recommendations.append("Should not be used in production networks")
        elif is_private:
            if ip_class == 'A':
                recommendations.append("Ideal for very large private networks")
                recommendations.append("Commonly used in enterprise environments")
            elif ip_class == 'B':
                recommendations.append("Suitable for medium to large private networks")
                recommendations.append("Good balance of networks and hosts")
            elif ip_class == 'C':
                recommendations.append("Perfect for small private networks")
                recommendations.append("Most common for home and small office networks")
            
            recommendations.append("Requires NAT for internet connectivity")
            recommendations.append("Can be freely used within private networks")
        else:
            recommendations.append("Routable on the public internet")
            recommendations.append("Requires proper registration and management")
            recommendations.append("Should be used with appropriate security measures")
        
        return recommendations
    
    def _cidr_to_mask(self, cidr: int) -> str:
        """Convert CIDR notation to subnet mask."""
        if cidr < 0 or cidr > 32:
            return "Invalid"
        
        binary = '1' * cidr + '0' * (32 - cidr)
        octets = []
        for i in range(0, 32, 8):
            octets.append(str(int(binary[i:i+8], 2)))
        
        return '.'.join(octets)
    
    def analyze_network_range(self, start_ip: str, end_ip: str) -> Dict:
        """
        Analyze a range of IP addresses.
        
        Args:
            start_ip (str): Starting IP address
            end_ip (str): Ending IP address
            
        Returns:
            Dict: Analysis of the IP range
        """
        if not validate_ip_address(start_ip) or not validate_ip_address(end_ip):
            return {'error': 'Invalid IP address(es) provided'}
        
        try:
            start_obj = ipaddress.ip_address(start_ip)
            end_obj = ipaddress.ip_address(end_ip)
            
            if start_obj > end_obj:
                start_obj, end_obj = end_obj, start_obj
                start_ip, end_ip = end_ip, start_ip
            
            range_size = int(end_obj) - int(start_obj) + 1
            
            # Analyze classes in range
            classes_in_range = set()
            sample_ips = []
            
            # Sample some IPs from the range for analysis
            sample_size = min(10, range_size)
            step = max(1, range_size // sample_size)
            
            for i in range(0, range_size, step):
                current_ip = str(ipaddress.ip_address(int(start_obj) + i))
                sample_ips.append(current_ip)
                ip_class = get_ip_class(current_ip)['class']
                classes_in_range.add(ip_class)
            
            return {
                'start_ip': start_ip,
                'end_ip': end_ip,
                'range_size': range_size,
                'classes_in_range': list(classes_in_range),
                'sample_analysis': [self.identify_class(ip) for ip in sample_ips],
                'is_contiguous': True,  # By definition, this range is contiguous
                'possible_supernet': self._find_supernet(start_ip, end_ip)
            }
            
        except Exception as e:
            return {'error': f"Error analyzing range: {str(e)}"}
    
    def _find_supernet(self, start_ip: str, end_ip: str) -> Optional[str]:
        """Find the smallest supernet that contains the given range."""
        try:
            start_obj = ipaddress.ip_address(start_ip)
            end_obj = ipaddress.ip_address(end_ip)
            
            # Find the network that encompasses both IPs
            for cidr in range(0, 32):
                network = ipaddress.ip_network(f"{start_ip}/{cidr}", strict=False)
                if start_obj in network and end_obj in network:
                    return str(network)
            
            return None
        except:
            return None
    
    def get_class_statistics(self, ip_list: List[str]) -> Dict:
        """
        Generate statistics for a list of IP addresses.
        
        Args:
            ip_list (List[str]): List of IP addresses to analyze
            
        Returns:
            Dict: Statistics about the IP addresses
        """
        if not ip_list:
            return {'error': 'No IP addresses provided'}
        
        stats = {
            'total_ips': len(ip_list),
            'valid_ips': 0,
            'invalid_ips': 0,
            'class_distribution': {},
            'private_count': 0,
            'public_count': 0,
            'special_ranges': {},
            'unique_ips': 0,
            'ipv4_count': 0,
            'ipv6_count': 0
        }
        
        valid_ips = set()
        
        for ip in ip_list:
            if validate_ip_address(ip):
                stats['valid_ips'] += 1
                valid_ips.add(ip)
                
                # Analyze the IP
                analysis = self.identify_class(ip)
                if analysis and 'class' in analysis:
                    ip_class = analysis['class']
                    stats['class_distribution'][ip_class] = stats['class_distribution'].get(ip_class, 0) + 1
                    
                    if analysis['is_private']:
                        stats['private_count'] += 1
                    elif analysis['is_public']:
                        stats['public_count'] += 1
                    
                    special_range = analysis['special_range']
                    if special_range:
                        stats['special_ranges'][special_range] = stats['special_ranges'].get(special_range, 0) + 1
                    
                    if analysis['version'] == 'IPv4':
                        stats['ipv4_count'] += 1
                    else:
                        stats['ipv6_count'] += 1
            else:
                stats['invalid_ips'] += 1
        
        stats['unique_ips'] = len(valid_ips)
        stats['duplicate_count'] = stats['valid_ips'] - stats['unique_ips']
        
        return stats
