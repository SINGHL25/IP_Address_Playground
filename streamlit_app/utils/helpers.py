import ipaddress
import socket
import re
from typing import Tuple, Dict, List, Union

def validate_ip_address(ip: str) -> bool:
    """Validate if the given string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_subnet_mask(mask: str) -> bool:
    """Validate if the given string is a valid subnet mask."""
    try:
        # Check if it's in CIDR notation
        if '/' in mask:
            return False
        
        # Check if it's a valid IP address format
        parts = mask.split('.')
        if len(parts) != 4:
            return False
        
        # Convert to binary and check if it's a valid subnet mask
        binary = ''
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False
            binary += format(num, '08b')
        
        # Valid subnet mask should have consecutive 1s followed by consecutive 0s
        if '01' in binary:
            return False
        
        return True
    except ValueError:
        return False

def ip_to_binary(ip: str) -> str:
    """Convert IP address to binary representation."""
    try:
        parts = ip.split('.')
        binary_parts = [format(int(part), '08b') for part in parts]
        return '.'.join(binary_parts)
    except:
        return ""

def binary_to_ip(binary: str) -> str:
    """Convert binary representation to IP address."""
    try:
        parts = binary.split('.')
        ip_parts = [str(int(part, 2)) for part in parts]
        return '.'.join(ip_parts)
    except:
        return ""

def cidr_to_subnet_mask(cidr: int) -> str:
    """Convert CIDR notation to subnet mask."""
    if cidr < 0 or cidr > 32:
        return ""
    
    # Create binary representation
    binary = '1' * cidr + '0' * (32 - cidr)
    
    # Convert to dotted decimal
    octets = []
    for i in range(0, 32, 8):
        octets.append(str(int(binary[i:i+8], 2)))
    
    return '.'.join(octets)

def subnet_mask_to_cidr(mask: str) -> int:
    """Convert subnet mask to CIDR notation."""
    try:
        parts = mask.split('.')
        binary = ''
        for part in parts:
            binary += format(int(part), '08b')
        return binary.count('1')
    except:
        return -1

def get_ip_class(ip: str) -> Dict[str, Union[str, int]]:
    """Determine the class of an IP address."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        first_octet = int(str(ip_obj).split('.')[0])
        
        if 1 <= first_octet <= 126:
            return {
                'class': 'A',
                'range': '1.0.0.0 - 126.255.255.255',
                'default_mask': '255.0.0.0',
                'cidr': 8,
                'networks': 126,
                'hosts_per_network': 16777214
            }
        elif 128 <= first_octet <= 191:
            return {
                'class': 'B',
                'range': '128.0.0.0 - 191.255.255.255',
                'default_mask': '255.255.0.0',
                'cidr': 16,
                'networks': 16384,
                'hosts_per_network': 65534
            }
        elif 192 <= first_octet <= 223:
            return {
                'class': 'C',
                'range': '192.0.0.0 - 223.255.255.255',
                'default_mask': '255.255.255.0',
                'cidr': 24,
                'networks': 2097152,
                'hosts_per_network': 254
            }
        elif 224 <= first_octet <= 239:
            return {
                'class': 'D',
                'range': '224.0.0.0 - 239.255.255.255',
                'default_mask': 'N/A (Multicast)',
                'cidr': 'N/A',
                'networks': 'N/A',
                'hosts_per_network': 'N/A'
            }
        elif 240 <= first_octet <= 255:
            return {
                'class': 'E',
                'range': '240.0.0.0 - 255.255.255.255',
                'default_mask': 'N/A (Experimental)',
                'cidr': 'N/A',
                'networks': 'N/A',
                'hosts_per_network': 'N/A'
            }
        else:
            return {
                'class': 'Invalid',
                'range': 'N/A',
                'default_mask': 'N/A',
                'cidr': 'N/A',
                'networks': 'N/A',
                'hosts_per_network': 'N/A'
            }
    except:
        return {
            'class': 'Invalid',
            'range': 'N/A',
            'default_mask': 'N/A',
            'cidr': 'N/A',
            'networks': 'N/A',
            'hosts_per_network': 'N/A'
        }

def is_private_ip(ip: str) -> bool:
    """Check if an IP address is private."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except:
        return False

def is_loopback_ip(ip: str) -> bool:
    """Check if an IP address is loopback."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_loopback
    except:
        return False

def calculate_network_info(ip: str, mask: str) -> Dict[str, str]:
    """Calculate network information given IP and subnet mask."""
    try:
        # Create network object
        if '/' in mask:
            network = ipaddress.ip_network(f"{ip}/{mask.split('/')[1]}", strict=False)
        else:
            cidr = subnet_mask_to_cidr(mask)
            network = ipaddress.ip_network(f"{ip}/{cidr}", strict=False)
        
        return {
            'network_address': str(network.network_address),
            'broadcast_address': str(network.broadcast_address),
            'first_host': str(list(network.hosts())[0]) if list(network.hosts()) else 'N/A',
            'last_host': str(list(network.hosts())[-1]) if list(network.hosts()) else 'N/A',
            'total_hosts': str(network.num_addresses - 2) if network.num_addresses > 2 else '0',
            'network_size': str(network.num_addresses),
            'wildcard_mask': str(network.hostmask)
        }
    except:
        return {
            'network_address': 'Invalid',
            'broadcast_address': 'Invalid',
            'first_host': 'Invalid',
            'last_host': 'Invalid',
            'total_hosts': 'Invalid',
            'network_size': 'Invalid',
            'wildcard_mask': 'Invalid'
        }

def format_mac_address(mac: str) -> str:
    """Format MAC address to standard format."""
    # Remove all non-alphanumeric characters
    cleaned = re.sub(r'[^a-fA-F0-9]', '', mac)
    
    if len(cleaned) != 12:
        return ""
    
    # Format as XX:XX:XX:XX:XX:XX
    formatted = ':'.join([cleaned[i:i+2] for i in range(0, 12, 2)])
    return formatted.upper()

def validate_domain_name(domain: str) -> bool:
    """Validate if the given string is a valid domain name."""
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    return bool(pattern.match(domain)) and len(domain) <= 253

def get_ip_info(ip: str) -> Dict[str, str]:
    """Get comprehensive information about an IP address."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        class_info = get_ip_class(ip)
        
        info = {
            'ip_address': ip,
            'version': f"IPv{ip_obj.version}",
            'class': class_info['class'],
            'type': 'Private' if ip_obj.is_private else 'Public',
            'is_loopback': str(ip_obj.is_loopback),
            'is_multicast': str(ip_obj.is_multicast),
            'is_reserved': str(ip_obj.is_reserved),
            'binary': ip_to_binary(ip),
            'default_mask': class_info['default_mask']
        }
        
        return info
    except:
        return {'error': 'Invalid IP address'}

def ping_host(hostname: str) -> bool:
    """Simple ping test to check if host is reachable."""
    import subprocess
    import platform
    
    try:
        # Determine ping command based on OS
        if platform.system().lower() == 'windows':
            cmd = ['ping', '-n', '1', hostname]
        else:
            cmd = ['ping', '-c', '1', hostname]
        
        result = subprocess.run(cmd, capture_output=True, timeout=5)
        return result.returncode == 0
    except:
        return False
