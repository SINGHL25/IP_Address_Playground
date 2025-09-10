"""
DHCP Allocator Module

This module simulates DHCP (Dynamic Host Configuration Protocol) functionality
including IP address allocation, lease management, and DHCP options configuration.
"""

import ipaddress
import random
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union, Any
from utils.helpers import validate_ip_address, format_mac_address

class DHCPAllocator:
    """
    A comprehensive DHCP server simulator that handles IP address allocation,
    lease management, reservations, and DHCP options configuration.
    """
    
    def __init__(self):
        """Initialize the DHCP allocator with default settings."""
        self.pool_start = None
        self.pool_end = None
        self.network = None
        self.subnet_mask = None
        self.available_ips = []
        self.allocated_leases = {}
        self.reservations = {}
        self.dhcp_options = {
            'gateway': '192.168.1.1',
            'dns_servers': ['8.8.8.8', '8.8.4.4'],
            'domain_name': 'local',
            'lease_time': '24 hours',
            'renewal_time': '12 hours',
            'rebinding_time': '21 hours'
        }
        self.server_identifier = '192.168.1.1'
        self.lease_database = []
        
    def configure_pool(self, network_ip: str, subnet_mask: str, start_ip: str, end_ip: str) -> bool:
        """
        Configure the DHCP address pool.
        
        Args:
            network_ip (str): Network address
            subnet_mask (str): Subnet mask
            start_ip (str): First IP in the pool
            end_ip (str): Last IP in the pool
            
        Returns:
            bool: True if configuration successful, False otherwise
        """
        try:
            # Validate all IP addresses
            if not all(validate_ip_address(ip) for ip in [network_ip, start_ip, end_ip]):
                raise ValueError("Invalid IP address format")
            
            # Create network object for validation
            network = ipaddress.ip_network(f"{network_ip}/{self._mask_to_cidr(subnet_mask)}", strict=False)
            start_obj = ipaddress.ip_address(start_ip)
            end_obj = ipaddress.ip_address(end_ip)
            
            # Validate that start and end IPs are within the network
            if start_obj not in network or end_obj not network:
                raise ValueError("Pool range is outside the specified network")
            
            if start_obj >= end_obj:
                raise ValueError("Start IP must be less than end IP")
            
            # Configure the pool
            self.network = network
            self.subnet_mask = subnet_mask
            self.pool_start = start_obj
            self.pool_end = end_obj
            
            # Generate list of available IP addresses
            self.available_ips = []
            current_ip = int(start_obj)
            end_ip_int = int(end_obj)
            
            while current_ip <= end_ip_int:
                ip_addr = str(ipaddress.ip_address(current_ip))
                # Skip network and broadcast addresses
                if ip_addr != str(network.network_address) and ip_addr != str(network.broadcast_address):
                    self.available_ips.append(ip_addr)
                current_ip += 1
            
            return True
            
        except Exception as e:
            print(f"Error configuring DHCP pool: {str(e)}")
            return False
    
    def request_ip(self, mac_address: str, hostname: str = None, device_type: str = "Unknown") -> Optional[Dict]:
        """
        Process a DHCP request for an IP address.
        
        Args:
            mac_address (str): MAC address of requesting device
            hostname (str): Hostname of requesting device
            device_type (str): Type of device making the request
            
        Returns:
            Dict: Lease information if successful, None if failed
        """
        try:
            # Format MAC address
            formatted_mac = format_mac_address(mac_address)
            if not formatted_mac:
                raise ValueError("Invalid MAC address format")
            
            # Check if device already has a lease
            existing_lease = self._find_lease_by_mac(formatted_mac)
            if existing_lease and not self._is_lease_expired(existing_lease):
                # Renew existing lease
                return self._renew_lease(existing_lease)
            
            # Check for reservation
            if formatted_mac in self.reservations:
                reserved_ip = self.reservations[formatted_mac]
                if reserved_ip not in self.allocated_leases:
                    return self._create_lease(reserved_ip, formatted_mac, hostname, device_type, reserved=True)
            
            # Find available IP address
            available_ip = self._get_next_available_ip()
            if not available_ip:
                return None  # Pool exhausted
            
            # Create new lease
            return self._create_lease(available_ip, formatted_mac, hostname, device_type)
            
        except Exception as e:
            print(f"Error processing DHCP request: {str(e)}")
            return None
    
    def release_ip(self, ip_address: str) -> bool:
        """
        Release an IP address lease.
        
        Args:
            ip_address (str): IP address to release
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if ip_address in self.allocated_leases:
                lease_info = self.allocated_leases[ip_address]
                
                # Mark lease as expired
                lease_info['active'] = False
                lease_info['released_at'] = datetime.now()
                
                # Add back to available pool if not reserved
                if not lease_info.get('reserved', False):
                    if ip_address not in self.available_ips:
                        self.available_ips.append(ip_address)
                
                # Remove from allocated leases
                del self.allocated_leases[ip_address]
                
                # Update lease database
                self._update_lease_database(lease_info)
                
                return True
            
            return False
            
        except Exception as e:
            print(f"Error releasing IP address: {str(e)}")
            return False
    
    def set_options(self, options: Dict[str, Any]) -> bool:
        """
        Configure DHCP options.
        
        Args:
            options (Dict): Dictionary of DHCP options
            
        Returns:
            bool: True if successful
        """
        try:
            self.dhcp_options.update(options)
            return True
        except:
            return False
    
    def add_reservation(self, mac_address: str, ip_address: str) -> bool:
        """
        Add a DHCP reservation.
        
        Args:
            mac_address (str): MAC address
            ip_address (str): Reserved IP address
            
        Returns:
            bool: True if successful
        """
        try:
            formatted_mac = format_mac_address(mac_address)
            if not formatted_mac or not validate_ip_address(ip_address):
                return False
            
            # Check if IP is within pool range
            ip_obj = ipaddress.ip_address(ip_address)
            if not (self.pool_start <= ip_obj <= self.pool_end):
                return False
            
            self.reservations[formatted_mac] = ip_address
            
            # Remove from available IPs if present
            if ip_address in self.available_ips:
                self.available_ips.remove(ip_address)
            
            return True
            
        except:
            return False
    
    def remove_reservation(self, mac_address: str) -> bool:
        """
        Remove a DHCP reservation.
        
        Args:
            mac_address (str): MAC address
            
        Returns:
            bool: True if successful
        """
        try:
            formatted_mac = format_mac_address(mac_address)
            if formatted_mac in self.reservations:
                reserved_ip = self.reservations[formatted_mac]
                del self.reservations[formatted_mac]
                
                # Add back to available pool if not currently leased
                if reserved_ip not in self.allocated_leases and reserved_ip not in self.available_ips:
                    self.available_ips.append(reserved_ip)
                
                return True
            return False
            
        except:
            return False
    
    def get_active_leases(self) -> List[Dict]:
        """
        Get all active DHCP leases.
        
        Returns:
            List[Dict]: List of active lease information
        """
        active_leases = []
        current_time = datetime.now()
        
        for ip_address, lease_info in self.allocated_leases.items():
            if lease_info.get('active', True) and not self._is_lease_expired(lease_info):
                lease_data = lease_info.copy()
                lease_data['ip_address'] = ip_address
                
                # Calculate remaining lease time
                lease_expires = lease_info.get('lease_expires')
                if isinstance(lease_expires, datetime):
                    remaining_time = lease_expires - current_time
                    lease_data['remaining_time'] = str(remaining_time).split('.')[0]  # Remove microseconds
                
                active_leases.append(lease_data)
        
        return active_leases
    
    def get_pool_stats(self) -> Dict:
        """
        Get DHCP pool statistics.
        
        Returns:
            Dict: Pool statistics
        """
        if not self.available_ips and not self.allocated_leases:
            return {'total_addresses': 0, 'allocated': 0, 'available': 0, 'utilization': 0}
        
        total_pool_size = len(self.available_ips) + len(self.allocated_leases)
        if hasattr(self, 'pool_start') and hasattr(self, 'pool_end') and self.pool_start and self.pool_end:
            total_pool_size = int(self.pool_end) - int(self.pool_start) + 1
        
        allocated_count = len([lease for lease in self.allocated_leases.values() 
                              if lease.get('active', True) and not self._is_lease_expired(lease)])
        
        available_count = total_pool_size - allocated_count
        utilization = (allocated_count / total_pool_size * 100) if total_pool_size > 0 else 0
        
        return {
            'total_addresses': total_pool_size,
            'allocated': allocated_count,
            'available': available_count,
            'utilization': round(utilization, 2),
            'reservations': len(self.reservations)
        }
    
    def clear_all_leases(self) -> bool:
        """
        Clear all DHCP leases (for testing/reset purposes).
        
        Returns:
            bool: True if successful
        """
        try:
            # Move all allocated IPs back to available pool
            for ip_address, lease_info in self.allocated_leases.items():
                if not lease_info.get('reserved', False):
                    if ip_address not in self.available_ips:
                        self.available_ips.append(ip_address)
            
            self.allocated_leases.clear()
            return True
            
        except:
            return False
    
    def _find_lease_by_mac(self, mac_address: str) -> Optional[Dict]:
        """Find a lease by MAC address."""
        for ip_address, lease_info in self.allocated_leases.items():
            if lease_info.get('mac_address') == mac_address:
                lease_info['ip_address'] = ip_address
                return lease_info
        return None
    
    def _is_lease_expired(self, lease_info: Dict) -> bool:
        """Check if a lease has expired."""
        if 'lease_expires' not in lease_info:
            return False
        
        lease_expires = lease_info['lease_expires']
        if isinstance(lease_expires, str):
            try:
                lease_expires = datetime.fromisoformat(lease_expires)
            except:
                return False
        
        return datetime.now() > lease_expires
    
    def _renew_lease(self, lease_info: Dict) -> Dict:
        """Renew an existing lease."""
        lease_time_hours = self._parse_lease_time(self.dhcp_options.get('lease_time', '24 hours'))
        new_expiry = datetime.now() + timedelta(hours=lease_time_hours)
        
        lease_info['lease_expires'] = new_expiry
        lease_info['renewed_at'] = datetime.now()
        lease_info['renewal_count'] = lease_info.get('renewal_count', 0) + 1
        
        return lease_info
    
    def _create_lease(self, ip_address: str, mac_address: str, hostname: str = None, 
                     device_type: str = "Unknown", reserved: bool = False) -> Dict:
        """Create a new DHCP lease."""
        lease_time_hours = self._parse_lease_time(self.dhcp_options.get('lease_time', '24 hours'))
        
        lease_info = {
            'ip_address': ip_address,
            'mac_address': mac_address,
            'hostname': hostname or f"host-{mac_address.replace(':', '')}",
            'device_type': device_type,
            'lease_start': datetime.now(),
            'lease_expires': datetime.now() + timedelta(hours=lease_time_hours),
            'server_identifier': self.server_identifier,
            'subnet_mask': self.subnet_mask,
            'gateway': self.dhcp_options.get('gateway'),
            'dns_servers': self.dhcp_options.get('dns_servers', []),
            'domain_name': self.dhcp_options.get('domain_name'),
            'reserved': reserved,
            'active': True,
            'renewal_count': 0
        }
        
        # Remove from available pool
        if ip_address in self.available_ips:
            self.available_ips.remove(ip_address)
        
        # Add to allocated leases
        self.allocated_leases[ip_address] = lease_info
        
        # Update lease database
        self._update_lease_database(lease_info)
        
        return lease_info
    
    def _get_next_available_ip(self) -> Optional[str]:
        """Get the next available IP address from the pool."""
        if not self.available_ips:
            return None
        
        # Clean up expired leases first
        self._cleanup_expired_leases()
        
        if self.available_ips:
            return self.available_ips[0]
        
        return None
    
    def _cleanup_expired_leases(self):
        """Clean up expired leases and return IPs to available pool."""
        expired_ips = []
        
        for ip_address, lease_info in self.allocated_leases.items():
            if self._is_lease_expired(lease_info) and not lease_info.get('reserved', False):
                expired_ips.append(ip_address)
        
        for ip_address in expired_ips:
            # Mark as expired in database
            lease_info = self.allocated_leases[ip_address]
            lease_info['active'] = False
            lease_info['expired_at'] = datetime.now()
            self._update_lease_database(lease_info)
            
            # Remove from allocated and add back to available
            del self.allocated_leases[ip_address]
            if ip_address not in self.available_ips:
                self.available_ips.append(ip_address)
    
    def _parse_lease_time(self, lease_time_str: str) -> int:
        """Parse lease time string and return hours."""
        lease_time_str = lease_time_str.lower()
        
        if 'hour' in lease_time_str:
            try:
                return int(lease_time_str.split()[0])
            except:
                return 24
        elif 'day' in lease_time_str:
            try:
                return int(lease_time_str.split()[0]) * 24
            except:
                return 24
        elif 'week' in lease_time_str:
            try:
                return int(lease_time_str.split()[0]) * 24 * 7
            except:
                return 24
        else:
            return 24  # Default to 24 hours
    
    def _mask_to_cidr(self, subnet_mask: str) -> int:
        """Convert subnet mask to CIDR notation."""
        try:
            parts = subnet_mask.split('.')
            binary = ''.join([format(int(part), '08b') for part in parts])
            return binary.count('1')
        except:
            return 24  # Default to /24
    
    def _update_lease_database(self, lease_info: Dict):
        """Update the lease database with lease information."""
        # Convert datetime objects to strings for storage
        db_entry = lease_info.copy()
        
        for key, value in db_entry.items():
            if isinstance(value, datetime):
                db_entry[key] = value.isoformat()
        
        # Add to database (in real implementation, this would be persistent storage)
        self.lease_database.append(db_entry)
        
        # Keep only last 1000 entries to prevent memory issues
        if len(self.lease_database) > 1000:
            self.lease_database = self.lease_database[-1000:]
    
    def get_lease_history(self, mac_address: str = None) -> List[Dict]:
        """
        Get lease history for a specific MAC address or all leases.
        
        Args:
            mac_address (str): Optional MAC address filter
            
        Returns:
            List[Dict]: Lease history
        """
        if mac_address:
            formatted_mac = format_mac_address(mac_address)
            return [lease for lease in self.lease_database 
                   if lease.get('mac_address') == formatted_mac]
        
        return self.lease_database.copy()
    
    def simulate_dhcp_process(self, mac_address: str, hostname: str = None) -> Dict:
        """
        Simulate the complete DHCP DORA process.
        
        Args:
            mac_address (str): Client MAC address
            hostname (str): Client hostname
            
        Returns:
            Dict: DHCP process simulation results
        """
        simulation = {
            'process_steps': [],
            'success': False,
            'lease_info': None,
            'error': None
        }
        
        try:
            # Step 1: DHCP DISCOVER
            simulation['process_steps'].append({
                'step': 'DISCOVER',
                'description': 'Client broadcasts request for IP configuration',
                'timestamp': datetime.now().isoformat(),
                'client_mac': mac_address,
                'message': f'DHCPDISCOVER from {mac_address}'
            })
            
            # Step 2: DHCP OFFER
            available_ip = self._get_next_available_ip()
            if not available_ip:
                simulation['error'] = 'No available IP addresses in pool'
                return simulation
            
            simulation['process_steps'].append({
                'step': 'OFFER',
                'description': 'Server offers IP configuration to client',
                'timestamp': datetime.now().isoformat(),
                'offered_ip': available_ip,
                'message': f'DHCPOFFER {available_ip} to {mac_address}'
            })
            
            # Step 3: DHCP REQUEST
            simulation['process_steps'].append({
                'step': 'REQUEST',
                'description': 'Client requests the offered IP configuration',
                'timestamp': datetime.now().isoformat(),
                'requested_ip': available_ip,
                'message': f'DHCPREQUEST for {available_ip} from {mac_address}'
            })
            
            # Step 4: DHCP ACK
            lease_info = self._create_lease(available_ip, format_mac_address(mac_address), hostname)
            
            simulation['process_steps'].append({
                'step': 'ACK',
                'description': 'Server acknowledges and confirms IP assignment',
                'timestamp': datetime.now().isoformat(),
                'assigned_ip': available_ip,
                'lease_duration': self.dhcp_options.get('lease_time', '24 hours'),
                'message': f'DHCPACK {available_ip} to {mac_address}'
            })
            
            simulation['success'] = True
            simulation['lease_info'] = lease_info
            
        except Exception as e:
            simulation['error'] = str(e)
        
        return simulation
