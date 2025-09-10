import ipaddress




def identify_ip_class(ip: str) -> str:
"""
Identify IPv4 class (A-E) for a given IPv4 string.
Raises ValueError for invalid IPs or IPv6.
"""
try:
ip_obj = ipaddress.IPv4Address(ip)
except Exception:
raise ValueError("Invalid IPv4 address")


first_octet = int(str(ip).split('.')[0])
if 1 <= first_octet <= 126:
return 'A'
if 127 == first_octet:
return 'Loopback (127.x.x.x)'
if 128 <= first_octet <= 191:
return 'B'
if 192 <= first_octet <= 223:
return 'C'
if 224 <= first_octet <= 239:
return 'D (Multicast)'
if 240 <= first_octet <= 254:
return 'E (Reserved)'
return 'Unknown'
