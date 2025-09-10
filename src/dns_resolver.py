
import socket
from typing import Dict, List




def resolve_name(name: str) -> Dict[str, List[str]]:
"""
Resolve a hostname to A records and attempt to get mail exchanger (MX) via getaddrinfo.
Returns dict with 'A' and 'other' keys.
"""
result = {'A': [], 'canonical_name': None, 'other': []}
try:
# gethostbyname_ex returns (hostname, aliaslist, ipaddrlist)
host, aliases, ips = socket.gethostbyname_ex(name)
result['canonical_name'] = host
result['A'] = ips
except socket.gaierror as e:
raise ValueError(f"DNS resolution failed: {e}")


# try getaddrinfo for additional records
try:
infos = socket.getaddrinfo(name, None)
others = set()
for info in infos:
others.add(info[4][0])
result['other'] = sorted(list(others))
except Exception:
pass


return result
