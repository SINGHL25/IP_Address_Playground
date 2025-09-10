from ipaddress import IPv4Address, IPv4Network
import random


class DHCPPool:
"""
Simple DHCP pool simulator. Tracks allocated IPs and free IP list.
"""
def __init__(self, start_ip: str, end_ip: str):
s = IPv4Address(start_ip)
e = IPv4Address(end_ip)
if int(e) < int(s):
raise ValueError("End IP must be >= start IP")
self.start = s
self.end = e
# build pool
self._all_ips = [IPv4Address(int(s) + i) for i in range(int(e) - int(s) + 1)]
self._free = set(self._all_ips)
self._allocated = {}


def request_ip(self, client_id: str = None):
if not self._free:
return None
ip = sorted(self._free)[0]
self._free.remove(ip)
key = client_id or str(ip)
self._allocated[key] = ip
return str(ip)


def release(self, ip_str: str):
ip = IPv4Address(ip_str)
if ip in self._allocated.values():
# remove by value
keys = [k for k, v in self._allocated.items() if v == ip]
for k in keys:
del self._allocated[k]
self._free.add(ip)
return True
return False


def release_random(self):
if not self._allocated:
return None
key = random.choice(list(self._allocated.keys()))
ip = self._allocated[key]
del self._allocated[key]
self._free.add(ip)
return str(ip)


def status(self):
return {
'total': len(self._all_ips),
'allocated': len(self._allocated),
'free': len(self._free),
}
