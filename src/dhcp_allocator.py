from ipaddress import IPv4Address
import random

class DHCPPool:
    # ...your same implementation as above...

class DHCPAllocator:
    """
    Wrapper for DHCPPool, provides higher-level API.
    """
    def __init__(self):
        self.pool = None

    def configure_pool(self, start_ip, end_ip):
        self.pool = DHCPPool(start_ip, end_ip)

    def request_ip(self, client_id=None):
        if self.pool:
            return self.pool.request_ip(client_id)
        return None

    def release(self, ip_str):
        if self.pool:
            return self.pool.release(ip_str)
        return False

    def release_random(self):
        if self.pool:
            return self.pool.release_random()
        return None

    def status(self):
        if self.pool:
            return self.pool.status()
        return {}
