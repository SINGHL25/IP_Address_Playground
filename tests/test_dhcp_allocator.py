
from src.dhcp_allocator import DHCPPool




def test_dhcp_alloc_release():
pool = DHCPPool('192.168.1.10', '192.168.1.12')
ip1 = pool.request_ip('client1')
ip2 = pool.request_ip('client2')
assert ip1 != ip2
status = pool.status()
assert status['allocated'] == 2
released = pool.release(ip1)
assert released is True
status2 = pool.status()
assert status2['allocated'] == 1
