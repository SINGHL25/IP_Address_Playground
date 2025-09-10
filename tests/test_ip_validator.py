
from src.ip_validator import validate_ipv4, validate_ipv6




def test_validate_ipv4():
assert validate_ipv4('192.168.1.1')
assert not validate_ipv4('300.1.1.1')




def test_validate_ipv6():
assert validate_ipv6('2001:0db8::1')
assert not validate_ipv6('not_an_ip')
