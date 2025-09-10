
from src.subnet_visualizer import summarize_subnet




def test_summarize_subnet():
info = summarize_subnet('192.168.1.10', '/28')
assert info['prefixlen'] == 28
assert info['num_addresses'] == 16
assert info['network'] == '192.168.1.0'
