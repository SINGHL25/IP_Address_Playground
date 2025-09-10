
import streamlit as st
from src.dhcp_allocator import DHCPPool




def main():
st.header("DHCP Allocation Demo")
pool_start = st.text_input("Pool start (e.g., 192.168.1.10)", "192.168.1.10")
pool_end = st.text_input("Pool end (e.g., 192.168.1.50)", "192.168.1.50")


if st.button("Create Pool"):
try:
pool = DHCPPool(pool_start, pool_end)
st.session_state['dhcp_pool'] = pool
st.success("DHCP pool created")
except Exception as e:
st.error(e)


if st.button("Request IP"):
pool = st.session_state.get('dhcp_pool')
if not pool:
st.warning("Create a DHCP pool first")
else:
ip = pool.request_ip()
if ip:
st.info(f"Allocated IP: {ip}")
else:
st.error("No available IPs in pool")


if st.button("Release Random IP"):
pool = st.session_state.get('dhcp_pool')
if not pool:
st.warning("Create a DHCP pool first")
else:
released = pool.release_random()
if released:
st.info(f"Released IP: {released}")
else:
st.warning("No IP to release")
