
import streamlit as st
from src.subnet_visualizer import summarize_subnet




def main():
st.header("Subnet Calculator")
with st.form("subnet_form"):
ip = st.text_input("IP (IPv4)", "192.168.1.100")
mask = st.text_input("Subnet mask or CIDR", "/24")
submitted = st.form_submit_button("Calculate")
if submitted:
try:
info = summarize_subnet(ip, mask)
for k, v in info.items():
st.write(f"**{k}:** {v}")
except Exception as e:
st.error(e)
