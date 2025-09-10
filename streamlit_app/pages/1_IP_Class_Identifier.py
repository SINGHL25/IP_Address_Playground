
import streamlit as st
from src.ip_class_identifier import identify_ip_class




def main():
st.header("IP Class Identifier")
ip = st.text_input("Enter an IPv4 address", "192.168.1.1")
if st.button("Identify"):
try:
cls = identify_ip_class(ip)
st.success(f"{ip} is Class {cls}")
except ValueError as e:
st.error(str(e))
