
import streamlit as st
from src.dns_resolver import resolve_name




def main():
st.header("DNS Resolver")
name = st.text_input("Enter domain or hostname", "example.com")
if st.button("Resolve"):
try:
records = resolve_name(name)
st.write(records)
except Exception as e:
st.error(e)
