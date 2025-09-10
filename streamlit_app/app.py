
import streamlit as st
from streamlit_app.utils.helpers import sidebar_nav


st.set_page_config(layout="wide", page_title="IP Address Playground")


sidebar_nav()


st.title("IP Address Playground")
st.write("Welcome — use the left sidebar to navigate the learning tools and demos.")


st.markdown("---")


st.write("This playground includes: IP Class identification, Subnet Calculator, DHCP demo, DNS resolver, and an IP Ecosystem overview.")
