import streamlit as st


PAGES = {
"IP Class Identifier": "pages/1_IP_Class_Identifier",
"Subnet Calculator": "pages/2_Subnet_Calculator",
"DHCP Demo": "pages/3_DHCP_Demo",
"DNS Resolver": "pages/4_DNS_Resolver",
"IP Ecosystem": "pages/5_IP_Ecosystem",
}




def sidebar_nav():
st.sidebar.title("Navigation")
choice = st.sidebar.radio("Pages", list(PAGES.keys()))


# import the selected page module dynamically
module_path = PAGES[choice]
try:
page = __import__(module_path.replace('/', '.'), fromlist=["*"])
page.main()
except Exception as e:
st.error(f"Could not load page {choice}: {e}")
