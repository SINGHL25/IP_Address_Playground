
import streamlit as st
import sys
import os

# Add the current directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def main():
    st.set_page_config(
        page_title="Network Tools Suite",
        page_icon="🌐",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    st.title("🌐 Network Tools Suite")
    st.markdown("---")
    
    st.markdown("""
    ## Welcome to the Network Tools Suite!
    
    This application provides comprehensive networking tools and educational resources:
    
    ### 📋 Available Tools:
    
    1. **🔍 IP Class Identifier** - Identify IP address classes and analyze network properties
    2. **🧮 Subnet Calculator** - Calculate subnet masks, network ranges, and host counts
    3. **📡 DHCP Demo** - Demonstrate DHCP allocation and management
    4. **🌐 DNS Resolver** - Resolve domain names and analyze DNS records
    5. **🗺️ IP Ecosystem** - Visualize network topology and IP relationships
    
    ### 🚀 Getting Started:
    
    Navigate through the pages using the sidebar to access different networking tools.
    Each tool is designed to be educational and practical for network administrators,
    students, and IT professionals.
    
    ### 📚 Educational Features:
    
    - Interactive network calculations
    - Real-time DNS resolution
    - DHCP simulation environment
    - Visual network representations
    - Comprehensive IP analysis
    
    **Select a tool from the sidebar to begin!**
    """)
    
    # Display some quick stats or info
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.info("🔢 **IP Analysis**\nClassify and analyze IP addresses")
    
    with col2:
        st.success("⚡ **Real-time Tools**\nLive DNS resolution and calculations")
    
    with col3:
        st.warning("🎓 **Educational**\nLearn networking concepts interactively")

if __name__ == "__main__":
    main()
