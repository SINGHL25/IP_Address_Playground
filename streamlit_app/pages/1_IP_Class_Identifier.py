
import streamlit as st
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.helpers import validate_ip_address, get_ip_class, get_ip_info, is_private_ip, is_loopback_ip
from ip_class_identifier import IPClassIdentifier

def main():
    st.set_page_config(
        page_title="IP Class Identifier",
        page_icon="🔍",
        layout="wide"
    )
    
    st.title("🔍 IP Class Identifier")
    st.markdown("---")
    
    st.markdown("""
    ## About IP Address Classes
    
    IP addresses are divided into different classes based on their first octet:
    - **Class A**: 1-126 (Default mask: /8)
    - **Class B**: 128-191 (Default mask: /16) 
    - **Class C**: 192-223 (Default mask: /24)
    - **Class D**: 224-239 (Multicast)
    - **Class E**: 240-255 (Experimental)
    """)
    
    # Create two columns for input and results
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.subheader("Enter IP Address")
        ip_input = st.text_input(
            "IP Address:",
            value="192.168.1.1",
            help="Enter an IPv4 address (e.g., 192.168.1.1)"
        )
        
        analyze_button = st.button("🔍 Analyze IP", type="primary")
        
        # Sample IP addresses for quick testing
        st.markdown("### Quick Test IPs:")
        sample_ips = [
            "10.0.0.1",
            "172.16.0.1", 
            "192.168.1.1",
            "8.8.8.8",
            "127.0.0.1",
            "224.0.0.1"
        ]
        
        for sample_ip in sample_ips:
            if st.button(f"Test {sample_ip}", key=f"test_{sample_ip}"):
                st.session_state.test_ip = sample_ip
                st.rerun()
    
    with col2:
        # Check if there's a test IP to analyze
        if hasattr(st.session_state, 'test_ip'):
            ip_input = st.session_state.test_ip
            delattr(st.session_state, 'test_ip')
        
        if ip_input and (analyze_button or ip_input):
            if validate_ip_address(ip_input):
                # Create identifier instance
                identifier = IPClassIdentifier()
                
                # Get comprehensive IP information
                ip_info = get_ip_info(ip_input)
                class_info = get_ip_class(ip_input)
                
                st.subheader("📊 Analysis Results")
                
                # Display basic info in metrics
                metric_cols = st.columns(4)
                with metric_cols[0]:
                    st.metric("IP Class", class_info['class'])
                with metric_cols[1]:
                    st.metric("Type", "Private" if is_private_ip(ip_input) else "Public")
                with metric_cols[2]:
                    st.metric("Version", ip_info['version'])
                with metric_cols[3]:
                    st.metric("Loopback", "Yes" if is_loopback_ip(ip_input) else "No")
                
                # Detailed information
                st.markdown("### 📋 Detailed Information")
                
                info_col1, info_col2 = st.columns(2)
                
                with info_col1:
                    st.markdown("**Basic Properties:**")
                    st.write(f"**IP Address:** {ip_input}")
                    st.write(f"**Class:** {class_info['class']}")
                    st.write(f"**Range:** {class_info['range']}")
                    st.write(f"**Default Mask:** {class_info['default_mask']}")
                    
                    if class_info['class'] in ['A', 'B', 'C']:
                        st.write(f"**Default CIDR:** /{class_info['cidr']}")
                
                with info_col2:
                    st.markdown("**Network Properties:**")
                    if class_info['class'] in ['A', 'B', 'C']:
                        st.write(f"**Possible Networks:** {class_info['networks']:,}")
                        st.write(f"**Hosts per Network:** {class_info['hosts_per_network']:,}")
                    
                    st.write(f"**Private IP:** {'Yes' if is_private_ip(ip_input) else 'No'}")
                    st.write(f"**Loopback:** {'Yes' if is_loopback_ip(ip_input) else 'No'}")
                    st.write(f"**Multicast:** {ip_info.get('is_multicast', 'No')}")
                
                # Binary representation
                st.markdown("### 🔢 Binary Representation")
                st.code(ip_info['binary'], language="text")
                
                # Special IP ranges information
                st.markdown("### 🏷️ Special IP Address Ranges")
                
                special_ranges = {
                    "Private Ranges": [
                        "10.0.0.0/8 (Class A)",
                        "172.16.0.0/12 (Class B)", 
                        "192.168.0.0/16 (Class C)"
                    ],
                    "Reserved Ranges": [
                        "127.0.0.0/8 (Loopback)",
                        "169.254.0.0/16 (Link-local)",
                        "224.0.0.0/4 (Multicast)",
                        "240.0.0.0/4 (Experimental)"
                    ]
                }
                
                range_col1, range_col2 = st.columns(2)
                
                with range_col1:
                    st.markdown("**Private Ranges:**")
                    for range_info in special_ranges["Private Ranges"]:
                        st.write(f"• {range_info}")
                
                with range_col2:
                    st.markdown("**Reserved Ranges:**")
                    for range_info in special_ranges["Reserved Ranges"]:
                        st.write(f"• {range_info}")
                
                # Additional analysis using the identifier class
                identifier_results = identifier.identify_class(ip_input)
                
                if identifier_results:
                    st.markdown("### 🎯 Advanced Analysis")
                    
                    if identifier_results.get('subnetting_info'):
                        st.markdown("**Subnetting Capabilities:**")
                        subnetting = identifier_results['subnetting_info']
                        st.write(f"• Can be subnetted into smaller networks")
                        st.write(f"• Maximum subnets with default mask: {subnetting.get('max_subnets', 'N/A')}")
                
            else:
                st.error("❌ Invalid IP address format. Please enter a valid IPv4 address.")
        else:
            st.info("👆 Enter an IP address above and click 'Analyze IP' to see detailed information.")
    
    # Educational section
    st.markdown("---")
    st.markdown("## 📚 IP Address Class Reference")
    
    # Class comparison table
    class_data = {
        "Class": ["A", "B", "C", "D", "E"],
        "First Octet Range": ["1-126", "128-191", "192-223", "224-239", "240-255"],
        "Default Mask": ["255.0.0.0 (/8)", "255.255.0.0 (/16)", "255.255.255.0 (/24)", "N/A (Multicast)", "N/A (Experimental)"],
        "Network Bits": ["8", "16", "24", "N/A", "N/A"],
        "Host Bits": ["24", "16", "8", "N/A", "N/A"],
        "Max Networks": ["126", "16,384", "2,097,152", "N/A", "N/A"],
        "Max Hosts per Network": ["16,777,214", "65,534", "254", "N/A", "N/A"]
    }
    
    st.table(class_data)
    
    # Tips section
    st.markdown("### 💡 Tips")
    st.markdown("""
    - **Class A** networks are used for very large networks
    - **Class B** networks are used for medium-sized networks  
    - **Class C** networks are used for small networks
    - **Class D** addresses are used for multicast communication
    - **Class E** addresses are reserved for experimental use
    - The first octet determines the class of an IP address
    - Private IP ranges can be used within local networks
    """)

if __name__ == "__main__":
    main()
