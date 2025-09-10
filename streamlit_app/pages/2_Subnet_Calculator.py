
import streamlit as st
import sys
import os
import ipaddress

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.helpers import (
    validate_ip_address, validate_subnet_mask, calculate_network_info,
    cidr_to_subnet_mask, subnet_mask_to_cidr, ip_to_binary
)

def main():
    st.set_page_config(
        page_title="Subnet Calculator",
        page_icon="🧮",
        layout="wide"
    )
    
    st.title("🧮 Subnet Calculator")
    st.markdown("---")
    
    st.markdown("""
    ## Network Subnet Calculator
    
    Calculate network information, subnet details, and IP ranges for any given network.
    """)
    
    # Input section
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.subheader("Network Input")
        
        # IP Address input
        ip_input = st.text_input(
            "IP Address:",
            value="192.168.1.0",
            help="Enter the network or host IP address"
        )
        
        # Subnet mask input method selection
        mask_method = st.radio(
            "Subnet Mask Format:",
            ["CIDR Notation (/24)", "Dotted Decimal (255.255.255.0)"],
            index=0
        )
        
        if mask_method == "CIDR Notation (/24)":
            cidr_input = st.slider(
                "CIDR Prefix:",
                min_value=1,
                max_value=32,
                value=24,
                help="Number of network bits"
            )
            subnet_mask = cidr_to_subnet_mask(cidr_input)
        else:
            subnet_mask = st.text_input(
                "Subnet Mask:",
                value="255.255.255.0",
                help="Enter subnet mask in dotted decimal format"
            )
            cidr_input = subnet_mask_to_cidr(subnet_mask)
        
        calculate_btn = st.button("🧮 Calculate", type="primary")
        
        # Quick examples
        st.markdown("### Quick Examples:")
        examples = [
            ("192.168.1.0/24", "Small network"),
            ("10.0.0.0/8", "Large private network"),
            ("172.16.0.0/16", "Medium private network"),
            ("192.168.0.0/23", "Supernet example")
        ]
        
        for ip_cidr, description in examples:
            if st.button(f"{ip_cidr} ({description})", key=f"example_{ip_cidr}"):
                parts = ip_cidr.split('/')
                st.session_state.example_ip = parts[0]
                st.session_state.example_cidr = int(parts[1])
                st.rerun()
    
    with col2:
        # Handle examples
        if hasattr(st.session_state, 'example_ip'):
            ip_input = st.session_state.example_ip
            cidr_input = st.session_state.example_cidr
            subnet_mask = cidr_to_subnet_mask(cidr_input)
            delattr(st.session_state, 'example_ip')
            delattr(st.session_state, 'example_cidr')
        
        if ip_input and subnet_mask and (calculate_btn or ip_input):
            if validate_ip_address(ip_input):
                try:
                    # Calculate network information
                    network_info = calculate_network_info(ip_input, subnet_mask)
                    
                    st.subheader("📊 Network Information")
                    
                    # Key metrics
                    metric_cols = st.columns(4)
                    with metric_cols[0]:
                        st.metric("Network Address", network_info['network_address'])
                    with metric_cols[1]:
                        st.metric("Broadcast Address", network_info['broadcast_address'])
                    with metric_cols[2]:
                        st.metric("Total Hosts", network_info['total_hosts'])
                    with metric_cols[3]:
                        st.metric("CIDR", f"/{cidr_input}")
                    
                    # Detailed information
                    st.markdown("### 📋 Detailed Network Information")
                    
                    detail_col1, detail_col2 = st.columns(2)
                    
                    with detail_col1:
                        st.markdown("**Network Details:**")
                        st.write(f"**Network Address:** {network_info['network_address']}")
                        st.write(f"**Subnet Mask:** {subnet_mask}")
                        st.write(f"**CIDR Notation:** /{cidr_input}")
                        st.write(f"**Wildcard Mask:** {network_info['wildcard_mask']}")
                        st.write(f"**Network Size:** {network_info['network_size']} addresses")
                    
                    with detail_col2:
                        st.markdown("**Host Range:**")
                        st.write(f"**First Host:** {network_info['first_host']}")
                        st.write(f"**Last Host:** {network_info['last_host']}")
                        st.write(f"**Broadcast:** {network_info['broadcast_address']}")
                        st.write(f"**Usable Hosts:** {network_info['total_hosts']}")
                    
                    # Binary representation
                    st.markdown("### 🔢 Binary Representation")
                    
                    binary_col1, binary_col2 = st.columns(2)
                    
                    with binary_col1:
                        st.markdown("**Network Address:**")
                        st.code(ip_to_binary(network_info['network_address']))
                        
                        st.markdown("**Subnet Mask:**")
                        st.code(ip_to_binary(subnet_mask))
                    
                    with binary_col2:
                        st.markdown("**Broadcast Address:**")
                        st.code(ip_to_binary(network_info['broadcast_address']))
                        
                        st.markdown("**Wildcard Mask:**")
                        st.code(ip_to_binary(network_info['wildcard_mask']))
                    
                    # Subnetting analysis
                    if cidr_input < 30:  # Only show for networks that can be subnetted
                        st.markdown("### 🔀 Subnetting Analysis")
                        
                        subnet_col1, subnet_col2 = st.columns(2)
                        
                        with subnet_col1:
                            st.markdown("**Possible Subnets:**")
                            
                            # Show possible subnet divisions
                            possible_subnets = []
                            for new_cidr in range(cidr_input + 1, min(cidr_input + 5, 31)):
                                subnet_count = 2 ** (new_cidr - cidr_input)
                                hosts_per_subnet = (2 ** (32 - new_cidr)) - 2
                                possible_subnets.append({
                                    'cidr': new_cidr,
                                    'subnets': subnet_count,
                                    'hosts': hosts_per_subnet
                                })
                            
                            for subnet in possible_subnets:
                                st.write(f"**/{subnet['cidr']}:** {subnet['subnets']} subnets, {subnet['hosts']} hosts each")
                        
                        with subnet_col2:
                            st.markdown("**Sample Subnet Division (/25):**")
                            try:
                                # Show first few subnets when divided by /25 (if applicable)
                                if cidr_input < 25:
                                    network = ipaddress.ip_network(f"{network_info['network_address']}/{cidr_input}")
                                    subnets = list(network.subnets(new_prefix=min(25, cidr_input + 2)))[:4]
                                    
                                    for i, subnet in enumerate(subnets, 1):
                                        st.write(f"**Subnet {i}:** {subnet}")
                            except:
                                st.write("Cannot subnet further")
                    
                    # VLSM Calculator
                    st.markdown("### 📐 VLSM (Variable Length Subnet Mask) Helper")
                    
                    vlsm_col1, vlsm_col2 = st.columns(2)
                    
                    with vlsm_col1:
                        st.markdown("**Required Hosts:**")
                        required_hosts = st.number_input(
                            "Number of hosts needed:",
                            min_value=1,
                            max_value=2**30,
                            value=50,
                            help="Enter the number of hosts you need"
                        )
                        
                        # Calculate required subnet size
                        import math
                        host_bits = math.ceil(math.log2(required_hosts + 2))  # +2 for network and broadcast
                        required_cidr = 32 - host_bits
                        available_hosts = (2 ** host_bits) - 2
                        
                        st.write(f"**Recommended CIDR:** /{required_cidr}")
                        st.write(f"**Available Hosts:** {available_hosts}")
                        st.write(f"**Subnet Mask:** {cidr_to_subnet_mask(required_cidr)}")
                    
                    with vlsm_col2:
                        st.markdown("**Common Subnet Sizes:**")
                        common_sizes = [
                            ("/30", "2 hosts", "Point-to-point links"),
                            ("/29", "6 hosts", "Small office"),
                            ("/28", "14 hosts", "Small department"),
                            ("/27", "30 hosts", "Medium department"),
                            ("/26", "62 hosts", "Large department"),
                            ("/25", "126 hosts", "Small building"),
                            ("/24", "254 hosts", "Standard network")
                        ]
                        
                        for cidr, hosts, use_case in common_sizes:
                            st.write(f"**{cidr}:** {hosts} - {use_case}")
                    
                except Exception as e:
                    st.error(f"❌ Error calculating network information: {str(e)}")
            else:
                st.error("❌ Invalid IP address format. Please enter a valid IPv4 address.")
        else:
            st.info("👆 Enter network information above to calculate subnet details.")
    
    # Educational section
    st.markdown("---")
    st.markdown("## 📚 Subnetting Reference")
    
    # CIDR reference table
    st.markdown("### CIDR Notation Reference")
    
    cidr_data = {
        "CIDR": ["/24", "/25", "/26", "/27", "/28", "/29", "/30"],
        "Subnet Mask": ["255.255.255.0", "255.255.255.128", "255.255.255.192", 
                       "255.255.255.224", "255.255.255.240", "255.255.255.248", "255.255.255.252"],
        "Host Bits": ["8", "7", "6", "5", "4", "3", "2"],
        "Hosts per Subnet": ["254", "126", "62", "30", "14", "6", "2"],
        "Common Use": ["Standard LAN", "Medium subnet", "Small subnet", 
                      "Tiny subnet", "Very small", "Point-to-multipoint", "Point-to-point"]
    }
    
    st.table(cidr_data)
    
    # Subnetting tips
    st.markdown("### 💡 Subnetting Tips")
    
    tips_col1, tips_col2 = st.columns(2)
    
    with tips_col1:
        st.markdown("""
        **Key Concepts:**
        - Network address: First address in subnet
        - Broadcast address: Last address in subnet  
        - Host range: Addresses between network and broadcast
        - Subnet mask: Defines network vs host portion
        - CIDR notation: Shorthand for subnet mask (/24 = 255.255.255.0)
        """)
    
    with tips_col2:
        st.markdown("""
        **Calculation Rules:**
        - Hosts per subnet = 2^(host bits) - 2
        - Number of subnets = 2^(borrowed bits)
        - Always subtract 2 from total addresses (network + broadcast)
        - /30 subnets are perfect for point-to-point links
        - /24 is the most common subnet size
        """)
    
    # Advanced features
    st.markdown("### 🔧 Advanced Features")
    
    with st.expander("Subnet Aggregation (Supernetting)"):
        st.markdown("""
        **Route Aggregation Example:**
        
        If you have these networks:
        - 192.168.0.0/24
        - 192.168.1.0/24
        - 192.168.2.0/24  
        - 192.168.3.0/24
        
        They can be aggregated into: **192.168.0.0/22**
        
        This reduces routing table entries and improves efficiency.
        """)
    
    with st.expander("VLSM Design Guidelines"):
        st.markdown("""
        **Variable Length Subnet Masking (VLSM) Best Practices:**
        
        1. **Start with largest requirements first**
        2. **Use efficient subnet sizes** - don't waste addresses
        3. **Plan for growth** - leave room for expansion
        4. **Document your design** - maintain IP address management
        5. **Consider routing protocol requirements** - some don't support VLSM
        
        **Example VLSM Design:**
        - Main LAN: /24 (254 hosts)
        - Branch offices: /27 (30 hosts each)
        - Point-to-point links: /30 (2 hosts each)
        """)

if __name__ == "__main__":
    main()
