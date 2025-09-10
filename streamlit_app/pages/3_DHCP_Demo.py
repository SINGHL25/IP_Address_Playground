
import streamlit as st
import sys
import os
import ipaddress
import random
import time
from datetime import datetime, timedelta

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dhcp_allocator import DHCPAllocator
from utils.helpers import validate_ip_address, format_mac_address

def main():
    st.set_page_config(
        page_title="DHCP Demo",
        page_icon="📡",
        layout="wide"
    )
    
    st.title("📡 DHCP Demo & Simulator")
    st.markdown("---")
    
    st.markdown("""
    ## Dynamic Host Configuration Protocol (DHCP) Simulator
    
    This demo shows how DHCP works to automatically assign IP addresses to devices on a network.
    """)
    
    # Initialize DHCP allocator in session state
    if 'dhcp_allocator' not in st.session_state:
        st.session_state.dhcp_allocator = DHCPAllocator()
        st.session_state.dhcp_allocator.configure_pool("192.168.1.0", "255.255.255.0", "192.168.1.100", "192.168.1.200")
    
    # DHCP Configuration Section
    st.markdown("## ⚙️ DHCP Server Configuration")
    
    config_col1, config_col2 = st.columns(2)
    
    with config_col1:
        st.subheader("Pool Configuration")
        
        network_ip = st.text_input(
            "Network Address:",
            value="192.168.1.0",
            help="Base network address"
        )
        
        subnet_mask = st.text_input(
            "Subnet Mask:",
            value="255.255.255.0",
            help="Network subnet mask"
        )
        
        start_ip = st.text_input(
            "Pool Start IP:",
            value="192.168.1.100",
            help="First IP address in the pool"
        )
        
        end_ip = st.text_input(
            "Pool End IP:",
            value="192.168.1.200",
            help="Last IP address in the pool"
        )
        
        if st.button("🔄 Configure Pool", type="primary"):
            try:
                st.session_state.dhcp_allocator.configure_pool(network_ip, subnet_mask, start_ip, end_ip)
                st.success("✅ DHCP pool configured successfully!")
            except Exception as e:
                st.error(f"❌ Configuration error: {str(e)}")
    
    with config_col2:
        st.subheader("DHCP Options")
        
        gateway = st.text_input(
            "Default Gateway:",
            value="192.168.1.1",
            help="Router IP address"
        )
        
        dns_primary = st.text_input(
            "Primary DNS:",
            value="8.8.8.8",
            help="Primary DNS server"
        )
        
        dns_secondary = st.text_input(
            "Secondary DNS:",
            value="8.8.4.4",
            help="Secondary DNS server"
        )
        
        lease_time = st.selectbox(
            "Lease Time:",
            ["1 hour", "8 hours", "24 hours", "7 days"],
            index=2,
            help="How long the IP address lease lasts"
        )
        
        # Update DHCP options
        if st.button("💾 Update Options"):
            options = {
                'gateway': gateway,
                'dns_servers': [dns_primary, dns_secondary],
                'lease_time': lease_time
            }
            st.session_state.dhcp_allocator.set_options(options)
            st.success("✅ DHCP options updated!")
    
    # Client Simulation Section
    st.markdown("---")
    st.markdown("## 🖥️ Client Device Simulation")
    
    client_col1, client_col2 = st.columns([1, 2])
    
    with client_col1:
        st.subheader("Add New Device")
        
        device_name = st.text_input(
            "Device Name:",
            value=f"Device-{random.randint(1000, 9999)}",
            help="Friendly name for the device"
        )
        
        mac_address = st.text_input(
            "MAC Address:",
            value=":".join([f"{random.randint(0, 255):02x}" for _ in range(6)]),
            help="Device MAC address (auto-generated)"
        )
        
        device_type = st.selectbox(
            "Device Type:",
            ["Laptop", "Desktop", "Smartphone", "Tablet", "Printer", "IoT Device", "Server"],
            help="Type of device requesting IP"
        )
        
        col_request, col_release = st.columns(2)
        
        with col_request:
            if st.button("📱 Request IP", type="primary"):
                try:
                    formatted_mac = format_mac_address(mac_address)
                    if formatted_mac:
                        lease_info = st.session_state.dhcp_allocator.request_ip(formatted_mac, device_name, device_type)
                        if lease_info:
                            st.success(f"✅ IP assigned: {lease_info['ip_address']}")
                        else:
                            st.error("❌ No available IP addresses in pool")
                    else:
                        st.error("❌ Invalid MAC address format")
                except Exception as e:
                    st.error(f"❌ Request failed: {str(e)}")
        
        with col_release:
            if st.button("🔄 Generate New MAC"):
                st.rerun()
    
    with client_col2:
        st.subheader("📊 Current DHCP Leases")
        
        leases = st.session_state.dhcp_allocator.get_active_leases()
        
        if leases:
            # Display leases in a table format
            lease_data = []
            for lease in leases:
                lease_data.append({
                    "Device": lease.get('device_name', 'Unknown'),
                    "IP Address": lease.get('ip_address', ''),
                    "MAC Address": lease.get('mac_address', ''),
                    "Type": lease.get('device_type', 'Unknown'),
                    "Lease Time": lease.get('lease_expires', 'N/A'),
                    "Status": "Active" if lease.get('active', False) else "Expired"
                })
            
            st.dataframe(lease_data, use_container_width=True)
            
            # Pool utilization
            pool_stats = st.session_state.dhcp_allocator.get_pool_stats()
            
            util_col1, util_col2, util_col3 = st.columns(3)
            with util_col1:
                st.metric("Total Pool Size", pool_stats.get('total_addresses', 0))
            with util_col2:
                st.metric("Allocated", pool_stats.get('allocated', 0))
            with util_col3:
                st.metric("Available", pool_stats.get('available', 0))
            
            # Show utilization percentage
            if pool_stats.get('total_addresses', 0) > 0:
                utilization = (pool_stats.get('allocated', 0) / pool_stats.get('total_addresses', 1)) * 100
                st.progress(utilization / 100)
                st.write(f"Pool Utilization: {utilization:.1f}%")
        else:
            st.info("No active DHCP leases. Add a device to see lease information.")
    
    # DHCP Process Visualization
    st.markdown("---")
    st.markdown("## 🔄 DHCP Process Flow")
    
    process_col1, process_col2 = st.columns(2)
    
    with process_col1:
        st.markdown("### The DHCP 4-Step Process (DORA)")
        
        steps = [
            ("1️⃣ **DISCOVER**", "Client broadcasts request for IP address"),
            ("2️⃣ **OFFER**", "DHCP server offers available IP address"),
            ("3️⃣ **REQUEST**", "Client requests the offered IP address"),
            ("4️⃣ **ACKNOWLEDGE**", "Server confirms and assigns the IP address")
        ]
        
        for step, description in steps:
            st.markdown(f"{step}")
            st.write(f"   {description}")
            st.markdown("")
    
    with process_col2:
        st.markdown("### Simulate DHCP Process")
        
        if st.button("▶️ Simulate DORA Process", type="secondary"):
            # Create a progress simulation
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            messages = [
                "Client broadcasts DHCP DISCOVER...",
                "Server receives DISCOVER, preparing OFFER...",
                "Server sends DHCP OFFER to client...",
                "Client sends DHCP REQUEST...",
                "Server sends DHCP ACK, lease complete!"
            ]
            
            for i, message in enumerate(messages):
                status_text.text(message)
                progress_bar.progress((i + 1) / len(messages))
                time.sleep(1)
            
            status_text.text("✅ DHCP process completed successfully!")
    
    # Lease Management
    st.markdown("---")
    st.markdown("## 🛠️ Lease Management")
    
    mgmt_col1, mgmt_col2 = st.columns(2)
    
    with mgmt_col1:
        st.subheader("Release IP Address")
        
        active_leases = st.session_state.dhcp_allocator.get_active_leases()
        if active_leases:
            lease_options = [f"{lease.get('device_name', 'Unknown')} ({lease.get('ip_address', '')})" 
                           for lease in active_leases]
            
            selected_lease = st.selectbox(
                "Select device to release:",
                lease_options,
                help="Choose a device to release its IP address"
            )
            
            if st.button("🔓 Release IP", type="secondary"):
                # Extract IP from selection
                ip_to_release = selected_lease.split('(')[1].split(')')[0]
                if st.session_state.dhcp_allocator.release_ip(ip_to_release):
                    st.success(f"✅ Released IP address: {ip_to_release}")
                    st.rerun()
                else:
                    st.error("❌ Failed to release IP address")
        else:
            st.info("No active leases to release.")
    
    with mgmt_col2:
        st.subheader("Pool Management")
        
        if st.button("🗑️ Clear All Leases"):
            st.session_state.dhcp_allocator.clear_all_leases()
            st.success("✅ All leases cleared!")
            st.rerun()
        
        if st.button("📊 Refresh Statistics"):
            st.rerun()
        
        st.markdown("### Reservation Management")
        reserve_ip = st.text_input("Reserve IP for MAC:", help="IP address to reserve")
        reserve_mac = st.text_input("MAC Address:", help="MAC address for reservation")
        
        if st.button("📌 Add Reservation"):
            if validate_ip_address(reserve_ip) and format_mac_address(reserve_mac):
                # Add reservation logic here
                st.success(f"✅ Reserved {reserve_ip} for {format_mac_address(reserve_mac)}")
            else:
                st.error("❌ Invalid IP address or MAC address format")
    
    # Educational Section
    st.markdown("---")
    st.markdown("## 📚 DHCP Configuration Reference")
    
    ref_col1, ref_col2 = st.columns(2)
    
    with ref_col1:
        st.markdown("### Common DHCP Options")
        
        dhcp_options = [
            ("Option 1", "Subnet Mask"),
            ("Option 3", "Default Gateway/Router"),
            ("Option 6", "DNS Servers"),
            ("Option 15", "Domain Name"),
            ("Option 51", "IP Address Lease Time"),
            ("Option 54", "DHCP Server Identifier"),
            ("Option 121", "Classless Static Routes")
        ]
        
        for option, description in dhcp_options:
            st.write(f"**{option}:** {description}")
    
    with ref_col2:
        st.markdown("### DHCP Message Types")
        
        message_types = [
            ("DHCPDISCOVER", "Client seeks DHCP server"),
            ("DHCPOFFER", "Server offers configuration"),
            ("DHCPREQUEST", "Client requests configuration"),
            ("DHCPACK", "Server acknowledges request"),
            ("DHCPNAK", "Server denies request"),
            ("DHCPRELEASE", "Client releases IP address"),
            ("DHCPINFORM", "Client requests local config only")
        ]
        
        for msg_type, description in message_types:
            st.write(f"**{msg_type}:** {description}")
    
    # Tips and Best Practices
    st.markdown("### 💡 DHCP Best Practices")
    
    st.markdown("""
    **Configuration Tips:**
    - Set appropriate lease times (24 hours for most networks)
    - Reserve IP addresses for servers and network devices
    - Monitor pool utilization to avoid exhaustion
    - Use DHCP reservations for devices that need consistent IPs
    - Configure redundant DHCP servers for high availability
    
    **Security Considerations:**
    - Enable DHCP snooping on managed switches
    - Use port security to prevent rogue DHCP servers
    - Monitor for unusual DHCP activity
    - Consider MAC address filtering for sensitive networks
    """)

if __name__ == "__main__":
    main()
