
import streamlit as st
import sys
import os
import json
import ipaddress
import random
from datetime import datetime

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.helpers import validate_ip_address, get_ip_class, calculate_network_info

def main():
    st.set_page_config(
        page_title="IP Ecosystem",
        page_icon="🗺️",
        layout="wide"
    )
    
    st.title("🗺️ IP Address Ecosystem Visualizer")
    st.markdown("---")
    
    st.markdown("""
    ## Network Topology & IP Address Management
    
    Visualize and manage IP address allocations, network relationships, and address space utilization.
    """)
    
    # Initialize ecosystem data
    if 'ip_ecosystem' not in st.session_state:
        st.session_state.ip_ecosystem = {
            'networks': [],
            'devices': [],
            'subnets': []
        }
    
    # Main sections
    tab1, tab2, tab3, tab4 = st.tabs(["🌐 Network Overview", "📊 IP Analytics", "🔧 Network Designer", "📈 Monitoring"])
    
    with tab1:
        st.markdown("## 🌐 Network Overview")
        
        overview_col1, overview_col2 = st.columns([1, 2])
        
        with overview_col1:
            st.subheader("Add Network")
            
            network_name = st.text_input(
                "Network Name:",
                value=f"Network-{len(st.session_state.ip_ecosystem['networks']) + 1}",
                help="Descriptive name for the network"
            )
            
            network_address = st.text_input(
                "Network Address:",
                value="192.168.1.0/24",
                help="Network in CIDR notation (e.g., 192.168.1.0/24)"
            )
            
            network_type = st.selectbox(
                "Network Type:",
                ["LAN", "WAN", "VLAN", "DMZ", "Management", "Guest"],
                help="Type/purpose of the network"
            )
            
            location = st.text_input(
                "Location:",
                value="Main Office",
                help="Physical location of the network"
            )
            
            if st.button("➕ Add Network", type="primary"):
                try:
                    # Validate network address
                    network = ipaddress.ip_network(network_address, strict=False)
                    
                    network_info = {
                        'name': network_name,
                        'address': network_address,
                        'type': network_type,
                        'location': location,
                        'network_obj': str(network.network_address),
                        'broadcast': str(network.broadcast_address),
                        'total_hosts': network.num_addresses - 2,
                        'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    st.session_state.ip_ecosystem['networks'].append(network_info)
                    st.success(f"✅ Added network: {network_name}")
                    st.rerun()
                    
                except Exception as e:
                    st.error(f"❌ Error adding network: {str(e)}")
        
        with overview_col2:
            st.subheader("📋 Current Networks")
            
            networks = st.session_state.ip_ecosystem['networks']
            
            if networks:
                for i, network in enumerate(networks):
                    with st.expander(f"🌐 {network['name']} ({network['address']})"):
                        info_col1, info_col2 = st.columns(2)
                        
                        with info_col1:
                            st.write(f"**Type:** {network['type']}")
                            st.write(f"**Location:** {network['location']}")
                            st.write(f"**Network:** {network['network_obj']}")
                            st.write(f"**Broadcast:** {network['broadcast']}")
                        
                        with info_col2:
                            st.write(f"**Total Hosts:** {network['total_hosts']:,}")
                            st.write(f"**Created:** {network['created_at']}")
                            
                            if st.button(f"🗑️ Delete", key=f"delete_network_{i}"):
                                st.session_state.ip_ecosystem['networks'].pop(i)
                                st.rerun()
                        
                        # Show utilization (simulated)
                        utilization = random.randint(10, 90)
                        st.progress(utilization / 100)
                        st.write(f"Utilization: {utilization}%")
                
                # Network summary
                st.markdown("### 📊 Network Summary")
                
                summary_col1, summary_col2, summary_col3 = st.columns(3)
                
                with summary_col1:
                    st.metric("Total Networks", len(networks))
                
                with summary_col2:
                    total_hosts = sum(net['total_hosts'] for net in networks)
                    st.metric("Total IP Addresses", f"{total_hosts:,}")
                
                with summary_col3:
                    network_types = list(set(net['type'] for net in networks))
                    st.metric("Network Types", len(network_types))
                
            else:
                st.info("No networks configured. Add a network to get started.")
    
    with tab2:
        st.markdown("## 📊 IP Address Analytics")
        
        if st.session_state.ip_ecosystem['networks']:
            
            # IP Address Distribution Analysis
            st.subheader("🎯 IP Address Distribution")
            
            dist_col1, dist_col2 = st.columns(2)
            
            with dist_col1:
                st.markdown("### Network Class Distribution")
                
                class_counts = {}
                for network in st.session_state.ip_ecosystem['networks']:
                    try:
                        ip_class = get_ip_class(network['network_obj'])['class']
                        class_counts[ip_class] = class_counts.get(ip_class, 0) + 1
                    except:
                        pass
                
                if class_counts:
                    for ip_class, count in class_counts.items():
                        st.write(f"**Class {ip_class}:** {count} networks")
                else:
                    st.info("No class distribution data available")
            
            with dist_col2:
                st.markdown("### Network Type Distribution")
                
                type_counts = {}
                for network in st.session_state.ip_ecosystem['networks']:
                    net_type = network['type']
                    type_counts[net_type] = type_counts.get(net_type, 0) + 1
                
                for net_type, count in type_counts.items():
                    st.write(f"**{net_type}:** {count} networks")
            
            # Address Space Utilization
            st.subheader("📈 Address Space Analysis")
            
            util_col1, util_col2 = st.columns(2)
            
            with util_col1:
                st.markdown("### Subnet Size Distribution")
                
                subnet_sizes = {}
                for network in st.session_state.ip_ecosystem['networks']:
                    try:
                        cidr = network['address'].split('/')[1]
                        size_category = f"/{cidr}"
                        subnet_sizes[size_category] = subnet_sizes.get(size_category, 0) + 1
                    except:
                        pass
                
                for size, count in sorted(subnet_sizes.items()):
                    st.write(f"**{size}:** {count} subnets")
            
            with util_col2:
                st.markdown("### Total Address Space")
                
                total_addresses = sum(net['total_hosts'] for net in st.session_state.ip_ecosystem['networks'])
                private_addresses = 0
                public_addresses = 0
                
                for network in st.session_state.ip_ecosystem['networks']:
                    try:
                        network_ip = ipaddress.ip_network(network['address'], strict=False)
                        if network_ip.is_private:
                            private_addresses += network['total_hosts']
                        else:
                            public_addresses += network['total_hosts']
                    except:
                        pass
                
                st.metric("Total Addresses", f"{total_addresses:,}")
                st.metric("Private Addresses", f"{private_addresses:,}")
                st.metric("Public Addresses", f"{public_addresses:,}")
            
            # IP Address Planning Tool
            st.subheader("🎯 IP Address Planning")
            
            planning_col1, planning_col2 = st.columns(2)
            
            with planning_col1:
                st.markdown("### Subnet Planning Calculator")
                
                required_subnets = st.number_input(
                    "Required Subnets:",
                    min_value=1,
                    max_value=1024,
                    value=4,
                    help="Number of subnets needed"
                )
                
                hosts_per_subnet = st.number_input(
                    "Hosts per Subnet:",
                    min_value=1,
                    max_value=65534,
                    value=50,
                    help="Number of hosts needed per subnet"
                )
                
                if st.button("📐 Calculate Subnetting"):
                    import math
                    
                    # Calculate required subnet bits
                    subnet_bits = math.ceil(math.log2(required_subnets))
                    host_bits = math.ceil(math.log2(hosts_per_subnet + 2))
                    total_bits = subnet_bits + host_bits
                    
                    if total_bits <= 32:
                        recommended_cidr = 32 - host_bits
                        actual_subnets = 2 ** subnet_bits
                        actual_hosts = (2 ** host_bits) - 2
                        
                        st.success("✅ Subnetting Plan:")
                        st.write(f"**Recommended CIDR:** /{recommended_cidr}")
                        st.write(f"**Actual Subnets:** {actual_subnets}")
                        st.write(f"**Hosts per Subnet:** {actual_hosts}")
                        st.write(f"**Total Host Addresses:** {actual_subnets * actual_hosts:,}")
                    else:
                        st.error("❌ Requirements exceed available address space")
            
            with planning_col2:
                st.markdown("### Address Conflicts Detection")
                
                # Check for overlapping networks
                conflicts = []
                networks = st.session_state.ip_ecosystem['networks']
                
                for i, net1 in enumerate(networks):
                    for j, net2 in enumerate(networks[i+1:], i+1):
                        try:
                            network1 = ipaddress.ip_network(net1['address'], strict=False)
                            network2 = ipaddress.ip_network(net2['address'], strict=False)
                            
                            if network1.overlaps(network2):
                                conflicts.append((net1['name'], net2['name']))
                        except:
                            pass
                
                if conflicts:
                    st.warning("⚠️ Network Conflicts Detected:")
                    for net1, net2 in conflicts:
                        st.write(f"• {net1} ↔ {net2}")
                else:
                    st.success("✅ No network conflicts detected")
                
                # Suggest optimization
                if st.button("🔧 Suggest Optimizations"):
                    st.info("💡 Optimization Suggestions:")
                    st.write("• Consider consolidating small subnets")
                    st.write("• Use VLSM for efficient address utilization")
                    st.write("• Reserve address space for future growth")
                    st.write("• Implement proper IP address documentation")
        
        else:
            st.info("Add networks in the Network Overview tab to see analytics.")
    
    with tab3:
        st.markdown("## 🔧 Network Designer")
        
        designer_col1, designer_col2 = st.columns([1, 2])
        
        with designer_col1:
            st.subheader("Network Design Wizard")
            
            # Network design parameters
            organization_size = st.selectbox(
                "Organization Size:",
                ["Small (< 50 users)", "Medium (50-500 users)", "Large (500+ users)"],
                help="Size of the organization"
            )
            
            network_types_needed = st.multiselect(
                "Network Types Needed:",
                ["User LAN", "Server VLAN", "Guest Network", "Management Network", "DMZ", "Voice VLAN"],
                default=["User LAN", "Server VLAN"],
                help="Types of networks required"
            )
            
            security_level = st.selectbox(
                "Security Level:",
                ["Basic", "Enhanced", "High Security"],
                help="Required security level"
            )
            
            if st.button("🎨 Generate Design", type="primary"):
                st.success("✅ Network design generated!")
                
                # Generate recommended design
                design_recommendations = {
                    "Small (< 50 users)": {
                        "User LAN": "192.168.1.0/24",
                        "Server VLAN": "192.168.10.0/27", 
                        "Guest Network": "192.168.100.0/24",
                        "Management Network": "192.168.99.0/28"
                    },
                    "Medium (50-500 users)": {
                        "User LAN": "10.1.0.0/22",
                        "Server VLAN": "10.1.10.0/26",
                        "Guest Network": "10.1.100.0/24", 
                        "Management Network": "10.1.99.0/28",
                        "Voice VLAN": "10.1.200.0/24"
                    },
                    "Large (500+ users)": {
                        "User LAN": "10.0.0.0/16",
                        "Server VLAN": "10.1.0.0/20",
                        "Guest Network": "10.100.0.0/16",
                        "Management Network": "10.99.0.0/24",
                        "DMZ": "172.16.0.0/24"
                    }
                }
                
                recommendations = design_recommendations.get(organization_size, {})
                
                for net_type in network_types_needed:
                    if net_type in recommendations:
                        st.write(f"**{net_type}:** {recommendations[net_type]}")
        
        with designer_col2:
            st.subheader("🗺️ Network Topology Visualization")
            
            # Simple text-based network diagram
            if st.session_state.ip_ecosystem['networks']:
                st.markdown("### Current Network Topology")
                
                st.code("""
Internet
    |
[Router/Firewall]
    |
[Core Switch]
    |
+---+---+---+---+
|   |   |   |   |
""", language="text")
                
                # Show networks in topology
                for network in st.session_state.ip_ecosystem['networks']:
                    st.code(f"[{network['type']}] {network['name']} ({network['address']})", language="text")
                
                # Network relationships
                st.markdown("### Network Relationships")
                
                relationships = []
                for i, network in enumerate(st.session_state.ip_ecosystem['networks']):
                    for j, other_network in enumerate(st.session_state.ip_ecosystem['networks']):
                        if i != j:
                            # Simulate routing relationships
                            if network['type'] in ['LAN', 'VLAN'] and other_network['type'] in ['LAN', 'VLAN']:
                                relationships.append(f"{network['name']} ↔ {other_network['name']} (Inter-VLAN)")
                
                for relationship in relationships[:5]:  # Show first 5 relationships
                    st.write(f"• {relationship}")
            
            else:
                st.info("Add networks to visualize topology")
            
            # Network documentation export
            st.markdown("### 📄 Documentation Export")
            
            if st.button("📋 Generate Documentation"):
                doc_content = "# Network Documentation\n\n"
                doc_content += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                
                doc_content += "## Networks\n\n"
                for network in st.session_state.ip_ecosystem['networks']:
                    doc_content += f"### {network['name']}\n"
                    doc_content += f"- **Address:** {network['address']}\n"
                    doc_content += f"- **Type:** {network['type']}\n"
                    doc_content += f"- **Location:** {network['location']}\n"
                    doc_content += f"- **Capacity:** {network['total_hosts']} hosts\n\n"
                
                st.download_button(
                    label="💾 Download Documentation",
                    data=doc_content,
                    file_name=f"network_documentation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                    mime="text/markdown"
                )
    
    with tab4:
        st.markdown("## 📈 Network Monitoring Dashboard")
        
        if st.session_state.ip_ecosystem['networks']:
            
            # Monitoring metrics (simulated)
            st.subheader("📊 Real-time Network Status")
            
            monitor_col1, monitor_col2, monitor_col3, monitor_col4 = st.columns(4)
            
            with monitor_col1:
                st.metric("Total Networks", len(st.session_state.ip_ecosystem['networks']))
            
            with monitor_col2:
                avg_util = random.randint(20, 80)
                st.metric("Avg Utilization", f"{avg_util}%", f"{random.randint
