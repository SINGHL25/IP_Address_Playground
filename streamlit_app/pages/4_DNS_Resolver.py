
import streamlit as st
import sys
import os
import socket
import time
from datetime import datetime

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns_resolver import DNSResolver
from utils.helpers import validate_domain_name, ping_host

def main():
    st.set_page_config(
        page_title="DNS Resolver",
        page_icon="🌐",
        layout="wide"
    )
    
    st.title("🌐 DNS Resolver & Analyzer")
    st.markdown("---")
    
    st.markdown("""
    ## Domain Name System (DNS) Resolution Tool
    
    Resolve domain names, analyze DNS records, and explore the DNS hierarchy.
    """)
    
    # Initialize DNS resolver
    if 'dns_resolver' not in st.session_state:
        st.session_state.dns_resolver = DNSResolver()
    
    # DNS Resolution Section
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.subheader("DNS Lookup")
        
        domain_input = st.text_input(
            "Domain Name:",
            value="google.com",
            help="Enter a domain name to resolve (e.g., google.com)"
        )
        
        record_type = st.selectbox(
            "Record Type:",
            ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "PTR", "SOA"],
            index=0,
            help="Select the type of DNS record to query"
        )
        
        dns_server = st.selectbox(
            "DNS Server:",
            ["System Default", "8.8.8.8 (Google)", "1.1.1.1 (Cloudflare)", 
             "208.67.222.222 (OpenDNS)", "Custom"],
            help="Choose which DNS server to query"
        )
        
        if dns_server == "Custom":
            custom_dns = st.text_input(
                "Custom DNS Server:",
                value="8.8.8.8",
                help="Enter custom DNS server IP address"
            )
        else:
            custom_dns = None
        
        resolve_btn = st.button("🔍 Resolve", type="primary")
        
        # Quick domain examples
        st.markdown("### Quick Examples:")
        example_domains = [
            "google.com",
            "github.com", 
            "cloudflare.com",
            "microsoft.com",
            "amazon.com"
        ]
        
        for domain in example_domains:
            if st.button(f"Resolve {domain}", key=f"example_{domain}"):
                st.session_state.example_domain = domain
                st.rerun()
    
    with col2:
        # Handle examples
        if hasattr(st.session_state, 'example_domain'):
            domain_input = st.session_state.example_domain
            delattr(st.session_state, 'example_domain')
        
        if domain_input and (resolve_btn or domain_input):
            if validate_domain_name(domain_input):
                st.subheader(f"🔍 DNS Resolution Results for {domain_input}")
                
                try:
                    # Determine DNS server to use
                    server_ip = None
                    if dns_server != "System Default":
                        server_map = {
                            "8.8.8.8 (Google)": "8.8.8.8",
                            "1.1.1.1 (Cloudflare)": "1.1.1.1",
                            "208.67.222.222 (OpenDNS)": "208.67.222.222",
                            "Custom": custom_dns
                        }
                        server_ip = server_map.get(dns_server)
                    
                    # Perform DNS resolution
                    with st.spinner(f"Resolving {domain_input}..."):
                        start_time = time.time()
                        result = st.session_state.dns_resolver.resolve_domain(
                            domain_input, record_type, server_ip
                        )
                        resolution_time = time.time() - start_time
                    
                    if result and 'records' in result:
                        # Display resolution metrics
                        metric_col1, metric_col2, metric_col3 = st.columns(3)
                        
                        with metric_col1:
                            st.metric("Records Found", len(result['records']))
                        with metric_col2:
                            st.metric("Resolution Time", f"{resolution_time:.3f}s")
                        with metric_col3:
                            st.metric("Server Used", result.get('server', 'System Default'))
                        
                        # Display DNS records
                        st.markdown("### 📋 DNS Records")
                        
                        if result['records']:
                            for i, record in enumerate(result['records'], 1):
                                with st.expander(f"Record {i}: {record}"):
                                    record_info = st.session_state.dns_resolver.get_record_info(record, record_type)
                                    
                                    if record_info:
                                        info_col1, info_col2 = st.columns(2)
                                        
                                        with info_col1:
                                            st.write(f"**Record:** {record}")
                                            st.write(f"**Type:** {record_type}")
                                            st.write(f"**TTL:** {record_info.get('ttl', 'N/A')}")
                                        
                                        with info_col2:
                                            if record_type == "A":
                                                st.write(f"**IPv4 Address:** {record}")
                                                # Check if IP is reachable
                                                if ping_host(record):
                                                    st.success("✅ Host is reachable")
                                                else:
                                                    st.warning("⚠️ Host may not be reachable")
                                            elif record_type == "MX":
                                                priority, server = record.split(' ', 1) if ' ' in record else ('N/A', record)
                                                st.write(f"**Priority:** {priority}")
                                                st.write(f"**Mail Server:** {server}")
                        else:
                            st.warning(f"No {record_type} records found for {domain_input}")
                        
                        # Additional DNS analysis
                        if record_type == "A":
                            st.markdown("### 🌍 Additional Analysis")
                            
                            analysis_col1, analysis_col2 = st.columns(2)
                            
                            with analysis_col1:
                                st.markdown("**Reverse DNS Lookup:**")
                                for record in result['records'][:3]:  # Limit to first 3 records
                                    try:
                                        reverse_result = socket.gethostbyaddr(record)
                                        st.write(f"{record} → {reverse_result[0]}")
                                    except:
                                        st.write(f"{record} → No reverse DNS")
                            
                            with analysis_col2:
                                st.markdown("**IP Geolocation:**")
                                st.info("🗺️ Geolocation lookup would require external API")
                                
                                # Show IP classification
                                from utils.helpers import get_ip_info
                                for record in result['records'][:1]:  # Show for first record only
                                    ip_info = get_ip_info(record)
                                    if 'error' not in ip_info:
                                        st.write(f"**Class:** {ip_info.get('class', 'Unknown')}")
                                        st.write(f"**Type:** {ip_info.get('type', 'Unknown')}")
                    
                    else:
                        st.error(f"❌ Failed to resolve {domain_input}")
                        st.write("Possible reasons:")
                        st.write("• Domain does not exist")
                        st.write("• DNS server is unreachable")
                        st.write("• Record type does not exist for this domain")
                
                except Exception as e:
                    st.error(f"❌ DNS resolution error: {str(e)}")
            else:
                st.error("❌ Invalid domain name format. Please enter a valid domain name.")
        else:
            st.info("👆 Enter a domain name above and click 'Resolve' to perform DNS lookup.")
    
    # DNS Hierarchy Visualization
    st.markdown("---")
    st.markdown("## 🌳 DNS Hierarchy Explorer")
    
    hierarchy_col1, hierarchy_col2 = st.columns(2)
    
    with hierarchy_col1:
        st.subheader("Trace DNS Path")
        
        trace_domain = st.text_input(
            "Domain to trace:",
            value="www.example.com",
            help="Enter domain to trace DNS resolution path"
        )
        
        if st.button("🔗 Trace DNS Path"):
            if validate_domain_name(trace_domain):
                st.markdown("**DNS Resolution Path:**")
                
                # Simulate DNS hierarchy traversal
                domain_parts = trace_domain.split('.')
                
                for i in range(len(domain_parts)):
                    level = len(domain_parts) - i
                    current_domain = '.'.join(domain_parts[i:])
                    
                    if level == len(domain_parts):
                        st.write(f"🌐 **Root (.)** → Looking for {current_domain}")
                    elif level > 1:
                        st.write(f"📁 **{domain_parts[-level]} TLD** → Looking for {current_domain}")
                    else:
                        st.write(f"🎯 **{current_domain}** → Final resolution")
                
                st.success(f"✅ DNS path traced for {trace_domain}")
            else:
                st.error("❌ Invalid domain name")
    
    with hierarchy_col2:
        st.subheader("DNS Record Types")
        
        record_info = {
            "A": "Maps domain to IPv4 address",
            "AAAA": "Maps domain to IPv6 address", 
            "CNAME": "Canonical name (alias) record",
            "MX": "Mail exchange server record",
            "NS": "Name server record",
            "TXT": "Text record for various purposes",
            "PTR": "Pointer record for reverse DNS",
            "SOA": "Start of Authority record"
        }
        
        for record_type, description in record_info.items():
            st.write(f"**{record_type}:** {description}")
    
    # DNS Cache Simulation
    st.markdown("---")
    st.markdown("## 💾 DNS Cache Simulator")
    
    cache_col1, cache_col2 = st.columns(2)
    
    with cache_col1:
        st.subheader("DNS Cache Status")
        
        # Initialize cache in session state
        if 'dns_cache' not in st.session_state:
            st.session_state.dns_cache = {}
        
        cache = st.session_state.dns_cache
        
        if cache:
            st.markdown("**Cached Records:**")
            for domain, info in cache.items():
                with st.expander(f"{domain}"):
                    st.write(f"**IP:** {info.get('ip', 'N/A')}")
                    st.write(f"**TTL:** {info.get('ttl', 'N/A')} seconds")
                    st.write(f"**Cached at:** {info.get('cached_at', 'N/A')}")
        else:
            st.info("DNS cache is empty. Perform some DNS lookups to populate the cache.")
        
        if st.button("🗑️ Clear DNS Cache"):
            st.session_state.dns_cache = {}
            st.success("✅ DNS cache cleared!")
            st.rerun()
    
    with cache_col2:
        st.subheader("Cache Management")
        
        # Add manual cache entry
        st.markdown("**Add Cache Entry:**")
        cache_domain = st.text_input("Domain:", help="Domain to cache")
        cache_ip = st.text_input("IP Address:", help="IP address for domain")
        cache_ttl = st.number_input("TTL (seconds):", min_value=1, value=3600)
        
        if st.button("💾 Add to Cache"):
            if cache_domain and cache_ip:
                st.session_state.dns_cache[cache_domain] = {
                    'ip': cache_ip,
                    'ttl': cache_ttl,
                    'cached_at': datetime.now().strftime("%H:%M:%S")
                }
                st.success(f"✅ Added {cache_domain} to cache")
                st.rerun()
        
        # Cache statistics
        if st.session_state.dns_cache:
            st.markdown("**Cache Statistics:**")
            st.metric("Cached Domains", len(st.session_state.dns_cache))
            
            # Show cache hit simulation
            if st.button("🎯 Simulate Cache Hit"):
                domain = list(st.session_state.dns_cache.keys())[0]
                st.success(f"✅ Cache HIT for {domain} - No DNS query needed!")
    
    # DNS Tools Section
    st.markdown("---")
    st.markdown("## 🛠️ DNS Tools & Utilities")
    
    tools_col1, tools_col2, tools_col3 = st.columns(3)
    
    with tools_col1:
        st.subheader("Bulk DNS Lookup")
        
        bulk_domains = st.text_area(
            "Domains (one per line):",
            value="google.com\ngithub.com\nstackoverflow.com",
            height=100,
            help="Enter multiple domains for batch resolution"
        )
        
        if st.button("🔍 Bulk Resolve"):
            domains = [d.strip() for d in bulk_domains.split('\n') if d.strip()]
            
            if domains:
                st.markdown("**Bulk Resolution Results:**")
                
                progress_bar = st.progress(0)
                results = []
                
                for i, domain in enumerate(domains):
                    if validate_domain_name(domain):
                        try:
                            result = st.session_state.dns_resolver.resolve_domain(domain, "A")
                            if result and result.get('records'):
                                results.append({
                                    'Domain': domain,
                                    'IP Address': result['records'][0],
                                    'Status': '✅ Resolved'
                                })
                            else:
                                results.append({
                                    'Domain': domain,
                                    'IP Address': 'N/A',
                                    'Status': '❌ Failed'
                                })
                        except:
                            results.append({
                                'Domain': domain,
                                'IP Address': 'N/A', 
                                'Status': '❌ Error'
                            })
                    else:
                        results.append({
                            'Domain': domain,
                            'IP Address': 'N/A',
                            'Status': '❌ Invalid'
                        })
                    
                    progress_bar.progress((i + 1) / len(domains))
                
                st.dataframe(results, use_container_width=True)
    
    with tools_col2:
        st.subheader("DNS Performance Test")
        
        test_domain = st.text_input(
            "Test Domain:",
            value="google.com",
            help="Domain for performance testing"
        )
        
        test_servers = [
            "8.8.8.8",
            "1.1.1.1", 
            "208.67.222.222",
            "9.9.9.9"
        ]
        
        if st.button("⚡ Performance Test"):
            if validate_domain_name(test_domain):
                st.markdown("**DNS Server Performance:**")
                
                performance_results = []
                
                for server in test_servers:
                    try:
                        start_time = time.time()
                        result = st.session_state.dns_resolver.resolve_domain(
                            test_domain, "A", server
                        )
                        response_time = (time.time() - start_time) * 1000  # Convert to ms
                        
                        if result and result.get('records'):
                            performance_results.append({
                                'DNS Server': server,
                                'Response Time': f"{response_time:.2f} ms",
                                'Status': '✅ Success'
                            })
                        else:
                            performance_results.append({
                                'DNS Server': server,
                                'Response Time': 'N/A',
                                'Status': '❌ Failed'
                            })
                    except:
                        performance_results.append({
                            'DNS Server': server,
                            'Response Time': 'N/A',
                            'Status': '❌ Error'
                        })
                
                st.dataframe(performance_results, use_container_width=True)
                
                # Find fastest server
                successful_results = [r for r in performance_results if r['Status'] == '✅ Success']
                if successful_results:
                    fastest = min(successful_results, key=lambda x: float(x['Response Time'].split()[0]))
                    st.success(f"🏆 Fastest DNS Server: {fastest['DNS Server']} ({fastest['Response Time']})")
    
    with tools_col3:
        st.subheader("DNS Health Check")
        
        health_domain = st.text_input(
            "Domain to Check:",
            value="example.com",
            help="Domain for comprehensive health check"
        )
        
        if st.button("🏥 Health Check"):
            if validate_domain_name(health_domain):
                st.markdown("**DNS Health Report:**")
                
                health_checks = [
                    ("A Record", "A"),
                    ("AAAA Record", "AAAA"), 
                    ("MX Record", "MX"),
                    ("NS Record", "NS"),
                    ("TXT Record", "TXT")
                ]
                
                health_results = []
                
                for check_name, record_type in health_checks:
                    try:
                        result = st.session_state.dns_resolver.resolve_domain(
                            health_domain, record_type
                        )
                        if result and result.get('records'):
                            health_results.append({
                                'Check': check_name,
                                'Status': '✅ Present',
                                'Count': len(result['records'])
                            })
                        else:
                            health_results.append({
                                'Check': check_name,
                                'Status': '❌ Missing',
                                'Count': 0
                            })
                    except:
                        health_results.append({
                            'Check': check_name,
                            'Status': '⚠️ Error',
                            'Count': 0
                        })
                
                st.dataframe(health_results, use_container_width=True)
                
                # Overall health score
                present_count = sum(1 for r in health_results if r['Status'] == '✅ Present')
                health_score = (present_count / len(health_checks)) * 100
                
                if health_score >= 80:
                    st.success(f"🏆 DNS Health Score: {health_score:.0f}% - Excellent")
                elif health_score >= 60:
                    st.warning(f"⚠️ DNS Health Score: {health_score:.0f}% - Good")
                else:
                    st.error(f"❌ DNS Health Score: {health_score:.0f}% - Needs Attention")
    
    # Educational Section
    st.markdown("---")
    st.markdown("## 📚 DNS Educational Resources")
    
    edu_col1, edu_col2 = st.columns(2)
    
    with edu_col1:
        st.markdown("### How DNS Works")
        
        st.markdown("""
        **DNS Resolution Process:**
        
        1. **User Request** - Browser needs IP for domain
        2. **Local Cache** - Check browser/OS cache first
        3. **Recursive Resolver** - Query ISP DNS server
        4. **Root Servers** - Query root name servers (.)
        5. **TLD Servers** - Query top-level domain servers (.com)
        6. **Authoritative** - Query authoritative name servers
        7. **Response** - Return IP address to user
        
        **Key Concepts:**
        - **TTL (Time To Live)** - How long to cache records
        - **FQDN** - Fully Qualified Domain Name
        - **Zone Files** - DNS configuration files
        - **Delegation** - Passing authority to other servers
        """)
    
    with edu_col2:
        st.markdown("### DNS Security")
        
        st.markdown("""
        **DNS Security Considerations:**
        
        **Common Threats:**
        - DNS Spoofing/Cache Poisoning
        - DNS Hijacking  
        - DNS Tunneling
        - DDoS attacks on DNS servers
        
        **Protection Measures:**
        - **DNSSEC** - DNS Security Extensions
        - **DNS over HTTPS (DoH)** - Encrypted DNS queries
        - **DNS over TLS (DoT)** - Encrypted transport
        - **DNS Filtering** - Block malicious domains
        
        **Best Practices:**
        - Use reputable DNS providers
        - Enable DNSSEC validation
        - Monitor DNS query logs
        - Implement DNS redundancy
        """)
    
    # DNS Tips
    st.markdown("### 💡 DNS Troubleshooting Tips")
    
    st.markdown("""
    **Common DNS Issues:**
    
    - **Slow resolution** - Try different DNS servers, check network connectivity
    - **Domain not found** - Verify domain spelling, check if domain exists  
    - **Intermittent failures** - DNS server overload, network issues
    - **Stale cache** - Clear DNS cache, wait for TTL expiration
    - **Reverse DNS issues** - Check PTR records configuration
    
    **Useful Commands:**
    - `nslookup domain.com` - Basic DNS lookup
    - `dig domain.com` - Detailed DNS information  
    - `ipconfig /flushdns` (Windows) - Clear DNS cache
    - `sudo dscacheutil -flushcache` (macOS) - Clear DNS cache
    """)

if __name__ == "__main__":
    main()
