# IP_Address_Playground
```Plain Text
IP_Address_Playground/
│
├── README.md                 # This file
├── requirements.txt          # Python dependencies
├── LICENSE                   # MIT License
│
├── docs/                     # Detailed tutorials
│   ├── 01_ip_basics.md
│   ├── 02_subnetting.md
│   ├── 03_dhcp_guide.md
│   ├── 04_dns_guide.md
│   └── 05_advanced_topics.md
│
├── notebooks/                # Jupyter notebooks
│   ├── 01_IP_Basics.ipynb
│   ├── 02_Subnetting_Practice.ipynb
│   ├── 03_DHCP_Simulation.ipynb
│   └── 04_DNS_Playground.ipynb
│
├── src/                      # Core Python modules
│   ├── __init__.py
│   ├── ip_validator.py
│   ├── subnet_visualizer.py
│   ├── dhcp_allocator.py
│   ├── dns_resolver.py
│   └── ip_class_identifier.py
│
├── streamlit_app/            # Interactive web app
│   ├── app.py
│   ├── pages/
│   │   ├── 1_IP_Class_Identifier.py
│   │   ├── 2_Subnet_Calculator.py
│   │   ├── 3_DHCP_Demo.py
│   │   ├── 4_DNS_Resolver.py
│   │   └── 5_IP_Ecosystem.py
│   └── utils/
│       └── helpers.py
│
├── tests/                    # Unit tests
│   ├── test_ip_validator.py
│   ├── test_subnet_visualizer.py
│   ├── test_dhcp_allocator.py
│   └── test_dns_resolver.py
│
├── examples/                 # Sample datasets
│   ├── sample_ips.csv
│   ├── subnet_exercises.json
│   ├── dhcp_pools.yaml
│   └── dns_records.txt
│
└── images/                   # Visual resources
    ├── prompts/
    │   ├── ip_basics_prompt.txt
    │   ├── dhcp_workflow_prompt.txt
    │   ├── subnetting_prompt.txt
    │   ├── dns_resolution_prompt.txt
    │   └── ecosystem_prompt.txt
    └── generated/
        └── README.md


🌐 IP Addressing Playground

A comprehensive, hands-on learning platform for mastering IP addressing, subnetting, DHCP, DNS, and networking fundamentals.

Show Image
Show Image
Show Image
📚 Complete Learning Roadmap
🎯 Beginner Level (Weeks 1-2)
1. Basics of IP Addresses

What is an IP Address?

Unique identifier for devices on a network
Think of it as a "postal address" for computers
Two versions: IPv4 (32-bit) and IPv6 (128-bit)


IPv4 Structure

Format: 192.168.1.1 (4 octets, each 0-255)
Binary representation: 32 bits total
Total addresses: 2³² = ~4.3 billion


IPv6 Structure

Format: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
128 bits = 2¹²⁸ possible addresses
Solves IPv4 exhaustion problem



2. Private vs Public IP Addresses
Private IP Ranges (RFC 1918):

Class A: 10.0.0.0 to 10.255.255.255 (10/8)
Class B: 172.16.0.0 to 172.31.255.255 (172.16/12)
Class C: 192.168.0.0 to 192.168.255.255 (192.168/16)

Public IP Addresses:

Globally unique, routable on the Internet
Assigned by ISPs and regional registries (IANA → RIRs)
NAT translates private ↔ public at router boundary

🔧 Intermediate Level (Weeks 3-4)
3. IP Classes (Classful Addressing)
ClassFirst OctetNetwork BitsHost BitsDefault MaskPurposeA1-126824255.0.0.0Large networks (16M hosts)B128-1911616255.255.0.0Medium networks (65K hosts)C192-223248255.255.255.0Small networks (254 hosts)D224-239---MulticastE240-255---Experimental
Special Addresses:

127.0.0.0/8 - Loopback (localhost)
0.0.0.0/8 - Current network
169.254.0.0/16 - Link-local (APIPA)

4. Subnetting Fundamentals
CIDR (Classless Inter-Domain Routing):

Notation: 192.168.1.0/24 where /24 = subnet mask bits
Allows flexible subnet sizes beyond classful boundaries

Subnet Mask:

Defines network vs host portion
Example: 255.255.255.0 = /24 = 24 network bits, 8 host bits

Subnetting Formula:

Networks = 2^(borrowed bits)
Hosts per subnet = 2^(host bits) - 2
Valid host range: Network+1 to Broadcast-1

Example: Subnet 192.168.1.0/24 into 4 subnets:
Original: 192.168.1.0/24
Borrow 2 bits: /26 (255.255.255.192)

Subnet 1: 192.168.1.0/26   (0-63)
Subnet 2: 192.168.1.64/26  (64-127)
Subnet 3: 192.168.1.128/26 (128-191)
Subnet 4: 192.168.1.192/26 (192-255)
🚀 Advanced Level (Weeks 5-6)
5. DHCP (Dynamic Host Configuration Protocol)
DHCP Process - DORA:

Discover - Client broadcasts request for IP
Offer - Server offers available IP
Request - Client requests offered IP
Acknowledge - Server confirms allocation

DHCP Components:

DHCP Server: Manages IP pool, leases
DHCP Client: Requests configuration
DHCP Relay: Forwards requests across subnets
Lease Time: Duration of IP assignment

DHCP Options:

IP Address & Subnet Mask
Default Gateway
DNS Servers
Domain Name
NTP Servers

6. DNS (Domain Name System)
DNS Hierarchy:
Root (.) 
  └── TLD (.com, .org, .net)
      └── Domain (example.com)
          └── Subdomain (www.example.com)
DNS Record Types:

A: IPv4 address mapping
AAAA: IPv6 address mapping
CNAME: Canonical name (alias)
MX: Mail exchange servers
TXT: Text information
NS: Name servers
PTR: Reverse DNS lookup

DNS Resolution Process:

Check local cache
Query recursive resolver
Root nameserver → TLD nameserver → Authoritative nameserver
Return IP address to client

7. Network Components
Three Critical IP Addresses:

Network IP: First address (all host bits = 0)

Example: 192.168.1.0/24


Broadcast IP: Last address (all host bits = 1)

Example: 192.168.1.255/24


Host IPs: All addresses between network and broadcast

Example: 192.168.1.1 to 192.168.1.254



🌍 Complete IP Ecosystem
Internet Cloud
     |
[ISP Router] ← Public IP (203.0.113.1)
     |
[Home Router/NAT] ← Private Network (192.168.1.0/24)
     |
[DHCP Server] ← Manages IP Pool
     |
├── [PC: 192.168.1.10] → DNS Query → [DNS Server]
├── [Phone: 192.168.1.20] → Web Request → [Gateway]
└── [IoT: 192.168.1.30] → Local Traffic → [Switch]
🛠️ Repository Structure
IP_Address_Playground/
│
├── README.md                 # This file
├── requirements.txt          # Python dependencies
├── LICENSE                   # MIT License
│
├── docs/                     # Detailed tutorials
│   ├── 01_ip_basics.md
│   ├── 02_subnetting.md
│   ├── 03_dhcp_guide.md
│   ├── 04_dns_guide.md
│   └── 05_advanced_topics.md
│
├── notebooks/                # Jupyter notebooks
│   ├── 01_IP_Basics.ipynb
│   ├── 02_Subnetting_Practice.ipynb
│   ├── 03_DHCP_Simulation.ipynb
│   └── 04_DNS_Playground.ipynb
│
├── src/                      # Core Python modules
│   ├── __init__.py
│   ├── ip_validator.py
│   ├── subnet_visualizer.py
│   ├── dhcp_allocator.py
│   ├── dns_resolver.py
│   └── ip_class_identifier.py
│
├── streamlit_app/            # Interactive web app
│   ├── app.py
│   ├── pages/
│   │   ├── 1_IP_Class_Identifier.py
│   │   ├── 2_Subnet_Calculator.py
│   │   ├── 3_DHCP_Demo.py
│   │   ├── 4_DNS_Resolver.py
│   │   └── 5_IP_Ecosystem.py
│   └── utils/
│       └── helpers.py
│
├── tests/                    # Unit tests
│   ├── test_ip_validator.py
│   ├── test_subnet_visualizer.py
│   ├── test_dhcp_allocator.py
│   └── test_dns_resolver.py
│
├── examples/                 # Sample datasets
│   ├── sample_ips.csv
│   ├── subnet_exercises.json
│   ├── dhcp_pools.yaml
│   └── dns_records.txt
│
└── images/                   # Visual resources
    ├── prompts/
    │   ├── ip_basics_prompt.txt
    │   ├── dhcp_workflow_prompt.txt
    │   ├── subnetting_prompt.txt
    │   ├── dns_resolution_prompt.txt
    │   └── ecosystem_prompt.txt
    └── generated/
        └── README.md
🚀 Quick Start
Prerequisites

Python 3.8 or higher
pip package manager
Git

Installation

Clone the repository:

bashgit clone https://github.com/yourusername/IP_Address_Playground.git
cd IP_Address_Playground

Create virtual environment:

bashpython -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

Install dependencies:

bashpip install -r requirements.txt
Running the Applications
🌐 Streamlit Web App
bashstreamlit run streamlit_app/app.py
Visit http://localhost:8501 in your browser.
📓 Jupyter Notebooks
bashjupyter notebook
Navigate to the notebooks/ directory.
🐍 Python Scripts
bash# Validate an IP address
python src/ip_validator.py 192.168.1.1

# Visualize subnet
python src/subnet_visualizer.py 192.168.1.0/24

# Run DHCP simulation
python src/dhcp_allocator.py

# Resolve DNS
python src/dns_resolver.py google.com
📖 Learning Path
Week 1-2: Foundation

Read docs/01_ip_basics.md
Complete notebooks/01_IP_Basics.ipynb
Practice with src/ip_validator.py
Use IP Class Identifier in Streamlit app

Week 3-4: Subnetting Mastery

Study docs/02_subnetting.md
Work through notebooks/02_Subnetting_Practice.ipynb
Use Subnet Calculator tool
Complete exercises in examples/subnet_exercises.json

Week 5-6: Advanced Topics

Learn DHCP via docs/03_dhcp_guide.md
Simulate with notebooks/03_DHCP_Simulation.ipynb
Explore DNS with docs/04_dns_guide.md
Practice DNS queries with resolver tool

🧪 Testing
Run all tests:
bashpytest tests/
Run specific test:
bashpytest tests/test_ip_validator.py -v
📚 Educational Resources
Official Documentation

IETF RFC 791 - Internet Protocol
IETF RFC 1918 - Private IP Addresses
IETF RFC 4632 - CIDR
IETF RFC 2131 - DHCP
IETF RFC 1034 - DNS Concepts

Cisco Resources

Cisco IP Addressing Guide
Cisco Subnetting Tutorial
Cisco DHCP Configuration

Online Tools & Simulators

Subnet Calculator
Visual Subnet Calculator
DNS Lookup Tools
Packet Tracer

YouTube Channels

Professor Messer - CompTIA Network+
NetworkChuck - Practical Networking
David Bombal - CCNA Training

🤝 Contributing
We welcome contributions! Please see our Contributing Guidelines for details.

Fork the repository
Create your feature branch (git checkout -b feature/AmazingFeature)
Commit your changes (git commit -m 'Add some AmazingFeature')
Push to the branch (git push origin feature/AmazingFeature)
Open a Pull Request

📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
🙏 Acknowledgments

Internet Engineering Task Force (IETF) for protocol standards
Python ipaddress module developers
Streamlit team for the amazing framework
Open-source community for continuous support

📧 Contact

GitHub: @yourusername
Email: your.email@example.com


Happy Learning! 🎓 Master IP addressing one subnet at a time!

```
