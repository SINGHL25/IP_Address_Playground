
#!/usr/bin/env python3
"""
Subnet Visualizer
Creates visual representations of IP subnets using matplotlib.
"""

import ipaddress
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import Rectangle, FancyBboxPatch
import numpy as np
from typing import List, Tuple, Optional, Dict
import sys
import colorsys


class SubnetVisualizer:
    """Visualize IP subnets and their relationships."""
    
    def __init__(self, figsize: Tuple[int, int] = (14, 10)):
        """
        Initialize subnet visualizer.
        
        Args:
            figsize: Figure size for matplotlib plots
        """
        self.figsize = figsize
        self.colors = self._generate_colors(20)
    
    def _generate_colors(self, n: int) -> List[str]:
        """Generate n distinct colors for visualization."""
        colors = []
        for i in range(n):
            hue = i / n
            saturation = 0.7
            value = 0.9
            rgb = colorsys.hsv_to_rgb(hue, saturation, value)
            colors.append('#%02x%02x%02x' % tuple(int(c * 255) for c in rgb))
        return colors
    
    def visualize_subnet(self, subnet_str: str) -> None:
        """
        Create comprehensive visualization of a single subnet.
        
        Args:
            subnet_str: Subnet in CIDR notation (e.g., '192.168.1.0/24')
        """
        try:
            network = ipaddress.ip_network(subnet_str, strict=False)
        except ValueError as e:
            print(f"Error: {e}")
            return
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=self.figsize)
        fig.suptitle(f'Subnet Analysis: {subnet_str}', fontsize=16, fontweight='bold')
        
        # 1. IP Range Bar
        self._plot_ip_range(ax1, network)
        
        # 2. Binary Representation
        self._plot_binary_representation(ax2, network)
        
        # 3. Host Distribution Pie Chart
        self._plot_host_distribution(ax3, network)
        
        # 4. Subnet Information Table
        self._plot_info_table(ax4, network)
        
        plt.tight_layout()
        plt.show()
    
    def _plot_ip_range(self, ax, network: ipaddress.IPv4Network) -> None:
        """Plot IP range as a horizontal bar."""
        ax.set_title('IP Address Range', fontweight='bold')
        
        # Create segments for different IP types
        total_ips = network.num_addresses
        
        if total_ips > 2:
            segments = [
                ('Network', 1, self.colors[0]),
                ('Usable Hosts', total_ips - 2, self.colors[1]),
                ('Broadcast', 1, self.colors[2])
            ]
        else:
            segments = [('Network/Broadcast', total_ips, self.colors[0])]
        
        # Plot segments
        x_pos = 0
        for label, size, color in segments:
            width = size / total_ips
            rect = FancyBboxPatch(
                (x_pos, 0.3), width, 0.4,
                boxstyle="round,pad=0.01",
                facecolor=color, edgecolor='black',
                linewidth=2, alpha=0.8
            )
            ax.add_patch(rect)
            
            # Add label if segment is large enough
            if width > 0.1:
                ax.text(x_pos + width/2, 0.5, label,
                       ha='center', va='center', fontsize=10, fontweight='bold')
            
            x_pos += width
        
        # Add IP addresses as labels
        ax.text(0, 0.1, str(network.network_address),
               ha='left', va='top', fontsize=9)
        ax.text(1, 0.1, str(network.broadcast_address),
               ha='right', va='top', fontsize=9)
        
        if total_ips > 2:
            hosts = list(network.hosts())
            if hosts:
                ax.text(0.5, 0.9, f"First Host: {hosts[0]}",
                       ha='center', va='bottom', fontsize=9)
                ax.text(0.5, 0.1, f"Last Host: {hosts[-1]}",
                       ha='center', va='top', fontsize=9)
        
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis('off')
    
    def _plot_binary_representation(self, ax, network: ipaddress.IPv4Network) -> None:
        """Plot binary representation of network and mask."""
        ax.set_title('Binary Representation', fontweight='bold')
        
        # Network address binary
        net_addr = network.network_address
        net_binary = format(int(net_addr), '032b')
        
        # Subnet mask binary
        mask_binary = format(int(network.netmask), '032b')
        
        # Create grid for binary display
        for i, (net_bit, mask_bit) in enumerate(zip(net_binary, mask_binary)):
            row = i // 8
            col = i % 8
            
            # Network bit
            color = 'lightgreen' if mask_bit == '1' else 'lightcoral'
            rect = Rectangle((col, 3-row), 1, 0.45, 
                           facecolor=color, edgecolor='black', linewidth=1)
            ax.add_patch(rect)
            ax.text(col + 0.5, 3-row + 0.225, net_bit,
                   ha='center', va='center', fontweight='bold', fontsize=10)
            
            # Mask bit
            mask_color = 'darkgreen' if mask_bit == '1' else 'darkred'
            rect = Rectangle((col, 3-row - 0.5), 1, 0.45,
                           facecolor=mask_color, edgecolor='black', linewidth=1, alpha=0.3)
            ax.add_patch(rect)
            ax.text(col + 0.5, 3-row - 0.275, mask_bit,
                   ha='center', va='center', fontsize=10)
            
            # Add octet separator
            if col == 7 and i < 31:
                ax.axvline(x=8, color='blue', linestyle='--', alpha=0.5)
        
        # Labels
        ax.text(-0.5, 3.225, 'Network:', ha='right', va='center', fontweight='bold')
        ax.text(-0.5, 2.225, '', ha='right', va='center')
        ax.text(-0.5, 1.225, '', ha='right', va='center')
        ax.text(-0.5, 0.225, '', ha='right', va='center')
        
        ax.text(-0.5, 2.725, 'Mask:', ha='right', va='center', fontweight='bold')
        ax.text(-0.5, 1.725, '', ha='right', va='center')
        ax.text(-0.5, 0.725, '', ha='right', va='center')
        ax.text(-0.5, -0.275, '', ha='right', va='center')
        
        # Octet labels
        octets = str(net_addr).split('.')
        for i, octet in enumerate(octets):
            ax.text(i*8 + 4, 4, octet, ha='center', va='bottom', fontweight='bold', fontsize=11)
        
        ax.set_xlim(-1, 32)
        ax.set_ylim(-1, 4.5)
        ax.axis('off')
    
    def _plot_host_distribution(self, ax, network: ipaddress.IPv4Network) -> None:
        """Plot host distribution as a pie chart."""
        ax.set_title('Address Distribution', fontweight='bold')
        
        total = network.num_addresses
        
        if total <= 2:
            sizes = [total]
            labels = ['Network/Broadcast']
            colors = [self.colors[0]]
        else:
            usable = total - 2
            sizes = [1, usable, 1]
            labels = ['Network\n(1 IP)', f'Usable Hosts\n({usable:,} IPs)', 'Broadcast\n(1 IP)']
            colors = [self.colors[0], self.colors[1], self.colors[2]]
        
        # Create pie chart
        wedges, texts, autotexts = ax.pie(sizes, labels=labels, colors=colors,
                                           autopct=lambda pct: f'{pct:.1f}%' if pct > 5 else '',
                                           startangle=90, explode=[0.05] * len(sizes))
        
        # Enhance text
        for text in texts:
            text.set_fontsize(10)
            text.set_fontweight('bold')
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
            autotext.set_fontsize(10)
        
        # Add total IPs in center
        ax.text(0, 0, f'Total:\n{total:,} IPs', ha='center', va='center',
               fontsize=12, fontweight='bold', bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))
    
    def _plot_info_table(self, ax, network: ipaddress.IPv4Network) -> None:
        """Plot subnet information as a table."""
        ax.set_title('Subnet Details', fontweight='bold')
        
        # Prepare data
        info = [
            ['Property', 'Value'],
            ['Network Address', str(network.network_address)],
            ['Broadcast Address', str(network.broadcast_address)],
            ['Subnet Mask', str(network.netmask)],
            ['Wildcard Mask', str(network.hostmask)],
            ['Prefix Length', f'/{network.prefixlen}'],
            ['Total Addresses', f'{network.num_addresses:,}'],
            ['Usable Hosts', f'{max(0, network.num_addresses - 2):,}'],
            ['IP Version', f'IPv{network.version}'],
            ['Private', 'Yes' if network.is_private else 'No'],
        ]
        
        # Create table
        table = ax.table(cellText=info, cellLoc='left', loc='center',
                        colWidths=[0.4, 0.6])
        table.auto_set_font_size(False)
        table.set_fontsize(10)
        table.scale(1, 2)
        
        # Style header row
        for i in range(2):
            cell = table[(0, i)]
            cell.set_facecolor('#4CAF50')
            cell.set_text_props(weight='bold', color='white')
        
        # Alternate row colors
        for i in range(1, len(info)):
            for j in range(2):
                cell = table[(i, j)]
                if i % 2 == 0:
                    cell.set_facecolor('#f0f0f0')
                else:
                    cell.set_facecolor('white')
                
                if j == 0:  # Property column
                    cell.set_text_props(weight='bold')
        
        ax.axis('off')
    
    def visualize_subnetting(self, parent_subnet: str, prefix_length: int) -> None:
        """
        Visualize subnetting of a parent network.
        
        Args:
            parent_subnet: Parent subnet in CIDR notation
            prefix_length: New prefix length for subnets
        """
        try:
            parent = ipaddress.ip_network(parent_subnet, strict=False)
            if prefix_length <= parent.prefixlen:
                print(f"Error: New prefix length must be greater than {parent.prefixlen}")
                return
            
            subnets = list(parent.subnets(new_prefix=prefix_length))
            
        except ValueError as e:
            print(f"Error: {e}")
            return
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 10))
        fig.suptitle(f'Subnetting: {parent_subnet} → /{prefix_length}', 
                    fontsize=16, fontweight='bold')
        
        # Top: Visual representation of subnets
        self._plot_subnet_blocks(ax1, parent, subnets)
        
        # Bottom: Subnet details table
        self._plot_subnet_table(ax2, subnets)
        
        plt.tight_layout()
        plt.show()
    
    def _plot_subnet_blocks(self, ax, parent: ipaddress.IPv4Network, 
                           subnets: List[ipaddress.IPv4Network]) -> None:
        """Plot subnets as colored blocks."""
        ax.set_title(f'Visual Subnet Division ({len(subnets)} subnets)', fontweight='bold')
        
        # Calculate layout
        n_subnets = len(subnets)
        cols = min(8, n_subnets)
        rows = (n_subnets + cols - 1) // cols
        
        # Plot each subnet
        for idx, subnet in enumerate(subnets):
            row = idx // cols
            col = idx % cols
            
            # Create rectangle for subnet
            rect = FancyBboxPatch(
                (col * 1.2, row * 1.2), 1, 1,
                boxstyle="round,pad=0.05",
                facecolor=self.colors[idx % len(self.colors)],
                edgecolor='black', linewidth=2, alpha=0.8
            )
            ax.add_patch(rect)
            
            # Add subnet info
            ax.text(col * 1.2 + 0.5, row * 1.2 + 0.7, f'Subnet {idx + 1}',
                   ha='center', va='center', fontweight='bold', fontsize=10)
            ax.text(col * 1.2 + 0.5, row * 1.2 + 0.5, str(subnet),
                   ha='center', va='center', fontsize=9)
            ax.text(col * 1.2 + 0.5, row * 1.2 + 0.3, 
                   f'{subnet.num_addresses - 2} hosts',
                   ha='center', va='center', fontsize=8, style='italic')
        
        ax.set_xlim(-0.2, cols * 1.2)
        ax.set_ylim(-0.2, rows * 1.2 + 0.2)
        ax.invert_yaxis()
        ax.axis('off')
    
    def _plot_subnet_table(self, ax, subnets: List[ipaddress.IPv4Network]) -> None:
        """Plot detailed subnet information table."""
        ax.set_title('Subnet Details Table', fontweight='bold')
        
        # Prepare table data
        headers = ['#', 'Network', 'First Host', 'Last Host', 'Broadcast', 'Hosts']
        data = [headers]
        
        for idx, subnet in enumerate(subnets[:20]):  # Limit to 20 for readability
            hosts = list(subnet.hosts())
            first_host = str(hosts[0]) if hosts else 'N/A'
            last_host = str(hosts[-1]) if hosts else 'N/A'
            
            data.append([
                str(idx + 1),
                str(subnet.network_address),
                first_host,
                last_host,
                str(subnet.broadcast_address),
                str(max(0, subnet.num_addresses - 2))
            ])
        
        if len(subnets) > 20:
            data.append(['...', '...', '...', '...', '...', '...'])
        
        # Create table
        table = ax.table(cellText=data, cellLoc='center', loc='center',
                        colWidths=[0.08, 0.22, 0.22, 0.22, 0.22, 0.1])
        table.auto_set_font_size(False)
        table.set_fontsize(9)
        table.scale(1, 1.5)
        
        # Style header row
        for i in range(len(headers)):
            cell = table[(0, i)]
            cell.set_facecolor('#2196F3')
            cell.set_text_props(weight='bold', color='white')
        
        # Alternate row colors
        for i in range(1, len(data)):
            for j in range(len(headers)):
                cell = table[(i, j)]
                if i % 2 == 0:
                    cell.set_facecolor('#e3f2fd')
                else:
                    cell.set_facecolor('white')
        
        ax.axis('off')
    
    def compare_subnets(self, subnet_list: List[str]) -> None:
        """
        Compare multiple subnets visually.
        
        Args:
            subnet_list: List of subnet strings in CIDR notation
        """
        networks = []
        for subnet_str in subnet_list:
            try:
                networks.append(ipaddress.ip_network(subnet_str, strict=False))
            except ValueError as e:
                print(f"Error parsing {subnet_str}: {e}")
                return
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 10))
        fig.suptitle('Subnet Comparison', fontsize=16, fontweight='bold')
        
        # Top: Size comparison bar chart
        self._plot_size_comparison(ax1, networks)
        
        # Bottom: IP range timeline
        self._plot_ip_timeline(ax2, networks)
        
        plt.tight_layout()
        plt.show()
    
    def _plot_size_comparison(self, ax, networks: List[ipaddress.IPv4Network]) -> None:
        """Plot size comparison of subnets."""
        ax.set_title('Subnet Size Comparison', fontweight='bold')
        
        labels = [str(net) for net in networks]
        sizes = [net.num_addresses for net in networks]
        usable = [max(0, net.num_addresses - 2) for net in networks]
        
        x = np.arange(len(labels))
        width = 0.35
        
        bars1 = ax.bar(x - width/2, sizes, width, label='Total IPs',
                      color=self.colors[0], alpha=0.8)
        bars2 = ax.bar(x + width/2, usable, width, label='Usable Hosts',
                      color=self.colors[1], alpha=0.8)
        
        ax.set_xlabel('Subnet', fontweight='bold')
        ax.set_ylabel('Number of IP Addresses', fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=45, ha='right')
        ax.legend()
        ax.grid(True, alpha=0.3)
        
        # Add value labels on bars
        for bar in bars1:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{int(height):,}', ha='center', va='bottom', fontsize=9)
        
        for bar in bars2:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{int(height):,}', ha='center', va='bottom', fontsize=9)
    
    def _plot_ip_timeline(self, ax, networks: List[ipaddress.IPv4Network]) -> None:
        """Plot IP ranges on a timeline."""
        ax.set_title('IP Address Range Timeline', fontweight='bold')
        
        # Convert to numeric representation for plotting
        min_ip = min(int(net.network_address) for net in networks)
        max_ip = max(int(net.broadcast_address) for net in networks)
        ip_range = max_ip - min_ip
        
        # Plot each network as a horizontal bar
        for idx, net in enumerate(networks):
            start = int(net.network_address) - min_ip
            width = int(net.broadcast_address) - int(net.network_address)
            
            rect = Rectangle((start, idx), width, 0.8,
                           facecolor=self.colors[idx % len(self.colors)],
                           edgecolor='black', linewidth=1, alpha=0.8)
            ax.add_patch(rect)
            
            # Add label
            ax.text(start + width/2, idx + 0.4, str(net),
                   ha='center', va='center', fontweight='bold', fontsize=10)
            
            # Add start and end IPs
            ax.text(start, idx - 0.1, str(net.network_address),
                   ha='left', va='top', fontsize=8, rotation=45)
            ax.text(start + width, idx - 0.1, str(net.broadcast_address),
                   ha='right', va='top', fontsize=8, rotation=45)
        
        ax.set_xlim(-ip_range * 0.05, ip_range * 1.05)
        ax.set_ylim(-0.5, len(networks))
        ax.set_yticks(range(len(networks)))
        ax.set_yticklabels([f'Subnet {i+1}' for i in range(len(networks))])
        ax.set_xlabel('IP Address Range (relative)', fontweight='bold')
        ax.grid(True, alpha=0.3, axis='x')
    
    def visualize_vlsm(self, base_network: str, requirements: List[Tuple[str, int]]) -> None:
        """
        Visualize Variable Length Subnet Masking (VLSM) allocation.
        
        Args:
            base_network: Base network in CIDR notation
            requirements: List of (name, host_count) tuples
        """
        try:
            network = ipaddress.ip_network(base_network, strict=False)
        except ValueError as e:
            print(f"Error: {e}")
            return
        
        # Sort requirements by host count (largest first)
        requirements.sort(key=lambda x: x[1], reverse=True)
        
        # Calculate required subnets
        vlsm_subnets = []
        current_net = network
        
        for name, hosts_needed in requirements:
            # Calculate required subnet size
            # Need to account for network and broadcast addresses
            total_needed = hosts_needed + 2
            
            # Find the smallest power of 2 that fits
            subnet_size = 1
            while subnet_size < total_needed:
                subnet_size *= 2
            
            # Calculate prefix length
            host_bits = subnet_size.bit_length() - 1
            prefix_len = 32 - host_bits
            
            # Try to allocate subnet
            try:
                # Find available space
                for subnet in current_net.subnets(new_prefix=prefix_len):
                    # Check if this subnet overlaps with already allocated ones
                    overlap = False
                    for allocated_name, allocated_subnet in vlsm_subnets:
                        if subnet.overlaps(allocated_subnet):
                            overlap = True
                            break
                    
                    if not overlap:
                        vlsm_subnets.append((name, subnet))
                        break
            except:
                print(f"Cannot allocate subnet for {name} ({hosts_needed} hosts)")
        
        # Visualize VLSM allocation
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 12))
        fig.suptitle(f'VLSM Allocation for {base_network}', fontsize=16, fontweight='bold')
        
        # Top: VLSM tree/block diagram
        self._plot_vlsm_blocks(ax1, network, vlsm_subnets)
        
        # Bottom: Allocation table
        self._plot_vlsm_table(ax2, vlsm_subnets, requirements)
        
        plt.tight_layout()
        plt.show()
    
    def _plot_vlsm_blocks(self, ax, parent: ipaddress.IPv4Network, 
                         vlsm_subnets: List[Tuple[str, ipaddress.IPv4Network]]) -> None:
        """Plot VLSM allocation as blocks."""
        ax.set_title('VLSM Space Allocation', fontweight='bold')
        
        # Calculate positions based on IP ranges
        parent_size = parent.num_addresses
        y_pos = 0
        
        for idx, (name, subnet) in enumerate(vlsm_subnets):
            # Calculate relative position and size
            start_offset = int(subnet.network_address) - int(parent.network_address)
            width = subnet.num_addresses
            
            x_start = (start_offset / parent_size) * 10
            x_width = (width / parent_size) * 10
            
            # Draw subnet block
            rect = FancyBboxPatch(
                (x_start, y_pos), x_width, 0.8,
                boxstyle="round,pad=0.02",
                facecolor=self.colors[idx % len(self.colors)],
                edgecolor='black', linewidth=2, alpha=0.8
            )
            ax.add_patch(rect)
            
            # Add labels
            ax.text(x_start + x_width/2, y_pos + 0.4, name,
                   ha='center', va='center', fontweight='bold', fontsize=10)
            ax.text(x_start + x_width/2, y_pos + 0.2, str(subnet),
                   ha='center', va='center', fontsize=8)
            
            y_pos += 1
        
        # Add parent network reference
        ax.text(5, -0.5, f'Parent Network: {parent}',
               ha='center', va='center', fontweight='bold', fontsize=11)
        
        ax.set_xlim(-0.5, 10.5)
        ax.set_ylim(-1, len(vlsm_subnets))
        ax.set_xlabel('IP Space Utilization', fontweight='bold')
        ax.set_yticks([])
        ax.grid(True, alpha=0.3, axis='x')
    
    def _plot_vlsm_table(self, ax, vlsm_subnets: List[Tuple[str, ipaddress.IPv4Network]], 
                        requirements: List[Tuple[str, int]]) -> None:
        """Plot VLSM allocation table."""
        ax.set_title('VLSM Allocation Details', fontweight='bold')
        
        # Create requirement lookup
        req_dict = dict(requirements)
        
        # Prepare table data
        headers = ['Network Name', 'Required Hosts', 'Allocated Subnet', 
                  'Subnet Mask', 'Usable Hosts', 'Efficiency']
        data = [headers]
        
        total_required = 0
        total_allocated = 0
        
        for name, subnet in vlsm_subnets:
            required = req_dict.get(name, 0)
            usable = subnet.num_addresses - 2
            efficiency = (required / usable * 100) if usable > 0 else 0
            
            total_required += required
            total_allocated += usable
            
            data.append([
                name,
                str(required),
                str(subnet),
                str(subnet.netmask),
                str(usable),
                f'{efficiency:.1f}%'
            ])
        
        # Add summary row
        overall_efficiency = (total_required / total_allocated * 100) if total_allocated > 0 else 0
        data.append([
            'TOTAL',
            str(total_required),
            '-',
            '-',
            str(total_allocated),
            f'{overall_efficiency:.1f}%'
        ])
        
        # Create table
        table = ax.table(cellText=data, cellLoc='center', loc='center',
                        colWidths=[0.2, 0.15, 0.25, 0.2, 0.15, 0.15])
        table.auto_set_font_size(False)
        table.set_fontsize(9)
        table.scale(1, 1.5)
        
        # Style header row
        for i in range(len(headers)):
            cell = table[(0, i)]
            cell.set_facecolor('#FF9800')
            cell.set_text_props(weight='bold', color='white')
        
        # Style summary row
        for i in range(len(headers)):
            cell = table[(len(data)-1, i)]
            cell.set_facecolor('#FFC107')
            cell.set_text_props(weight='bold')
        
        # Alternate row colors
        for i in range(1, len(data)-1):
            for j in range(len(headers)):
                cell = table[(i, j)]
                if i % 2 == 0:
                    cell.set_facecolor('#fff3e0')
                else:
                    cell.set_facecolor('white')
        
        ax.axis('off')


def main():
    """Main function for command-line usage."""
    visualizer = SubnetVisualizer()
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python subnet_visualizer.py <subnet>")
        print("  python subnet_visualizer.py <subnet> <new_prefix>")
        print("  python subnet_visualizer.py compare <subnet1> <subnet2> ...")
        print("  python subnet_visualizer.py vlsm <base_network>")
        print("\nExamples:")
        print("  python subnet_visualizer.py 192.168.1.0/24")
        print("  python subnet_visualizer.py 192.168.1.0/24 26")
        print("  python subnet_visualizer.py compare 192.168.1.0/24 10.0.0.0/16")
        print("  python subnet_visualizer.py vlsm 192.168.1.0/24")
        sys.exit(1)
    
    if sys.argv[1] == 'compare':
        # Compare multiple subnets
        if len(sys.argv) < 3:
            print("Error: Please provide at least one subnet to compare")
            sys.exit(1)
        visualizer.compare_subnets(sys.argv[2:])
    
    elif sys.argv[1] == 'vlsm':
        # VLSM demonstration
        if len(sys.argv) < 3:
            # Use default example
            base = '192
