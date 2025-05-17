#!/usr/bin/env python3
"""
PCAP Analyzer v2.1 - Fragmentation & Security Specialist
"""

import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from collections import defaultdict
import sys
import os

def analyze_pcap(file_path):
    print(f"\n🔍 Analyzing {file_path}...")
    
    try:
        # Configure capture to focus on IP layers
        cap = pyshark.FileCapture(
            file_path,
            display_filter='ip',  # Only process IP packets
            keep_packets=False    # Save memory
        )
        
        stats = {
            'ipv4_fragments': 0,
            'icmp_packets': 0,
            'top_talkers': defaultdict(int),
            'protocol_dist': defaultdict(int),
            'fragment_sizes': [],
            # Security stats
            'icmp_requests': 0,
            'syn_packets': 0,
            'large_fragments': 0
        }

        for pkt in cap:
            try:
                # Basic IP info
                src = pkt.ip.src
                dst = pkt.ip.dst
                proto = pkt.highest_layer
                length = int(pkt.length)
                
                stats['protocol_dist'][proto] += 1
                stats['top_talkers'][src] += 1
                
                # Fragmentation detection
                if hasattr(pkt.ip, 'flags_mf'):
                    if pkt.ip.flags_mf == '1':
                        stats['ipv4_fragments'] += 1
                        stats['fragment_sizes'].append(length)
                        print(f"🚩 Fragment: {src} → {dst} | ID: {pkt.ip.id} | Size: {length}B")
                
                # ICMP specific analysis
                if 'ICMP' in proto:
                    stats['icmp_packets'] += 1
                
                # Security analysis
                detect_anomalies(pkt, stats)
                    
            except AttributeError as e:
                continue  # Skip non-IP packets

        # Generate report
        generate_report(stats, file_path)
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)

def detect_anomalies(pkt, stats):
    """Detect potential security threats"""
    try:
        # Ping flood detection (too many ICMP requests)
        if 'ICMP' in pkt.highest_layer and hasattr(pkt, 'icmp') and pkt.icmp.type == '8':
            stats['icmp_requests'] += 1
        
        # Possible port scan (many SYN packets)
        if 'TCP' in pkt.highest_layer and hasattr(pkt, 'tcp'):
            if pkt.tcp.flags_syn == '1' and pkt.tcp.flags_ack == '0':
                stats['syn_packets'] += 1
        
        # Large fragmented packets (possible DoS)
        if hasattr(pkt.ip, 'flags_mf'):
            if pkt.ip.flags_mf == '1' and int(pkt.length) > 1000:
                stats['large_fragments'] += 1
    except:
        pass  # Skip if any attribute is missing

def generate_report(stats, filename):
    """Generate visualizations and console output"""
    base_name = os.path.splitext(filename)[0]
    
    print("\n📊 Analysis Report")
    print("="*40)
    print(f"Total Packets: {sum(stats['protocol_dist'].values())}")
    print(f"IPv4 Fragments: {stats['ipv4_fragments']}")
    print(f"ICMP Packets: {stats['icmp_packets']}")
    
    # Security Alerts
    if stats['icmp_requests'] > 50 or stats['syn_packets'] > 20 or stats['large_fragments'] > 0:
        print("\n⚠️ Security Alerts:")
        if stats['icmp_requests'] > 50:
            print(f"- ICMP Flood: {stats['icmp_requests']} ping requests (possible ping flood)")
        if stats['syn_packets'] > 20:
            print(f"- SYN Packets: {stats['syn_packets']} (possible port scan)")
        if stats['large_fragments'] > 0:
            print(f"- Oversized Fragments: {stats['large_fragments']} (possible fragmentation attack)")
    
    # Protocol Distribution Pie Chart
    plt.figure(figsize=(10, 5))
    pd.Series(stats['protocol_dist']).plot.pie(
        autopct='%1.1f%%',
        title="Protocol Distribution"
    )
    plt.savefig(f"{base_name}_protocols.png")
    
    # Fragment Size Histogram
    if stats['fragment_sizes']:
        plt.figure(figsize=(10, 5))
        pd.Series(stats['fragment_sizes']).plot.hist(
            bins=20,
            title="Fragment Size Distribution",
            xlabel="Bytes",
            ylabel="Count"
        )
        plt.savefig(f"{base_name}_frag_sizes.png")
    
    # Security Alerts Plot
    plt.figure(figsize=(10, 3))
    security_data = {
        'ICMP Flood': stats['icmp_requests'],
        'SYN Packets': stats['syn_packets'],
        'Oversized Fragments': stats['large_fragments']
    }
    pd.Series(security_data).plot.bar(color=['red', 'orange', 'yellow'])
    plt.title("Security Alerts")
    plt.savefig(f"{base_name}_security.png")
    
    print(f"\n📈 Visualizations saved as:")
    print(f"- {base_name}_protocols.png")
    print(f"- {base_name}_frag_sizes.png")
    print(f"- {base_name}_security.png")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 pcap_analyzer.py <file.pcap>")
        sys.exit(1)
        
    analyze_pcap(sys.argv[1])