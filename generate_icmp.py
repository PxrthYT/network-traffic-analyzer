from scapy.all import *
import random

def create_proper_fragments(filename="correct_frags.pcap"):
    print("[+] Creating valid fragmented ICMP traffic...")
    
    packets = []
    for i in range(1, 6):  # 5 original packets
        # Create base packet
        ip = IP(dst="8.8.8.8", id=i, flags="MF")
        icmp = ICMP(type=8, id=random.randint(1, 1000), seq=i)
        payload = ("X" * 2000)  # Force fragmentation
        
        # Fragment manually
        frag1 = ip/icmp/payload[:1000]
        frag1[IP].flags = "MF"  # More fragments coming
        frag1[IP].frag = 0  # Offset 0
        
        frag2 = ip/icmp/payload[1000:]
        frag2[IP].frag = 1  # Offset 128 (8 bytes * 1)
        frag2[IP].flags = 0  # Last fragment
        
        packets.extend([frag1, frag2])
    
    wrpcap(filename, packets)
    print(f"[+] Created {filename} with {len(packets)} REAL fragments")

create_proper_fragments()