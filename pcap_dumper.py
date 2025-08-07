#!/usr/bin/env python3
"""
PCAP Dumper for ArtNet Configuration Utility Analysis

This script reads PCAP capture files and dumps their contents to a textual format
for reverse-engineering ArtNet -> SPI controller communication.
"""

import sys
import os
from datetime import datetime
from scapy.all import rdpcap, IP, UDP, Raw
import argparse

def hex_dump(data, length=16):
    """Create a hex dump of binary data."""
    if not data:
        return ""
    
    result = []
    for i in range(0, len(data), length):
        chunk = data[i:i + length]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        result.append(f'{i:04x}: {hex_part:<{length*3}} |{ascii_part}|')
    
    return '\n'.join(result)

def analyze_artnet_packet(packet, packet_num):
    """Analyze a single packet for ArtNet protocol information."""
    result = []
    
    # Basic packet info
    if IP in packet:
        result.append(f"  Source IP: {packet[IP].src}")
        result.append(f"  Destination IP: {packet[IP].dst}")
        result.append(f"  Protocol: {packet[IP].proto}")
    
    if UDP in packet:
        result.append(f"  Source Port: {packet[UDP].sport}")
        result.append(f"  Destination Port: {packet[UDP].dport}")
        result.append(f"  Length: {packet[UDP].len}")
        
        # Check if this might be ArtNet (ArtNet typically uses port 6454)
        if packet[UDP].dport == 6454 or packet[UDP].sport == 6454:
            result.append("  *** POTENTIAL ARTNET PACKET ***")
    
    if Raw in packet:
        payload = packet[Raw].load
        result.append(f"  Payload Length: {len(payload)} bytes")
        result.append("  Payload Hex Dump:")
        result.append(hex_dump(payload))
        
        # Try to decode as text if it looks like text
        try:
            text = payload.decode('utf-8', errors='ignore')
            if any(c.isprintable() for c in text):
                result.append("  Payload as Text:")
                result.append(f"    {repr(text)}")
        except:
            pass
    
    return result

def dump_pcap_file(pcap_file, output_file=None):
    """Dump a PCAP file to textual format."""
    if not os.path.exists(pcap_file):
        print(f"Error: File {pcap_file} not found.")
        return
    
    print(f"Reading PCAP file: {pcap_file}")
    packets = rdpcap(pcap_file)
    print(f"Found {len(packets)} packets")
    
    output_lines = []
    output_lines.append(f"PCAP Analysis: {pcap_file}")
    output_lines.append(f"Total Packets: {len(packets)}")
    output_lines.append(f"Analysis Time: {datetime.now().isoformat()}")
    output_lines.append("=" * 80)
    output_lines.append("")
    
    for i, packet in enumerate(packets):
        output_lines.append(f"Packet {i+1}:")
        # Handle different timestamp formats
        try:
            if hasattr(packet, 'time'):
                timestamp = float(packet.time)
                output_lines.append(f"  Time: {datetime.fromtimestamp(timestamp).isoformat()}")
            else:
                output_lines.append(f"  Time: Unknown")
        except (TypeError, ValueError):
            output_lines.append(f"  Time: {packet.time}")
        output_lines.append(f"  Length: {len(packet)} bytes")
        
        # Analyze packet contents
        analysis = analyze_artnet_packet(packet, i+1)
        output_lines.extend(analysis)
        
        output_lines.append("")
        output_lines.append("-" * 40)
        output_lines.append("")
    
    # Write to file or stdout
    if output_file:
        with open(output_file, 'w') as f:
            f.write('\n'.join(output_lines))
        print(f"Analysis written to: {output_file}")
    else:
        print('\n'.join(output_lines))

def main():
    parser = argparse.ArgumentParser(description='Dump PCAP files to textual format for ArtNet analysis')
    parser.add_argument('pcap_file', help='PCAP file to analyze')
    parser.add_argument('-o', '--output', help='Output file (default: auto-generated in captures/analysis/)')
    
    args = parser.parse_args()
    
    # Auto-generate output filename if not specified
    if not args.output:
        import os
        pcap_basename = os.path.splitext(os.path.basename(args.pcap_file))[0]
        output_dir = os.path.join('captures', 'analysis')
        os.makedirs(output_dir, exist_ok=True)
        args.output = os.path.join(output_dir, f"{pcap_basename}_dump.txt")
    
    dump_pcap_file(args.pcap_file, args.output)

if __name__ == "__main__":
    main() 