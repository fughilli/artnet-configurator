#!/usr/bin/env python3
"""
ArtNet Protocol Analyzer

This script analyzes PCAP files specifically for ArtNet protocol packets
and decodes their structure for reverse-engineering ArtNet -> SPI controllers.
"""

import sys
import os
from datetime import datetime
from scapy.all import rdpcap, IP, UDP, Raw
import argparse
import struct

# ArtNet OpCodes
ARTNET_OPCODES = {
    0x2000: "ArtPoll",
    0x2100: "ArtPollReply", 
    0x6000: "ArtDmx",
    0xfd00: "ArtAddress",  # This appears in our captures
}

def decode_artnet_header(payload):
    """Decode ArtNet packet header."""
    if len(payload) < 10:
        return None, "Payload too short for ArtNet header"
    
    # ArtNet header: "Art-Net" + null + opcode (little endian) + protocol version
    header = payload[:10]
    
    if header[:8] != b'Art-Net\x00':
        return None, "Not an ArtNet packet"
    
    opcode = struct.unpack('<H', header[8:10])[0]
    opcode_name = ARTNET_OPCODES.get(opcode, f"Unknown({opcode:04x})")
    
    return {
        'opcode': opcode,
        'opcode_name': opcode_name,
        'protocol_version': struct.unpack('<H', payload[10:12])[0] if len(payload) >= 12 else 0
    }, None

def decode_artpoll(payload):
    """Decode ArtPoll packet."""
    if len(payload) < 14:
        return "ArtPoll packet too short"
    
    header, error = decode_artnet_header(payload)
    if error:
        return error
    
    # ArtPoll specific fields
    talk_to_me = payload[12] if len(payload) > 12 else 0
    priority = payload[13] if len(payload) > 13 else 0
    
    return f"ArtPoll - TalkToMe: {talk_to_me:02x}, Priority: {priority:02x}"

def decode_artpoll_reply(payload):
    """Decode ArtPollReply packet."""
    if len(payload) < 238:
        return "ArtPollReply packet too short"
    
    header, error = decode_artnet_header(payload)
    if error:
        return error
    
    # Extract device information
    ip_address = '.'.join(str(b) for b in payload[12:16])
    port = struct.unpack('<H', payload[16:18])[0]
    version_info = struct.unpack('<H', payload[18:20])[0]
    net_switch = payload[20]
    sub_switch = payload[21]
    oem = struct.unpack('<H', payload[22:24])[0]
    ubea_version = payload[24]
    status1 = payload[25]
    esta_code = struct.unpack('<H', payload[26:28])[0]
    short_name = payload[28:44].decode('ascii', errors='ignore').rstrip('\x00')
    long_name = payload[44:172].decode('ascii', errors='ignore').rstrip('\x00')
    node_report = payload[172:204].decode('ascii', errors='ignore').rstrip('\x00')
    num_ports = struct.unpack('<H', payload[204:206])[0]
    port_types = payload[206:210]
    good_input = payload[210:214]
    good_output = payload[214:218]
    sw_in = payload[218:222]
    sw_out = payload[222:226]
    acn_priority = payload[226]
    sw_macro = payload[227]
    sw_remote = payload[228]
    spare1 = payload[229]
    spare2 = payload[230]
    spare3 = payload[231]
    style = payload[232]
    mac_address = ':'.join(f'{b:02x}' for b in payload[233:239])
    
    # Additional fields if present
    bind_index = payload[238] if len(payload) > 238 else 0
    status2 = payload[239] if len(payload) > 239 else 0
    
    return f"""ArtPollReply:
  IP: {ip_address}:{port}
  Version: {version_info:04x}
  Net/Sub: {net_switch}/{sub_switch}
  OEM: {oem:04x}
  Short Name: {short_name}
  Long Name: {long_name}
  Node Report: {node_report}
  Ports: {num_ports}
  MAC: {mac_address}
  Style: {style:02x}
  Bind Index: {bind_index}
  Status2: {status2:02x}"""

def decode_artaddress(payload):
    """Decode ArtAddress packet."""
    if len(payload) < 14:
        return "ArtAddress packet too short"
    
    header, error = decode_artnet_header(payload)
    if error:
        return error
    
    # ArtAddress specific fields
    short_name = payload[12:28].decode('ascii', errors='ignore').rstrip('\x00')
    long_name = payload[28:156].decode('ascii', errors='ignore').rstrip('\x00')
    sub_switch = payload[156]
    net_switch = payload[157]
    command = payload[158]
    
    # Additional data
    additional_data = payload[159:] if len(payload) > 159 else b''
    
    return f"""ArtAddress:
  Short Name: {short_name}
  Long Name: {long_name}
  Sub Switch: {sub_switch}
  Net Switch: {net_switch}
  Command: {command:02x}
  Additional Data: {additional_data.hex()}"""

def analyze_artnet_packet(packet, packet_num):
    """Analyze a single packet for ArtNet protocol information."""
    result = []
    
    # Basic packet info
    if IP in packet:
        result.append(f"  Source IP: {packet[IP].src}")
        result.append(f"  Destination IP: {packet[IP].dst}")
    
    if UDP in packet:
        result.append(f"  Source Port: {packet[UDP].sport}")
        result.append(f"  Destination Port: {packet[UDP].dport}")
        
        # Check if this might be ArtNet (ArtNet typically uses port 6454)
        if packet[UDP].dport == 6454 or packet[UDP].sport == 6454:
            result.append("  *** ARTNET PACKET DETECTED ***")
    
    if Raw in packet:
        payload = packet[Raw].load
        
        # Try to decode as ArtNet
        if payload.startswith(b'Art-Net\x00'):
            result.append("  ArtNet Protocol Analysis:")
            
            # Decode based on opcode
            if len(payload) >= 10:
                opcode = struct.unpack('<H', payload[8:10])[0]
                
                if opcode == 0x2000:
                    result.append(f"    {decode_artpoll(payload)}")
                elif opcode == 0x2100:
                    result.append(f"    {decode_artpoll_reply(payload)}")
                elif opcode == 0xfd00:
                    result.append(f"    {decode_artaddress(payload)}")
                else:
                    result.append(f"    Unknown ArtNet OpCode: {opcode:04x}")
                    result.append(f"    Payload: {payload.hex()}")
        else:
            result.append(f"  Payload Length: {len(payload)} bytes")
            result.append("  Payload Hex Dump:")
            result.append(hex_dump(payload))
    
    return result

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

def analyze_pcap_file(pcap_file, output_file=None):
    """Analyze a PCAP file for ArtNet protocol."""
    if not os.path.exists(pcap_file):
        print(f"Error: File {pcap_file} not found.")
        return
    
    print(f"Reading PCAP file: {pcap_file}")
    packets = rdpcap(pcap_file)
    print(f"Found {len(packets)} packets")
    
    output_lines = []
    output_lines.append(f"ArtNet Protocol Analysis: {pcap_file}")
    output_lines.append(f"Total Packets: {len(packets)}")
    output_lines.append(f"Analysis Time: {datetime.now().isoformat()}")
    output_lines.append("=" * 80)
    output_lines.append("")
    
    artnet_packets = 0
    
    for i, packet in enumerate(packets):
        # Only analyze packets with UDP and potential ArtNet content
        if UDP in packet and Raw in packet:
            payload = packet[Raw].load
            if payload.startswith(b'Art-Net\x00'):
                artnet_packets += 1
                output_lines.append(f"ArtNet Packet {artnet_packets}:")
                
                # Handle timestamp
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
                output_lines.append("-" * 80)
                output_lines.append("")
    
    output_lines.append(f"Total ArtNet packets found: {artnet_packets}")
    
    # Write to file or stdout
    if output_file:
        with open(output_file, 'w') as f:
            f.write('\n'.join(output_lines))
        print(f"ArtNet analysis written to: {output_file}")
    else:
        print('\n'.join(output_lines))

def main():
    parser = argparse.ArgumentParser(description='Analyze PCAP files for ArtNet protocol')
    parser.add_argument('pcap_file', help='PCAP file to analyze')
    parser.add_argument('-o', '--output', help='Output file (default: auto-generated in captures/analysis/)')
    
    args = parser.parse_args()
    
    # Auto-generate output filename if not specified
    if not args.output:
        import os
        pcap_basename = os.path.splitext(os.path.basename(args.pcap_file))[0]
        output_dir = os.path.join('captures', 'analysis')
        os.makedirs(output_dir, exist_ok=True)
        args.output = os.path.join(output_dir, f"{pcap_basename}_artnet.txt")
    
    analyze_pcap_file(args.pcap_file, args.output)

if __name__ == "__main__":
    main() 