#!/usr/bin/env python3
"""
ArtNet Device Configuration Utility

This script allows configuring ArtNet devices using the reverse-engineered
protocol from the Windows configuration utility.
"""

import socket
import struct
import argparse
import time
import ipaddress
from typing import List, Optional

class ArtNetConfigurator:
    """ArtNet device configurator using reverse-engineered protocol."""
    
    def __init__(self, bind_ip: str = "0.0.0.0", bind_port: int = 6454):
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.socket = None
        
    def start(self):
        """Start the configurator."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        # Bind to the specified interface IP if provided, otherwise use 0.0.0.0
        bind_ip = self.bind_ip if self.bind_ip != "0.0.0.0" else "0.0.0.0"
        try:
            self.socket.bind((bind_ip, self.bind_port))
            print(f"ArtNet configurator started on {bind_ip}:{self.bind_port}")
        except OSError as e:
            if "Can't assign requested address" in str(e):
                print(f"Error: Cannot bind to {bind_ip}. This IP address may not be available on your system.")
                print("Try using --bind=0.0.0.0 to bind to all interfaces, or specify a valid IP address.")
                raise
            else:
                raise
        
    def stop(self):
        """Stop the configurator."""
        if self.socket:
            self.socket.close()
            
    def discover_devices(self, timeout: float = 5.0) -> List[dict]:
        """Discover ArtNet devices on the network."""
        print("Discovering ArtNet devices...")
        
        # Create ArtPoll packet
        artpoll = self._create_artpoll_packet()
        
        # Send broadcast
        self.socket.sendto(artpoll, ('255.255.255.255', 6454))
        
        # Listen for responses
        devices = {}  # Use dict to deduplicate by IP
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                self.socket.settimeout(0.1)
                data, addr = self.socket.recvfrom(1024)
                
                if self._is_artpoll_reply(data):
                    device = self._parse_artpoll_reply(data, addr)
                    if device:
                        # Use self-reported IP as key to deduplicate (each device sends multiple replies)
                        if device['self_reported_ip'] not in devices:
                            devices[device['self_reported_ip']] = device
                            print(f"Found device: self-reported={device['self_reported_ip']}, source={device['source_ip']} - {device['short_name']}")
                        
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Error during discovery: {e}")
                
        device_list = list(devices.values())
        print(f"Discovery complete. Found {len(device_list)} unique devices.")
        return device_list
        
    def _create_artpoll_packet(self) -> bytes:
        """Create ArtPoll packet."""
        packet = b'Art-Net\x00'  # ID
        packet += struct.pack('<H', 0x2000)  # OpCode (ArtPoll)
        packet += struct.pack('<H', 0x0000)  # Protocol version
        packet += b'\x00'  # TalkToMe
        packet += b'\x00'  # Priority
        return packet
        
    def _is_artpoll_reply(self, data: bytes) -> bool:
        """Check if packet is an ArtPollReply."""
        return (len(data) >= 10 and 
                data.startswith(b'Art-Net\x00') and
                struct.unpack('<H', data[8:10])[0] == 0x2100)
                
    def _parse_artpoll_reply(self, data: bytes, addr: tuple) -> Optional[dict]:
        """Parse ArtPollReply packet."""
        if len(data) < 238:
            return None
            
        try:
            # Extract device information
            # IP address is at bytes 10-13 in the format [first_octet] [second_octet] [third_octet] [fourth_octet]
            # Based on Wireshark data: 02 00 63 32 = 2.0.99.50
            ip_bytes = data[10:14]
            # Reconstruct IP: [first] [second] [third] [fourth]
            self_reported_ip = f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"
            port = struct.unpack('<H', data[16:18])[0]
            short_name = data[28:44].decode('ascii', errors='ignore').rstrip('\x00')
            long_name = data[44:172].decode('ascii', errors='ignore').rstrip('\x00')
            
            return {
                'self_reported_ip': self_reported_ip,
                'source_ip': addr[0],  # IP address from the network frame
                'port': port,
                'short_name': short_name,
                'long_name': long_name,
                'addr': addr
            }
        except Exception as e:
            print(f"Error parsing ArtPollReply: {e}")
            return None
            
    def set_ip_address(self, target_ip: str, new_ip: str):
        """Set IP address on a target device."""
        try:
            # Validate IP addresses
            ipaddress.ip_address(target_ip)
            ipaddress.ip_address(new_ip)
        except ValueError as e:
            print(f"Invalid IP address: {e}")
            return False
            
        print(f"Setting IP address on {target_ip} to {new_ip}...")
        
        # Create IP configuration packet
        config_packet = self._create_ip_config_packet(new_ip)
        
        # Send to target device
        self.socket.sendto(config_packet, (target_ip, 6454))
        
        print(f"IP configuration packet sent to {target_ip}")
        return True
        
    def _create_ip_config_packet(self, ip: str) -> bytes:
        """Create IP configuration packet based on reverse-engineered protocol."""
        # Parse IP address
        ip_parts = [int(x) for x in ip.split('.')]
        
        # Create packet based on observed pattern from PCAP analysis
        packet = b'Art-Net\x00'  # ID
        packet += struct.pack('<H', 0xfd00)  # OpCode (ArtAddress)
        packet += struct.pack('<H', 0x0000)  # Protocol version
        
        # Based on the PCAP analysis, the IP address appears to be encoded
        # in a specific pattern. Let me create the packet structure:
        
        # Protocol version and command type (observed pattern)
        packet += struct.pack('<H', 0x7402)  # Protocol version + command type
        
        # IP address in the observed format (based on PCAP analysis)
        # The pattern shows: 02 00 63 32 for 2.0.99.50
        # and: 02 00 63 33 for 2.0.99.51
        # This suggests the IP is encoded as: [second_octet] [first_octet] [third_octet] [fourth_octet]
        packet += struct.pack('<BBBB', ip_parts[1], ip_parts[0], ip_parts[2], ip_parts[3])
        
        # Additional configuration data (based on observed packets)
        packet += b'\x06'  # Command type (observed)
        packet += b'\x00\x00\x06\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x06\x00\x07'
        packet += b'\x06\x00\x0d\x06\x00\x13\x06\x00\x19\x06\x00\x1f\x06\x00\x25\x06'
        packet += b'\x00\x2b\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        
        return packet

def main():
    """Main function for the configuration utility."""
    parser = argparse.ArgumentParser(description='ArtNet Device Configuration Utility')
    parser.add_argument('--bind', default='0.0.0.0', help='Bind to specific network interface IP (default: 0.0.0.0 for all interfaces)')
    parser.add_argument('--port', type=int, default=6454, help='Bind port (default: 6454)')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Discover command
    discover_parser = subparsers.add_parser('discover', help='Discover ArtNet devices')
    discover_parser.add_argument('--timeout', type=float, default=5.0, help='Discovery timeout in seconds')
    
    # Configure command
    config_parser = subparsers.add_parser('configure', help='Configure ArtNet devices')
    config_parser.add_argument('--set-ip', help='Set IP address (format: x.x.x.x)')
    config_parser.add_argument('--target', help='Target device IP address')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
        
    # Create configurator
    configurator = ArtNetConfigurator(args.bind, args.port)
    
    try:
        configurator.start()
        
        if args.command == 'discover':
            devices = configurator.discover_devices(args.timeout)
            if devices:
                print("\nDiscovered devices:")
                for device in devices:
                    print(f"  Self-reported: {device['self_reported_ip']}, Source: {device['source_ip']}")
                    print(f"    {device['short_name']} ({device['long_name']})")
                    print()
            else:
                print("No devices found.")
                
        elif args.command == 'configure':
            if args.set_ip and args.target:
                success = configurator.set_ip_address(args.target, args.set_ip)
                if success:
                    print("Configuration completed successfully.")
                    print("Note: Device may need to restart to apply new IP address.")
                else:
                    print("Configuration failed.")
            else:
                print("Error: --set-ip and --target are required for configure command.")
                
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        configurator.stop()

if __name__ == "__main__":
    main() 