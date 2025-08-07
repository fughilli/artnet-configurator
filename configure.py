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
import enum
from typing import List, Optional

class ChannelConfig(enum.Enum):
    """Channel configuration values."""
    CHANNEL_CONFIG_RGB = 0x00
    CHANNEL_CONFIG_RBG = 0x08
    CHANNEL_CONFIG_GRB = 0x10
    CHANNEL_CONFIG_GBR = 0x18
    CHANNEL_CONFIG_BRG = 0x20
    CHANNEL_CONFIG_BGR = 0x28

class ArtNetConfigurator:
    """ArtNet device configurator using reverse-engineered protocol."""
    
    def __init__(self, bind_ip: str = "0.0.0.0", bind_port: int = 6454, num_ports: int = 12):
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.num_ports = num_ports
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
            
    def set_config(self, new_ip: str, target_ip: str, channel_config: ChannelConfig, universes_per_port: int):
        """Set IP address on a target device."""
        try:
            # Validate IP addresses
            ipaddress.ip_address(new_ip)
            ipaddress.ip_address(target_ip)
        except ValueError as e:
            print(f"Invalid IP address: {e}")
            return False
            
        print(f"Setting IP address to {new_ip}...")
        
        # Create IP configuration packet based on packet diff analysis
        config_packet = self._create_config_packet(new_ip, channel_config, universes_per_port)
        
        # Send as broadcast (ArtNet configuration packets are broadcast)
        self.socket.sendto(config_packet, (target_ip, 6454))
        
        print(f"IP configuration packet broadcast to network")
        
        # Wait a moment for the device to process the configuration
        time.sleep(1)
        
        # Verify the change by polling for the device at the new IP
        print(f"Verifying configuration by polling {new_ip}...")
        self.socket.sendto(self._create_artpoll_packet(), (new_ip, 6454))
        
        # Listen for response from the new IP
        try:
            self.socket.settimeout(3.0)
            data, addr = self.socket.recvfrom(1024)
            if self._is_artpoll_reply(data) and addr[0] == new_ip:
                print(f"✅ Success! Device now responds at {new_ip}")
                return True
            else:
                print(f"⚠️  Device may not have updated to {new_ip}")
                return False
        except socket.timeout:
            print(f"⚠️  No response from {new_ip} - device may not have updated")
            return False
        
        return True
        
    def _create_config_packet(self, ip: str, channel_config: ChannelConfig, universes_per_port: int) -> bytes:
        """Create IP configuration packet based on reverse-engineered protocol."""
        # Parse IP address
        ip_parts = [int(x) for x in ip.split('.')]
        
        # Create packet based on packet diff analysis findings
        packet = b'Art-Net\x00'  # ID (8 bytes)
        packet += struct.pack('>H', 0xfd00)  # OpCode (ArtAddress) - bytes 8-9
        packet += struct.pack('<B', 0x74)    # Protocol version
        
        # IP address assignment at bytes 11-14 (direct byte representation, not little-endian)
        # Based on packet diff analysis: 02 00 63 3c = 2.0.99.60
        packet += struct.pack('<BBBB', ip_parts[0], ip_parts[1], ip_parts[2], ip_parts[3])
        
        # Configuration data (bytes 16+) - using observed pattern from PCAP
        # This is the standard configuration data observed in successful IP config packets
        packet += b'\x06'
        packet += struct.pack('<B', channel_config.value)
        packet += b'\x00'
        packet += struct.pack('<B', universes_per_port)
        packet += b'\x00\x01\x00\x00\x00\x00\x00\x00'
        universe_offset = 1
        for i in range(self.num_ports):
            packet += struct.pack('<BBB', 0, universe_offset, universes_per_port)
            universe_offset += universes_per_port

        packet += b'\x00' * (128 - len(packet))
        
        return packet
        
    def _hex_dump(self, data: bytes, length: int = 16) -> str:
        """Create a hex dump of binary data for debugging."""
        if not data:
            return ""
        
        result = []
        for i in range(0, len(data), length):
            chunk = data[i:i + length]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            result.append(f'{i:04x}: {hex_part:<{length*3}} |{ascii_part}|')
        
        return '\n'.join(result)

CHANNEL_CONFIG_MAP = {
    name.replace('CHANNEL_CONFIG_', '').lower(): member
    for name, member in ChannelConfig.__members__.items()
}

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
    config_parser.add_argument('--target-ip', default='255.255.255.255', help='Target device IP address to configure (format: x.x.x.x)')
    config_parser.add_argument(
        '--channel-config',
        type=lambda x: CHANNEL_CONFIG_MAP[x.lower()],
        default='rgb',
        help='Channel configuration (choices: {})'.format(', '.join(CHANNEL_CONFIG_MAP.keys()))
    )
    config_parser.add_argument('--universes-per-port', type=int, default=1, help='Universes per port')
    config_parser.add_argument('--debug', action='store_true', help='Show packet hex dump for debugging')
    
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
            # Create config packet for debugging if requested
            if args.debug:
                config_packet = configurator._create_config_packet(args.set_ip, args.channel_config, args.universes_per_port)
                print("Configuration packet hex dump:")
                print(configurator._hex_dump(config_packet))
                print()
            
            success = configurator.set_config(args.set_ip, args.target_ip, args.channel_config, args.universes_per_port)
            if success:
                print("Configuration completed successfully.")
            else:
                print("Configuration failed.")
                
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        configurator.stop()

if __name__ == "__main__":
    main() 
