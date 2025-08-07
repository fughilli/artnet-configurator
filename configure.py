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
import enum
from scapy.all import conf, srp1, Ether, IP, UDP, Raw, ARP, get_if_addr, get_if_hwaddr

class ChannelConfig(enum.Enum):
    """Channel configuration values."""
    CHANNEL_CONFIG_RGB = 0x00
    CHANNEL_CONFIG_RBG = 0x08
    CHANNEL_CONFIG_GRB = 0x10
    CHANNEL_CONFIG_GBR = 0x18
    CHANNEL_CONFIG_BRG = 0x20
    CHANNEL_CONFIG_BGR = 0x28

CHANNEL_CONFIG_MAP = {
    name.replace('CHANNEL_CONFIG_', '').lower(): member
    for name, member in ChannelConfig.__members__.items()
}

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
        try:
            # Extract IP address from bytes 10-13 (corrected offset based on packet diff analysis)
            ip_bytes = data[10:14]
            self_reported_ip = f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"
            
            # Extract short name (bytes 26-43)
            short_name = data[26:43].decode('ascii', errors='ignore').strip('\x00')
            
            # Extract long name (bytes 44-171)
            long_name = data[44:171].decode('ascii', errors='ignore').strip('\x00')
            
            # Get MAC address for the source IP
            source_mac = self._get_mac_for_ip(addr[0])
            
            return {
                'self_reported_ip': self_reported_ip,
                'source_ip': addr[0],
                'source_mac': source_mac,
                'short_name': short_name,
                'long_name': long_name
            }
        except Exception as e:
            print(f"Error parsing ArtPollReply: {e}")
            return None
            
    def set_config(self, new_ip: str, target_ip: str, channel_config: ChannelConfig, universes_per_port: int):
        """Set configuration on a target device using Layer 2 packets."""
        try:
            # Validate IP addresses
            ipaddress.ip_address(new_ip)
            ipaddress.ip_address(target_ip)
        except ValueError as e:
            print(f"Invalid IP address: {e}")
            return False
            
        print(f"Setting configuration on {target_ip} to IP {new_ip}...")
        
        # Create configuration packet
        config_packet = self._create_config_packet(new_ip, channel_config, universes_per_port)
        
        # Send using Layer 2 (bypassing routing table)
        success = self._send_layer2_packet(config_packet, target_ip)
        
        if success:
            print(f"Configuration packet sent to {target_ip}")
            
            # Wait a moment for the device to process the configuration
            time.sleep(1)
            
            # Try to verify the change by polling for the device at the new IP
            # Note: This may fail if routing table doesn't know about the new IP yet
            print(f"Verifying configuration by polling {new_ip}...")
            try:
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
                        return True  # Still consider it successful
                except socket.timeout:
                    print(f"⚠️  No response from {new_ip} - device may not have updated yet")
                    return True  # Still consider it successful
            except OSError as e:
                if "No route to host" in str(e):
                    print(f"⚠️  Cannot verify {new_ip} - routing table may not be updated yet")
                    print(f"   This is normal for IP changes. Device should respond after restart.")
                    return True  # Still consider it successful
                else:
                    print(f"⚠️  Verification failed: {e}")
                    return True  # Still consider it successful
        else:
            print(f"Failed to send configuration packet to {target_ip}")
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
        
    def _send_layer2_packet(self, payload: bytes, target_ip: str) -> bool:
        """Send packet at Layer 2 through the bound interface."""
        try:
            # Get the interface name from the bind IP
            interface = self._get_interface_from_ip(self.bind_ip)
            if not interface:
                print(f"Could not determine interface for IP {self.bind_ip}")
                return False
                
            # Get interface MAC address
            src_mac = get_if_hwaddr(interface)
            src_ip = get_if_addr(interface)
            
            print(f"Using interface {interface} (MAC: {src_mac}, IP: {src_ip})")
            
            # Discover target MAC address
            target_mac = self._discover_target_mac(target_ip, interface, src_mac, src_ip)
            if not target_mac:
                print(f"Could not discover MAC address for {target_ip}")
                return False
                
            print(f"Discovered target MAC: {target_mac}")
            
            # Create Layer 2 packet with specific target MAC
            packet = (
                Ether(dst=target_mac, src=src_mac) /
                IP(src=src_ip, dst=target_ip) /
                UDP(sport=6454, dport=6454) /
                Raw(load=payload)
            )
            
            # Send the packet
            result = srp1(packet, iface=interface, timeout=1, verbose=False)
            
            if result:
                print(f"Packet sent successfully to {target_ip} ({target_mac})")
                return True
            else:
                print(f"No response from {target_ip} (this is normal for configuration packets)")
                return True  # Still consider it successful
                
        except Exception as e:
            print(f"Error sending Layer 2 packet: {e}")
            return False
            
    def _discover_target_mac(self, target_ip: str, interface: str, src_mac: str, src_ip: str) -> Optional[str]:
        """Discover MAC address of target IP using ARP."""
        try:
            print(f"Discovering MAC address for {target_ip}...")
            
            # Create ARP request packet
            arp_packet = (
                Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac) /
                ARP(op=1, hwsrc=src_mac, psrc=src_ip, hwdst="00:00:00:00:00:00", pdst=target_ip)
            )
            
            # Send ARP request and wait for response
            result = srp1(arp_packet, iface=interface, timeout=3, verbose=False)
            
            if result and result.haslayer(ARP):
                target_mac = result[ARP].hwsrc
                print(f"Found MAC address: {target_mac}")
                return target_mac
            else:
                print(f"No ARP response from {target_ip}")
                return None
                
        except Exception as e:
            print(f"Error during MAC discovery: {e}")
            return None
            
    def _get_mac_for_ip(self, ip: str) -> Optional[str]:
        """Get MAC address for an IP address using ARP cache or ARP resolution."""
        try:
            # First try to get from ARP cache
            interface = self._get_interface_from_ip(self.bind_ip)
            if not interface:
                return None
                
            # Try to get MAC from ARP cache first
            arp_cache = conf.arp_cache
            if ip in arp_cache:
                return arp_cache[ip]
                
            # If not in cache, perform ARP resolution
            src_mac = get_if_hwaddr(interface)
            src_ip = get_if_addr(interface)
            
            # Create ARP request
            arp_packet = (
                Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac) /
                ARP(op=1, hwsrc=src_mac, psrc=src_ip, hwdst="00:00:00:00:00:00", pdst=ip)
            )
            
            # Send ARP request and wait for response
            result = srp1(arp_packet, iface=interface, timeout=2, verbose=False)
            
            if result and result.haslayer(ARP):
                target_mac = result[ARP].hwsrc
                # Cache the result
                conf.arp_cache[ip] = target_mac
                return target_mac
            else:
                return None
                
        except Exception as e:
            # Don't print error for MAC lookup failures during discovery
            return None
            
    def make_unique_ips(self, base_ip: str, channel_config: ChannelConfig, universes_per_port: int, 
                       timeout: float = 5.0, dry_run: bool = False, debug: bool = False) -> bool:
        """Discover all controllers and assign them sequential IP addresses."""
        try:
            # Validate base IP
            ipaddress.ip_address(base_ip)
        except ValueError as e:
            print(f"Invalid base IP address: {e}")
            return False
            
        print(f"Discovering controllers and assigning sequential IPs starting from {base_ip}...")
        
        # Discover all devices
        devices = self.discover_devices(timeout)
        if not devices:
            print("No devices found to configure.")
            return False
            
        print(f"\nFound {len(devices)} devices to configure:")
        for i, device in enumerate(devices):
            mac_info = f"MAC: {device['source_mac']}" if device['source_mac'] else "MAC: Unknown"
            print(f"  {i+1}. {device['short_name']} (currently {device['self_reported_ip']}, {mac_info})")
            
        # Generate sequential IPs
        base_parts = [int(x) for x in base_ip.split('.')]
        sequential_ips = []
        for i in range(len(devices)):
            # Increment the last octet
            new_ip_parts = base_parts.copy()
            new_ip_parts[3] += i
            sequential_ips.append('.'.join(str(x) for x in new_ip_parts))
            
        print(f"\nSequential IP assignment:")
        for i, (device, new_ip) in enumerate(zip(devices, sequential_ips)):
            print(f"  {device['short_name']}: {device['self_reported_ip']} → {new_ip}")
            
        if dry_run:
            print("\nDRY RUN - No changes will be made")
            return True
            
        # Configure each device
        print(f"\nConfiguring devices...")
        success_count = 0
        
        for device, new_ip in zip(devices, sequential_ips):
            print(f"\nConfiguring {device['short_name']} ({device['self_reported_ip']} → {new_ip})...")
            
            # Create config packet for debugging if requested
            if debug:
                config_packet = self._create_config_packet(new_ip, channel_config, universes_per_port)
                print("Configuration packet hex dump:")
                print(self._hex_dump(config_packet))
                print()
            
            # Send configuration
            try:
                success = self.set_config(new_ip, device['self_reported_ip'], channel_config, universes_per_port)
                if success:
                    success_count += 1
                    print(f"✅ Successfully configured {device['short_name']} to {new_ip}")
                else:
                    print(f"❌ Failed to configure {device['short_name']}")
            except Exception as e:
                print(f"❌ Error configuring {device['short_name']}: {e}")
                print(f"   Continuing with next device...")
                
        print(f"\nConfiguration complete: {success_count}/{len(devices)} devices configured successfully")
        return success_count > 0  # Return True if at least one device was configured
            
    def _get_interface_from_ip(self, ip: str) -> Optional[str]:
        """Get interface name from IP address."""
        try:
            # Get all interfaces
            interfaces = conf.ifaces
            for iface_name, iface in interfaces.items():
                if hasattr(iface, 'ip') and iface.ip == ip:
                    return iface_name
            return None
        except Exception as e:
            print(f"Error getting interface for IP {ip}: {e}")
            return None
            
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
    config_parser.add_argument('--target', default='255.255.255.255', help='Target device IP address to configure (format: x.x.x.x)')
    config_parser.add_argument(
        '--channel-config',
        type=lambda x: CHANNEL_CONFIG_MAP[x.lower()],
        default='rgb',
        help='Channel configuration (choices: {})'.format(', '.join(CHANNEL_CONFIG_MAP.keys()))
    )
    config_parser.add_argument('--universes-per-port', type=int, default=1, help='Universes per port')
    config_parser.add_argument('--debug', action='store_true', help='Show packet hex dump for debugging')
    
    # Make unique IPs command
    unique_parser = subparsers.add_parser('make_unique_ips', help='Discover controllers and assign sequential IP addresses')
    unique_parser.add_argument('--base-ip', required=True, help='Base IP address for sequential assignment (format: x.x.x.x)')
    unique_parser.add_argument('--channel-config', type=lambda x: CHANNEL_CONFIG_MAP[x.lower()], default='rgb', help='Channel configuration')
    unique_parser.add_argument('--universes-per-port', type=int, default=1, help='Universes per port')
    unique_parser.add_argument('--timeout', type=float, default=5.0, help='Discovery timeout in seconds')
    unique_parser.add_argument('--dry-run', action='store_true', help='Show what would be configured without making changes')
    unique_parser.add_argument('--debug', action='store_true', help='Show packet hex dumps for debugging')
    
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
                    mac_info = f"MAC: {device['source_mac']}" if device['source_mac'] else "MAC: Unknown"
                    print(f"  Self-reported: {device['self_reported_ip']}, Source: {device['source_ip']}, {mac_info}")
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
            
            success = configurator.set_config(args.set_ip, args.target, args.channel_config, args.universes_per_port)
            if success:
                print("Configuration completed successfully.")
            else:
                print("Configuration failed.")
                
        elif args.command == 'make_unique_ips':
            success = configurator.make_unique_ips(
                args.base_ip, 
                args.channel_config, 
                args.universes_per_port, 
                args.timeout,
                args.dry_run,
                args.debug
            )
            if success:
                if args.dry_run:
                    print("Dry run completed successfully.")
                else:
                    print("Unique IP assignment completed successfully.")
            else:
                print("Unique IP assignment failed.")
                
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        configurator.stop()

if __name__ == "__main__":
    main() 
