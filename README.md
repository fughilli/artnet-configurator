# ArtNet Configuration Tools

A collection of Python tools for reverse-engineering and configuring ArtNet → SPI controllers.

## Hardware

This toolset is designed for the **GICO-6612PRO** ArtNet controller:

- **US Supplier**: [SuperLightingLED](https://www.superlightingled.com/12ch-artnet-pixel-led-controller-support-madrix-online-and-sd-card-offline-for-dmx512-ttl-spi-addressasble-led-lights-p-5175.html)
- **AliExpress**: [GICO-6612PRO Controller](https://www.aliexpress.us/item/3256808083769079.html)

The controller supports:
- 12-channel ArtNet → SPI/TTL conversion
- DMX512 compatibility
- SD card offline mode
- Madrix integration
- Addressable LED control

## Overview

This project provides tools for:
- **Packet Analysis**: Dump and analyze ArtNet protocol packets from PCAP captures
- **Device Discovery**: Find ArtNet devices on the network
- **Device Configuration**: Configure IP addresses, channel settings, and universe assignments
- **Packet Diffing**: Interactive and command-line tools for comparing packet differences

## Installation

```bash
pip install -r requirements.txt
```

## Tools

### 1. Packet Analysis Tools

#### `pcap_dumper.py`
Dumps raw packet contents from PCAP/PCAPNG files to text format.

```bash
python3 pcap_dumper.py captures/device_discovery.pcapng
python3 pcap_dumper.py captures/device_configuration.pcapng
```

**Output**: Saves analysis to `captures/analysis/` directory

#### `artnet_analyzer.py`
Enhanced ArtNet-specific protocol analyzer that decodes ArtPoll, ArtPollReply, and ArtAddress packets.

```bash
python3 artnet_analyzer.py captures/device_discovery.pcapng
python3 artnet_analyzer.py captures/device_configuration.pcapng
```

**Output**: Saves detailed ArtNet analysis to `captures/analysis/` directory

### 2. Device Discovery & Configuration

#### `configure.py`
Main configuration utility with multiple subcommands.

**Basic Usage**:
```bash
sudo python3 configure.py --bind=192.168.0.100 [command] [options]
```

**Commands**:

##### Discover Devices
```bash
# Basic discovery
sudo python3 configure.py --bind=192.168.0.100 discover

# Discovery with config save
sudo python3 configure.py --bind=192.168.0.100 discover --save-config=devices.json
```

##### Configure Devices
```bash
# Single device configuration
sudo python3 configure.py --bind=192.168.0.100 configure single \
  --set-ip=2.0.99.61 \
  --target=2.0.99.50 \
  --channel-config=rgb \
  --universes-per-port=6

# Sequential IP assignment
sudo python3 configure.py --bind=192.168.0.100 configure sequential \
  --base-ip=2.0.99.50 \
  --channel-config=rgb \
  --universes-per-port=6 \
  --save-config=config.json

# Configuration from file
sudo python3 configure.py --bind=192.168.0.100 configure from_config \
  --config=devices.json \
  --channel-config=rgb \
  --universes-per-port=6
```

**Configuration Options**:
- `--channel-config`: `rgb`, `rgbw`, `rgbwa` (default: `rgb`)
- `--universes-per-port`: Number of universes per port (default: 1)
- `--debug`: Show hex dumps of configuration packets
- `--dry-run`: Show what would be configured without making changes

### 3. Packet Diffing Tools

#### `packet_diff_tool.py`
Interactive GUI tool for comparing packets from multiple PCAP files.

```bash
python3 packet_diff_tool.py
```

**Features**:
- Load multiple PCAP files
- Select packet pairs for comparison
- Colorized hex diff with ASCII decoding
- Dark highlighting for specific byte changes
- Interactive packet selection

#### `packet_diff_cli.py`
Command-line version for automated packet analysis.

```bash
# List outbound packets
python3 packet_diff_cli.py captures/device_configuration.pcapng --list

# Compare specific packets
python3 packet_diff_cli.py captures/device_configuration.pcapng --diff 1 3

# Analyze changes from baseline
python3 packet_diff_cli.py captures/device_configuration.pcapng --analyze 1
```

## Configuration File Format

### Discovery Output (`devices.json`)
```json
{
  "devices": [
    {
      "mac": "18:c0:4d:b7:bd:32",
      "current_ip": "2.0.99.50",
      "new_ip": "2.0.99.50",
      "name": "GICO-6612pro",
      "description": "GICO-6612PRO 12PORT DMX512&SPI #0006"
    }
  ],
  "timestamp": "2024-01-15 14:30:25",
  "discovery_info": {
    "total_devices": 2,
    "source": "discovery"
  }
}
```

### Configuration with Settings
```json
{
  "devices": [...],
  "settings": {
    "channel_config": "rgb",
    "universes_per_port": 6
  }
}
```

## Workflow Examples

### 1. Initial Device Discovery
```bash
# Discover devices and save configuration
sudo python3 configure.py --bind=192.168.0.100 discover --save-config=devices.json

# Edit the JSON file to set new IP addresses
# Then configure from file
sudo python3 configure.py --bind=192.168.0.100 configure from_config \
  --config=devices.json \
  --channel-config=rgb \
  --universes-per-port=6
```

### 2. Sequential IP Assignment
```bash
# Automatically assign sequential IPs
sudo python3 configure.py --bind=192.168.0.100 configure sequential \
  --base-ip=2.0.99.50 \
  --channel-config=rgb \
  --universes-per-port=6 \
  --save-config=final_config.json
```

### 3. Single Device Configuration
```bash
# Configure a specific device
sudo python3 configure.py --bind=192.168.0.100 configure single \
  --set-ip=2.0.99.61 \
  --target=2.0.99.50 \
  --channel-config=rgb \
  --universes-per-port=6 \
  --debug
```

## Protocol Analysis

### ArtNet Packet Structure
- **ArtPoll (OpCode 0x2000)**: Device discovery
- **ArtPollReply (OpCode 0x2100)**: Device response with capabilities
- **ArtAddress (OpCode 0x6000)**: Configuration commands

### IP Configuration
IP addresses are encoded directly in bytes 12-15 of ArtAddress packets:
```
Art-Net header (8 bytes) + OpCode (2 bytes) + Command (2 bytes) + IP (4 bytes) + ...
```

### Channel Configuration
- `rgb`: 3 channels per universe
- `rgbw`: 4 channels per universe  
- `rgbwa`: 5 channels per universe

## Network Requirements

- **Interface Binding**: Use `--bind` to specify the network interface
- **Layer 2 Sending**: Configuration packets are sent as raw Ethernet frames
- **MAC Discovery**: ARP resolution is used to find target MAC addresses
- **Broadcast Support**: Discovery uses UDP broadcast on port 6454

## Troubleshooting

### Common Issues

1. **"No route to host"**: Normal for configuration packets, verification may fail
2. **"Can't assign requested address"**: Use `0.0.0.0` or a valid interface IP for `--bind`
3. **Duplicate devices**: Discovery deduplicates by IP address
4. **MAC "Unknown"**: ARP resolution may fail, but configuration continues

### Debug Options
- Use `--debug` flag to see hex dumps of configuration packets
- Use `--dry-run` to preview configuration without making changes
- Check `captures/analysis/` for detailed packet analysis

## Dependencies

- `scapy>=2.4.5`: Packet manipulation and network tools
- `tkinter`: GUI components (included with Python)
- Standard library: `argparse`, `socket`, `struct`, `json`, `time`, `enum`

## References

- **[ArtNet 4 Specification](https://art-net.org.uk/downloads/art-net.pdf)**: Official ArtNet protocol documentation from Artistic Licence
- **[GICO-6612PRO Product Datasheet](https://www.superlightingled.com/PDF/ARTNET%20Controller/GC-6612pro-EN.pdf)**: Technical specifications and user manual for the controller
