#!/usr/bin/env python3
"""
ArtNet Packet Diff Tool

A graphical tool for analyzing and diffing ArtNet configuration packets
to identify which octets change between different configuration commits.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import struct
import os
from typing import List, Dict, Tuple, Optional
from scapy.all import rdpcap, IP, UDP, Raw
import difflib

class PacketDiffTool:
    def __init__(self, root):
        self.root = root
        self.root.title("ArtNet Packet Diff Tool")
        self.root.geometry("1400x900")
        
        self.pcap_files = {}  # {filename: {packets: [], outbound_packets: []}}
        self.selected_packets = []
        
        self.setup_ui()
        
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # File management section
        file_frame = ttk.LabelFrame(main_frame, text="PCAP Files", padding="5")
        file_frame.grid(row=0, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=5)
        
        # File list
        ttk.Label(file_frame, text="Loaded Files:").grid(row=0, column=0, sticky=tk.W)
        
        # Create file listbox with scrollbar
        file_list_frame = ttk.Frame(file_frame)
        file_list_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.file_listbox = tk.Listbox(file_list_frame, height=4, selectmode=tk.SINGLE)
        file_scrollbar = ttk.Scrollbar(file_list_frame, orient=tk.VERTICAL, command=self.file_listbox.yview)
        self.file_listbox.configure(yscrollcommand=file_scrollbar.set)
        
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        file_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # File management buttons
        file_buttons_frame = ttk.Frame(file_frame)
        file_buttons_frame.grid(row=1, column=2, sticky=(tk.W, tk.E), padx=10)
        
        ttk.Button(file_buttons_frame, text="Add PCAP", command=self.add_pcap_file).pack(side=tk.TOP, pady=2)
        ttk.Button(file_buttons_frame, text="Remove PCAP", command=self.remove_pcap_file).pack(side=tk.TOP, pady=2)
        ttk.Button(file_buttons_frame, text="Clear All", command=self.clear_all_files).pack(side=tk.TOP, pady=2)
        
        # Bind file selection event
        self.file_listbox.bind('<<ListboxSelect>>', self.on_file_select)
        
        # Packet selection
        ttk.Label(main_frame, text="Outbound Packets:").grid(row=1, column=0, sticky=tk.W, pady=5)
        
        # Create notebook for different views
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=2, column=0, columnspan=4, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Packet list frame
        packet_frame = ttk.Frame(notebook)
        notebook.add(packet_frame, text="Packet List")
        
        # Packet list with file info
        packet_list_frame = ttk.Frame(packet_frame)
        packet_list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.packet_listbox = tk.Listbox(packet_list_frame, selectmode=tk.MULTIPLE)
        packet_scrollbar = ttk.Scrollbar(packet_list_frame, orient=tk.VERTICAL, command=self.packet_listbox.yview)
        self.packet_listbox.configure(yscrollcommand=packet_scrollbar.set)
        
        self.packet_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        packet_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind selection event
        self.packet_listbox.bind('<<ListboxSelect>>', self.on_packet_select)
        
        # Diff frame
        diff_frame = ttk.Frame(notebook)
        notebook.add(diff_frame, text="Packet Diff")
        
        # Diff controls
        diff_controls = ttk.Frame(diff_frame)
        diff_controls.pack(fill=tk.X, pady=5)
        
        ttk.Label(diff_controls, text="Baseline:").pack(side=tk.LEFT)
        self.baseline_var = tk.StringVar()
        self.baseline_combo = ttk.Combobox(diff_controls, textvariable=self.baseline_var, state="readonly", width=40)
        self.baseline_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(diff_controls, text="Compare:").pack(side=tk.LEFT, padx=(20, 0))
        self.compare_var = tk.StringVar()
        self.compare_combo = ttk.Combobox(diff_controls, textvariable=self.compare_var, state="readonly", width=40)
        self.compare_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(diff_controls, text="Show Diff", command=self.show_diff).pack(side=tk.LEFT, padx=20)
        
        # Diff display
        diff_display_frame = ttk.Frame(diff_frame)
        diff_display_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create text widget with scrollbars
        self.diff_text = tk.Text(diff_display_frame, wrap=tk.NONE, font=('Courier', 10))
        diff_scrollbar_y = ttk.Scrollbar(diff_display_frame, orient=tk.VERTICAL, command=self.diff_text.yview)
        diff_scrollbar_x = ttk.Scrollbar(diff_display_frame, orient=tk.HORIZONTAL, command=self.diff_text.xview)
        self.diff_text.configure(yscrollcommand=diff_scrollbar_y.set, xscrollcommand=diff_scrollbar_x.set)
        
        self.diff_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        diff_scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        diff_scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Configure text widget tags for colors
        self.diff_text.tag_configure("added", background="lightgreen", foreground="black")
        self.diff_text.tag_configure("removed", background="lightcoral", foreground="black")
        self.diff_text.tag_configure("unchanged", background="white", foreground="black")
        self.diff_text.tag_configure("header", background="lightblue", foreground="black", font=('Courier', 10, 'bold'))
        self.diff_text.tag_configure("file_header", background="lightyellow", foreground="black", font=('Courier', 10, 'bold'))
        
        # Darker highlight colors for specific octet changes
        self.diff_text.tag_configure("added_highlight", background="darkgreen", foreground="white")
        self.diff_text.tag_configure("removed_highlight", background="darkred", foreground="white")
        
    def add_pcap_file(self):
        """Add a PCAP file to the analysis."""
        filename = filedialog.askopenfilename(
            title="Select PCAP file",
            filetypes=[("PCAP files", "*.pcapng *.pcap"), ("All files", "*.*")]
        )
        if filename:
            try:
                # Load packets
                packets = rdpcap(filename)
                outbound_packets = self.extract_outbound_packets(packets)
                
                # Store in our data structure
                basename = os.path.basename(filename)
                self.pcap_files[basename] = {
                    'full_path': filename,
                    'packets': packets,
                    'outbound_packets': outbound_packets
                }
                
                # Update file list
                self.file_listbox.insert(tk.END, f"{basename} ({len(outbound_packets)} packets)")
                
                # Update packet list if this is the first file
                if len(self.pcap_files) == 1:
                    self.update_packet_list()
                
                messagebox.showinfo("Success", f"Loaded {basename}: {len(packets)} packets, {len(outbound_packets)} outbound ArtNet packets")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load PCAP file {filename}: {e}")
                
    def remove_pcap_file(self):
        """Remove selected PCAP file from analysis."""
        selection = self.file_listbox.curselection()
        if selection:
            index = selection[0]
            filename = self.file_listbox.get(index)
            basename = filename.split(' (')[0]  # Extract filename without packet count
            
            # Remove from data structure
            if basename in self.pcap_files:
                del self.pcap_files[basename]
            
            # Remove from listbox
            self.file_listbox.delete(index)
            
            # Update packet list
            self.update_packet_list()
            
    def clear_all_files(self):
        """Clear all loaded PCAP files."""
        self.pcap_files.clear()
        self.file_listbox.delete(0, tk.END)
        self.update_packet_list()
        
    def on_file_select(self, event):
        """Handle file selection."""
        # Update packet list when file selection changes
        self.update_packet_list()
        
    def extract_outbound_packets(self, packets):
        """Extract outbound ArtNet packets (host -> device)."""
        outbound_packets = []
        
        for i, packet in enumerate(packets):
            if UDP in packet and Raw in packet:
                payload = packet[Raw].load
                if payload.startswith(b'Art-Net\x00'):
                    # Check if this is an outbound packet (from host to device)
                    if IP in packet:
                        # Consider it outbound if it's a broadcast or to a specific device
                        if packet[IP].dst == '255.255.255.255' or packet[IP].dst.startswith('2.0.99.'):
                            outbound_packets.append({
                                'index': i,
                                'packet': packet,
                                'payload': payload,
                                'source': packet[IP].src,
                                'destination': packet[IP].dst,
                                'opcode': struct.unpack('<H', payload[8:10])[0] if len(payload) >= 10 else 0
                            })
        
        return outbound_packets
                            
    def update_packet_list(self):
        """Update the packet listbox with outbound packets from all files."""
        self.packet_listbox.delete(0, tk.END)
        
        all_packets = []
        
        for filename, file_data in self.pcap_files.items():
            for packet_info in file_data['outbound_packets']:
                opcode_name = self.get_opcode_name(packet_info['opcode'])
                display_text = f"[{filename}] Packet {packet_info['index']:3d}: {opcode_name} ({packet_info['source']} -> {packet_info['destination']})"
                
                # Store packet info with file reference
                packet_info['filename'] = filename
                all_packets.append((display_text, packet_info))
        
        # Sort by filename and packet index
        all_packets.sort(key=lambda x: (x[1]['filename'], x[1]['index']))
        
        for display_text, packet_info in all_packets:
            self.packet_listbox.insert(tk.END, display_text)
            
        # Update combo boxes
        packet_options = [display_text for display_text, _ in all_packets]
        self.baseline_combo['values'] = packet_options
        self.compare_combo['values'] = packet_options
        
        if packet_options:
            self.baseline_combo.set(packet_options[0])
            if len(packet_options) > 1:
                self.compare_combo.set(packet_options[1])
                
    def get_opcode_name(self, opcode):
        """Get human-readable name for ArtNet opcode."""
        opcodes = {
            0x2000: "ArtPoll",
            0x2100: "ArtPollReply",
            0x6000: "ArtDmx",
            0xfd00: "ArtAddress"
        }
        return opcodes.get(opcode, f"Unknown({opcode:04x})")
        
    def on_packet_select(self, event):
        """Handle packet selection."""
        selection = self.packet_listbox.curselection()
        self.selected_packets = []
        
        for index in selection:
            # Find the packet info for this selection
            display_text = self.packet_listbox.get(index)
            filename = display_text.split(']')[0][1:]  # Extract filename
            
            # Find the packet in our data structure
            for file_data in self.pcap_files.values():
                for packet_info in file_data['outbound_packets']:
                    if packet_info.get('filename') == filename:
                        self.selected_packets.append(packet_info)
                        break
        
    def show_diff(self):
        """Show diff between selected packets."""
        baseline_text = self.baseline_var.get()
        compare_text = self.compare_var.get()
        
        if not baseline_text or not compare_text:
            messagebox.showerror("Error", "Please select baseline and compare packets")
            return
            
        # Find the packets
        baseline_packet = None
        compare_packet = None
        
        # Search through all files for the selected packets
        for file_data in self.pcap_files.values():
            for packet_info in file_data['outbound_packets']:
                opcode_name = self.get_opcode_name(packet_info['opcode'])
                display_text = f"[{packet_info.get('filename', 'unknown')}] Packet {packet_info['index']:3d}: {opcode_name} ({packet_info['source']} -> {packet_info['destination']})"
                
                if display_text == baseline_text:
                    baseline_packet = packet_info
                elif display_text == compare_text:
                    compare_packet = packet_info
                    
        if not baseline_packet or not compare_packet:
            messagebox.showerror("Error", "Could not find selected packets")
            return
            
        self.display_diff(baseline_packet, compare_packet)
        
    def display_diff(self, baseline_packet, compare_packet):
        """Display a diff between two packets with highlighted octet changes."""
        self.diff_text.delete(1.0, tk.END)
        
        # Add file headers
        baseline_file = baseline_packet.get('filename', 'unknown')
        compare_file = compare_packet.get('filename', 'unknown')
        
        self.diff_text.insert(tk.END, f"Baseline: [{baseline_file}] Packet {baseline_packet['index']} ({baseline_packet['source']} -> {baseline_packet['destination']})\n", "file_header")
        self.diff_text.insert(tk.END, f"Compare:  [{compare_file}] Packet {compare_packet['index']} ({compare_packet['source']} -> {compare_packet['destination']})\n\n", "file_header")
        
        # Find specific byte differences
        baseline_data = baseline_packet['payload']
        compare_data = compare_packet['payload']
        byte_differences = self.find_byte_differences(baseline_data, compare_data)
        
        baseline_hex = self.hex_dump(baseline_packet['payload'])
        compare_hex = self.hex_dump(compare_packet['payload'])
        
        # Create diff with highlighted changes
        baseline_lines = baseline_hex.split('\n')
        compare_lines = compare_hex.split('\n')
        
        matcher = difflib.SequenceMatcher(None, baseline_lines, compare_lines)
        
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == 'equal':
                for line in baseline_lines[i1:i2]:
                    self.diff_text.insert(tk.END, f"  {line}\n", "unchanged")
            elif tag == 'replace':
                # Handle replaced lines with byte-level highlighting
                for line in baseline_lines[i1:i2]:
                    self.insert_highlighted_line(f"- {line}\n", line, byte_differences, is_removed=True)
                for line in compare_lines[j1:j2]:
                    self.insert_highlighted_line(f"+ {line}\n", line, byte_differences, is_removed=False)
            elif tag == 'delete':
                for line in baseline_lines[i1:i2]:
                    self.diff_text.insert(tk.END, f"- {line}\n", "removed")
            elif tag == 'insert':
                for line in compare_lines[j1:j2]:
                    self.diff_text.insert(tk.END, f"+ {line}\n", "added")
                    
    def hex_dump(self, data, length=16):
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
        
    def find_byte_differences(self, baseline_data: bytes, compare_data: bytes) -> List[Tuple[int, int, int]]:
        """Find specific byte differences between two data arrays.
        Returns list of (offset, old_value, new_value) tuples."""
        differences = []
        min_len = min(len(baseline_data), len(compare_data))
        
        for i in range(min_len):
            if baseline_data[i] != compare_data[i]:
                differences.append((i, baseline_data[i], compare_data[i]))
                
        return differences
        
    def highlight_byte_changes(self, hex_line: str, byte_differences: List[Tuple[int, int, int]], is_removed: bool) -> str:
        """Highlight specific byte changes in a hex dump line.
        Returns the line with special markers for highlighting."""
        if not byte_differences:
            return hex_line
            
        # Parse the hex line to find the offset
        # Format: "0000: 41 72 74 2d 4e 65 74 00 fd 00 74 02 00 63 3c 06 |Art-Net..t..c<.|"
        try:
            parts = hex_line.split(':')
            if len(parts) != 2:
                return hex_line
                
            offset_str = parts[0].strip()
            hex_part = parts[1].split('|')[0].strip()
            
            # Parse offset
            line_offset = int(offset_str, 16)
            
            # Split hex bytes
            hex_bytes = hex_part.split()
            
            # Check if any differences fall within this line
            line_highlights = []
            for diff_offset, old_val, new_val in byte_differences:
                if line_offset <= diff_offset < line_offset + len(hex_bytes):
                    byte_index = diff_offset - line_offset
                    if byte_index < len(hex_bytes):
                        # Mark this byte for highlighting
                        line_highlights.append((byte_index, old_val, new_val))
            
            if line_highlights:
                # Create highlighted version
                highlighted_bytes = []
                for i, hex_byte in enumerate(hex_bytes):
                    # Check if this byte should be highlighted
                    highlight_info = None
                    for byte_idx, old_val, new_val in line_highlights:
                        if byte_idx == i:
                            highlight_info = (old_val, new_val)
                            break
                    
                    if highlight_info:
                        # Add highlight marker
                        if is_removed:
                            highlighted_bytes.append(f"[[{hex_byte}]]")  # Dark red for removed
                        else:
                            highlighted_bytes.append(f"[[{hex_byte}]]")  # Dark green for added
                    else:
                        highlighted_bytes.append(hex_byte)
                
                # Reconstruct the line
                highlighted_hex = ' '.join(highlighted_bytes)
                return f"{offset_str}: {highlighted_hex:<{len(hex_part)}} |{parts[1].split('|')[1] if '|' in parts[1] else ''}|"
            
        except (ValueError, IndexError):
            pass
            
        return hex_line
        
    def insert_highlighted_line(self, prefix: str, hex_line: str, byte_differences: List[Tuple[int, int, int]], is_removed: bool):
        """Insert a hex line with byte-level highlighting applied."""
        if not byte_differences:
            # No differences, insert normally
            tag = "removed" if is_removed else "added"
            self.diff_text.insert(tk.END, prefix, tag)
            return
            
        # Parse the hex line to find the offset
        try:
            parts = hex_line.split(':')
            if len(parts) != 2:
                # Can't parse, insert normally
                tag = "removed" if is_removed else "added"
                self.diff_text.insert(tk.END, prefix, tag)
                return
                
            offset_str = parts[0].strip()
            hex_part = parts[1].split('|')[0].strip()
            
            # Parse offset
            line_offset = int(offset_str, 16)
            
            # Split hex bytes
            hex_bytes = hex_part.split()
            
            # Check if any differences fall within this line
            line_highlights = []
            for diff_offset, old_val, new_val in byte_differences:
                if line_offset <= diff_offset < line_offset + len(hex_bytes):
                    byte_index = diff_offset - line_offset
                    if byte_index < len(hex_bytes):
                        # Mark this byte for highlighting
                        line_highlights.append((byte_index, old_val, new_val))
            
            if line_highlights:
                # Insert with highlighting
                self.diff_text.insert(tk.END, prefix[:2])  # "- " or "+ "
                
                # Insert offset
                tag = "removed" if is_removed else "added"
                self.diff_text.insert(tk.END, f"{offset_str}: ", tag)
                
                # Insert hex bytes with highlighting
                for i, hex_byte in enumerate(hex_bytes):
                    # Check if this byte should be highlighted
                    should_highlight = False
                    for byte_idx, old_val, new_val in line_highlights:
                        if byte_idx == i:
                            should_highlight = True
                            break
                    
                    if should_highlight:
                        # Apply darker highlighting
                        highlight_tag = "removed_highlight" if is_removed else "added_highlight"
                        self.diff_text.insert(tk.END, hex_byte, highlight_tag)
                    else:
                        # Apply normal highlighting
                        self.diff_text.insert(tk.END, hex_byte, tag)
                    
                    # Add space between bytes
                    if i < len(hex_bytes) - 1:
                        self.diff_text.insert(tk.END, " ", tag)
                
                # Insert ASCII part with proper spacing (two spaces before |)
                ascii_part = parts[1].split('|')[1] if '|' in parts[1] else ''
                self.diff_text.insert(tk.END, f"  |{ascii_part}|\n", tag)
            else:
                # No highlights on this line, insert normally
                tag = "removed" if is_removed else "added"
                self.diff_text.insert(tk.END, prefix, tag)
                
        except (ValueError, IndexError):
            # Can't parse, insert normally
            tag = "removed" if is_removed else "added"
            self.diff_text.insert(tk.END, prefix, tag)

def main():
    root = tk.Tk()
    app = PacketDiffTool(root)
    root.mainloop()

if __name__ == "__main__":
    main() 