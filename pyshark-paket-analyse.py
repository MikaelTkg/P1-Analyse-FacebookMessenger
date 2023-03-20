# Jean-Pierre Sagdic and Mikael Turkoglu LINFO1341

import pyshark

# Open the packet capture file
capture = pyshark.FileCapture('Packets/Message-txtMika-Message-txtJP-Messenger.pcapng')


# Iterate through each packet in the capture file
for packet in capture:
    # Check if the packet has an IP layer
    if 'IP' in packet:
        # Extract the source and destination IP addresses
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        print(f'Packet {packet.number}: {src_ip} -> {dst_ip}')