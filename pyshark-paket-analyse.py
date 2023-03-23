# Jean-Pierre Sagdic and Mikael Turkoglu LINFO1341

import pyshark
import matplotlib.pyplot as plt
from collections import Counter

# Specify the path to your packet capture file
capture = pyshark.FileCapture('Packets/Message-txtMika-Message-txtJP-Messenger.pcapng')

# Create a counter to count the occurrences of each protocol
protocol_counts = Counter()

# Create a counter to count the occurrences of each transport protocol
transport_counts = Counter()

# Loop over each packet in the capture and count the number of packets for each transport protocol
for packet in capture:
    transport_protocol = packet.transport_layer
    protocols = [layer.layer_name for layer in packet.layers]

    # Count the number of packets for each protocol
    protocol_counts.update(protocols)

    # Count the number of packets for each transport protocol
    transport_counts.update([transport_protocol])

# order the counters by the number of packets
protocol_counts = protocol_counts.most_common()
transport_counts = transport_counts.most_common()

# Create a bar chart of the transport protocol counts
plt.figure(figsize=(5, 5), layout='constrained')
plt.bar(range(len(transport_counts)), [val[1] for val in transport_counts], align='center')
plt.xticks(range(len(transport_counts)), [val[0] for val in transport_counts])
plt.title('Transport Protocol Counts')
plt.xlabel('Transport Protocol')
plt.ylabel('Number of Packets')
plt.title('Transport Protocols in Packet Capture')
plt.savefig('Graph/transport_protocols_txt_txt.pdf')
plt.show()

# Create a bar chart of the protocol counts
plt.figure(figsize=(5, 5), layout='constrained')
plt.bar(range(len(protocol_counts)), [val[1] for val in protocol_counts], align='center')
plt.xticks(range(len(protocol_counts)), [val[0] for val in protocol_counts], rotation=90)
plt.title('Protocol Counts')
plt.xlabel('Protocol')
plt.ylabel('Number of Packets')
plt.title('Protocols in Packet Capture')
plt.savefig('Graph/protocols_txt_txt.pdf')
plt.show()
