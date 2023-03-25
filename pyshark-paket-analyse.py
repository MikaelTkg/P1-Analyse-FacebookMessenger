# Jean-Pierre Sagdic and Mikael Turkoglu LINFO1341

import ipaddress
from collections import Counter
from collections import defaultdict

import matplotlib.pyplot as plt
import pyshark
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP, TCP, UDP, ICMP

path = 'Packets/WIFI_appel_video_JP_Messnger.pcapng'
def process_dns_packet(packet):
    # Check if the packet has an IP layer
    if not packet.haslayer(IP):
        return

    # Check if the packet has a DNS layer
    if packet.haslayer(DNS):
        dns_server = packet[IP].dst
        unexpected_dns_servers = ["8.8.4.4", "208.67.220.220"]

        # Check if the DNS request is sent to an unexpected DNS server
        if dns_server in unexpected_dns_servers:
            print(f"Unexpected DNS server: {dns_server}")

        # Print DNS query and check for suspicious domains
        if packet[DNS].qr == 0:  # 0 = Query, 1 = Response
            query = packet[DNS].qd.qname.decode("utf-8")
            print(f"DNS Query: {query}")

            suspicious_domains = ["example-malicious.com", "example-phishing.com"]
            for domain in suspicious_domains:
                if domain in query:
                    print(f"Suspicious domain in DNS query: {domain}")

        # Print DNS response and check for malicious records
        elif packet[DNS].qr == 1:
            response = packet[DNS].an
            if response:
                for i in range(packet[DNS].ancount):
                    record = response[i].rrname.decode("utf-8")
                    rdata = response[i].rdata
                    print(f"DNS Response: {record} -> {rdata}")

                    malicious_records = ["192.0.2.123", "203.0.113.99"]
                    if rdata in malicious_records:
                        print(f"Malicious record in DNS response: {rdata}")


packetx = rdpcap(path)
for packet in packetx:
    print(process_dns_packet(packet))



def process_dns_packet(packet):
    # Check if the packet has a DNS layer
    if packet.haslayer(DNS):

        # Print DNS query
        if packet[DNS].qr == 0:  # 0 = Query, 1 = Response
            query = packet[DNS].qd.qname.decode("utf-8")
            print(f"DNS Query: {query}")

        # Print DNS response
        elif packet[DNS].qr == 1:
            response = packet[DNS].an
            if response:
                for i in range(packet[DNS].ancount):
                    record = response[i].rrname.decode("utf-8")
                    rdata = response[i].rdata
                    print(f"DNS Response: {record} -> {rdata}")

def analyze_pcapng(pcapng_file):
    sniff(offline=pcapng_file, prn=process_dns_packet, store=False)
print(analyze_pcapng(path))


def analyze_dns(file_path):
    pcap = pyshark.FileCapture(file_path)

    domain_names = set()
    authoritative_servers = {}
    query_types = set()

    for packet in pcap:
        if 'DNS' in packet:
            try:
                dns = packet.dns

                # Ajouter le nom de domaine résolu
                if hasattr(dns, 'qry_name'):
                    domain_names.add(dns.qry_name)

                # Ajouter le type de requête DNS
                if hasattr(dns, 'qry_type'):
                    query_types.add(dns.qry_type)

                # Ajouter les serveurs autoritatifs
                if hasattr(dns, 'a'):
                    authoritative_server = dns.a
                    domain = dns.qry_name
                    if domain not in authoritative_servers:
                        authoritative_servers[domain] = set()
                    authoritative_servers[domain].add(authoritative_server)

            except AttributeError:
                # Ignorer les paquets sans informations DNS pertinentes
                pass

    # Afficher les résultats
    print("Noms de domaines résolus :")
    for domain in domain_names:
        print(f"- {domain}")

    print("\nServeurs autoritatifs :")
    for domain, servers in authoritative_servers.items():
        print(f"{domain}:")
        for server in servers:
            print(f"- {server}")

    print("\nTypes de requêtes DNS :")
    for query_type in query_types:
        print(f"- {query_type}")
print(analyze_dns(path))



# Specify the path to your packet capture file
capture = pyshark.FileCapture('Packets/Message-image-vocalMika-Message-image-txtJp-Messenger.pcapng')


def extract_server_names(pcap_file):
    server_names = set()

    packets = rdpcap(pcap_file)
    for packet in packets:
        if packet.haslayer(DNSRR):
            rrname = packet[DNSRR].rrname.decode("utf-8")
            if rrname not in server_names:
                server_names.add(rrname)

    return server_names
print(extract_server_names(path))

def analyze_errors(pcap_file):
    packets = rdpcap(pcap_file)

    tcp_retransmissions = 0
    icmp_errors = 0
    udp_errors = 0

    for packet in packets:
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            if 'ECE' in flags and 'CWR' in flags:
                tcp_retransmissions += 1

        if packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type
            if icmp_type in {3, 4, 5, 11, 12}:
                icmp_errors += 1

        if packet.haslayer(UDP):
            udp_payload = packet[UDP].payload
            if len(udp_payload) % 2 != 0:
                udp_errors += 1
    print("tcp",tcp_retransmissions)
    print("icmp",icmp_errors)
    print("udp",udp_errors)
print(analyze_errors(path))

"""""
Ce script parcourt tous les paquets du fichier pcapng et vérifie s'ils contiennent des erreurs de communication :
Retransmissions TCP : Il vérifie si les drapeaux "ECE" et "CWR" sont présents dans le paquet TCP, ce qui peut indiquer une retransmission due à la congestion.
Erreurs ICMP : Il vérifie si le paquet ICMP a un type d'erreur (3, 4, 5, 11 ou 12).
Erreurs UDP : Il vérifie si la longueur de la charge utile UDP est impair, ce qui pourrait indiquer une corruption de paquet (cet exemple est simpliste et pourrait ne pas détecter toutes les erreurs UDP).
Le script affiche ensuite le nombre d'erreurs détectées pour chaque type. 
"""""

def extract_ip_and_ports(pcap_file):
    packets = rdpcap(pcap_file)

    connections = set()

    for packet in packets:
        if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet.sport
            dst_port = packet.dport
            protocol = "TCP" if packet.haslayer(TCP) else "UDP"

            connection = (src_ip, dst_ip, src_port, dst_port, protocol)
            connections.add(connection)

    return connections
conections = extract_ip_and_ports(path)
for connection in conections:
    src_ip, dst_ip, src_port, dst_port, protocol = connection
    print(f"{protocol}: {src_ip}: {src_port} -> {dst_ip}: {dst_port}")

"""""
Ce script lit les paquets du fichier pcapng et vérifie s'ils contiennent des couches IP,
 TCP ou UDP. Si c'est le cas, il extrait les adresses IP source et destination ainsi que les ports source et destination. 
 Les informations de connexion sont stockées dans un ensemble pour éviter les doublons.

Finalement, le script affiche les connexions trouvées dans le fichier pcapng, 
avec les adresses IP et les ports pour chaque paquet TCP et UDP
"""""
def extract_destination_ports(pcap_file):
    packets = rdpcap(pcap_file)
    destination_ports = []

    for packet in packets:
        if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
            dst_port = packet.dport
            destination_ports.append(dst_port)

    return destination_ports
# en faire un graph
def analyze_performance(pcap_file):
    packets = rdpcap(pcap_file)
    latencies = defaultdict(list)

    for packet in packets:
        # Calculate latencies
        if IP in packet and packet[IP].src and packet[IP].dst:
            key = (packet[IP].src, packet[IP].dst)
            latencies[key].append(packet.time)

    # Calculate and plot latencies
    latency_data = []
    for key, values in latencies.items():
        if len(values) > 1:
            latencies_list = [values[i + 1] - values[i] for i in range(len(values) - 1)]
            latency_data.append((key, latencies_list))

    plot_latencies(latency_data)

def plot_latencies(latency_data):
    fig, ax = plt.subplots()
    for key, values in latency_data:
        ax.plot(values, label=f"{key[0]} -> {key[1]}")

    ax.set_xlabel('Packet Index')
    ax.set_ylabel('Latency (s)')
    ax.set_title('Latency for Each Source/Destination Pair')
    ax.legend()

    plt.show()
print("analyse:",analyze_performance(path))
def analyze_user_behavior(pcap_file):
    packets = rdpcap(pcap_file)
    visited_websites = defaultdict(set)
    user_activity = defaultdict(list)

    for packet in packets:
        # Collect visited websites
        if TCP in packet and packet[TCP].dport == 80 and HTTPRequest in packet:
            host = packet[HTTPRequest].fields.get('Host')
            if host and IP in packet and packet[IP].src:
                visited_websites[packet[IP].src].add(host)

        # Collect user activity
        if IP in packet and packet[IP].src:
            user_activity[packet[IP].src].append(packet.time)

    # Print visited websites
    print("Visited Websites:")
    for user, websites in visited_websites.items():
        print("utilisateur: {} et le web {}".format(user,websites))
       # print(f"{user}: {', '.join(websites)}")

    # Print user activity
    print("\nUser Activity:")
    for user, timestamps in user_activity.items():
        print(f"{user}: {len(timestamps)} packets from {min(timestamps)} to {max(timestamps)}")
print(analyze_user_behavior(path))


def is_facebook_ip(ip):
    # List of Facebook IP ranges (please update if necessary)
    facebook_ip_ranges = [
        "31.13.24.0/21",
        "31.13.64.0/18",
        "66.220.144.0/20",
        "69.63.176.0/20",
        # Add more ranges as needed
    ]

    for ip_range in facebook_ip_ranges:
        if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(ip_range):
            return True
    return False

def analyze_messenger_usage(pcap_file):
    packets = rdpcap(pcap_file)
    messenger_users = defaultdict(list)

    for packet in packets:
        if IP in packet and (is_facebook_ip(packet[IP].src) or is_facebook_ip(packet[IP].dst)):
            user_ip = packet[IP].src if is_facebook_ip(packet[IP].dst) else packet[IP].dst
            messenger_users[user_ip].append(packet.time)

    print("Messenger Usage:")
    for user, timestamps in messenger_users.items():
        print(f"{user}: {len(timestamps)} packets from {min(timestamps)} to {max(timestamps)}")

print(analyze_messenger_usage(path))



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