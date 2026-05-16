from collections import Counter, defaultdict
from ipaddress import ip_address
import scapy.all as scapy

port_tracker = {}

# store risk per IP, convert raw traffic intno threat level 
risk_score = {}

def print_info(packet):
    # Check if the packet contains an IP layer (not all packets do)
    # Why: only IP packets have source/destination addresses
    if packet.haslayer(scapy.IP):

        # Extract and print source IP -> destination IP + packet summary
        # Why: gives a human-readable view of network communication
        print(f"{packet[scapy.IP].src} -> {packet[scapy.IP].dst} | {packet.summary()}")
    else: 
        # If no IP layer exists, just print general packet info
        # Why: some packets are lower-level (ARP, etc.)
        print(packet.summary())

 # extraire quelques informations utiles des nos paquets sniffés (analyser)
# Purpose: analyze network traffic for patterns and suspicious activity
def analyze_packets(packets):

    # List to store all source IPs seen in traffic
    # Why: used later for frequency analysis (who talks most)
    ip_addresses = []

    # List of ports commonly associated with suspicious or remote access activity
    # Why: helps flag unusual or potentially malicious connections
    suspicious_ports = [22, 23, 3389, 4444]

    for packet in packets:

        # extract actual layers for filtering and analysis 
        if packet.haslayer(scapy.IP):
            src = packet[scapy.IP].src
            dst = packet[scapy.IP].dst
            ip_addresses.append(src)

            # RISK ANALYSIS SCORE
            if src not in risk_score:
                risk_score[src] = 0
            
            risk_score[src] += 1

            # TCP Analysis 
            if packet.haslayer(scapy.TCP):
                sport = packet[scapy.TCP].sport
                dport = packet[scapy.TCP].dport

                if dport in suspicious_ports:
                    print(f"[ALERT] Suspicious port: {dst}:{dport}")
                    risk_score[src] += 4   # increase risk score

                # Track ports used by each source IP
                # Why: needed for detecting port scanning behavior
                if src not in port_tracker:
                    port_tracker[src] = set()

                port_tracker[src].add(dport)

                if len(port_tracker[src]) > 10:
                    print(f"[ALERT] Possible port scan: {src}")
                    risk_score[src] += 5   # strong risk increase

            # HTTP detection
            if packet.haslayer(scapy.TCP):
                if packet[scapy.TCP].dport == 80:
                    print(f"[HTTP TRAFFIC] {src} -> {dst}")
                    risk_score[src] += 1
                
                
            if risk_score[src] >= 8:
                print(f"[HIGH RISK] {src} score={risk_score[src]}")


    ip_counter = Counter(ip_addresses)
    print("\nTop IPs:")
    print(ip_counter.most_common(5))

if __name__ == "__main__":

    # une liste des noms des interfaces réseau
    print(scapy.get_if_list())

    # sélectionner une spécifique l'interface ...
    interface_name = 'en0' 

    # écouter l'interface, un seul paquet
    p = scapy.sniff(count=100, iface=interface_name, prn=print_info)  
    # p = scapy.rdpcap("wireshark.pcapng")
    analyze_packets(p)
    
    # retourner une list des paquets qui ont été sniffés
    # p[0].show()
    # p[0].summary()

  