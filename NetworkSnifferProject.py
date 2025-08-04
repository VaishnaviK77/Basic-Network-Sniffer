from scapy.all import sniff,IP,TCP,UDP,ICMP,Raw

def analyze_packet(packet):
    print("=" * 60)

    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP        : {ip_layer.src}")
        print(f"Destination IP   : {ip_layer.dst}")
        print(f"Protocol Number  : {ip_layer.proto}")

        if TCP in packet:
            print("Protocol         : TCP")
            print(f"Source Port      : {packet[TCP].sport}")
            print(f"Destination Port : {packet[TCP].dport}")
        elif UDP in packet:
            print("Protocol         : UDP")
            print(f"Source Port      : {packet[UDP].sport}")
            print(f"Destination Port : {packet[UDP].dport}")
        elif ICMP in packet:
            print("Protocol         : ICMP")

        if Raw in packet:
            print(f"Payload (raw data): {packet[Raw].load}")
    else:
        print("Non-IP Packet Captured")

print("Capturing packets... Press Ctrl + C to stop.\n")
sniff(prn=analyze_packet, count=10)
