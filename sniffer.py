from scapy.all import sniff, IP
def show_packet(packet):
    if IP in packet:
        print("Packet captured!")
        print("From:", packet[IP].src)
        print("To:", packet[IP].dst)
        print("Protocol:", packet[IP].proto)
        print("-" * 30)
print("Starting packet sniffer...")
sniff(count=10, prn=show_packet)

