from scapy.all import sniff

def capture_packets(count=5):
    packets = sniff(count=count)
    results = []

    for pkt in packets:
        if pkt.haslayer("IP"):
            results.append(
                f"Packet: {pkt['IP'].src} → {pkt['IP'].dst}"
            )

    return results