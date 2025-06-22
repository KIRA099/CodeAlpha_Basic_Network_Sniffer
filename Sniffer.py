from scapy.all import sniff, IP, Raw

packets = sniff(iface="WiFi", count=100)

for pkt in packets:
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        print(f"{src}--->{dst}  / Protocol : {proto}")

    if Raw in pkt:
        print(f"Payload : {pkt[Raw].load.decode(errors='ignore')}")
        