from scapy.all import sniff, IP, Raw

#name of network interface to listen on
interface = "WiFi"
packets = sniff(iface = interface, count=100)

for pkt in packets:
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        print(f"{src}--->{dst}  / Protocol : {proto}")
    #Check if packet contain a Raw payload
    if Raw in pkt:
        #Decoding payload and ignoring decoding errors
        print(f"Payload : {pkt[Raw].load.decode(errors='ignore')}")
        
