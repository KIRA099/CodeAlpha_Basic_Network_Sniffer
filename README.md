# Packet Sniffer using Scapy

This is a simple Python script that captures and analyzes network traffic using the **Scapy** library. It listens on a specified interface (e.g., `"WiFi"`), extracts IP information and raw data from packets, and displays them in the console.

---

## Features

- Captures **100 packets** from a network interface.
- Extracts and displays:
  - **Source IP**
  - **Destination IP**
  - **Protocol number**
  - **Raw payload data** (if available)
- Uses **Scapy**, a powerful Python library for packet manipulation.

---

## How It Works

1. **Set the Interface**  
   Define the name of the interface to capture packets from (e.g., `"WiFi"` or `"eth0"`).

2. **Sniff Packets**  
   The script uses Scapy's `sniff()` function to capture 100 packets.

3. **Process Each Packet**  
   - If the packet has an **IP** layer, extract the source IP, destination IP, and protocol.
   - If the packet has a **Raw** layer, decode and display the raw payload.

---

## Data Flow

```text
Network Interface ("WiFi")
          ↓
     sniff() function
          ↓
  For each captured packet:
      ├─ If IP layer → Extract & print IP + Protocol
      └─ If Raw layer → Decode & print payload
