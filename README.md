# Network Packet Sniffer (Python)

## Overview
Built a Python-based packet sniffer to capture and analyze live network traffic using low-level packet inspection techniques.

This project demonstrates how data moves across a network in real time by capturing packets before they reach applications and inspecting their contents at a low level.

---

## How It Works

The sniffer is built using Python and the Scapy library, which allows direct access to network packets.

It listens on available network interfaces such as:
- `lo0` (loopback)
- `en0` (Wi-Fi / Ethernet)
- `gif0`, `stf0` (system interfaces)

These interfaces represent different pathways through which network traffic flows.

---

## Packet Capture & Analysis

Once packets are captured, the program parses them into different network layers:

- **IP Layer**: Identifies source and destination IP addresses
- **TCP Layer**: Tracks reliable connections between devices (used for websites, logins, etc.)
- **UDP Layer**: Handles fast, connectionless communication (used for gaming, streaming, etc.)
- **Ethernet Layer**: Handles local network communication between devices

Each packet contains structured metadata such as:
- Source MAC address (`src`)
- Destination MAC address (`dst`)
- Protocol type (`type`)
- Ports and connection details

### Protocol Breakdown
- **HTTP**: Web traffic over TCP (data is visible, not encrypted)
- **TCP**: Reliable, connection-based communication between devices
- **UDP**: Fast but unreliable communication without guaranteed delivery

---

## Network Insights

This tool helps visualize and understand:
- Which device is sending or receiving data
- What server is being contacted
- What protocol is being used
- How connections are established, maintained, or closed

---

## Filtering & Detection Features

The sniffer includes filtering capabilities to isolate specific traffic, such as:
- Traffic by protocol (HTTP, TCP, UDP)
- Traffic by port number
- Traffic from specific IP addresses

It can also be extended to detect suspicious behavior such as:
- Repeated connection attempts
- Unexpected or unusual ports
- High or abnormal traffic volume

---

## Planned Improvements

- Packet frequency analysis
- Suspicious port detection
- Abnormal traffic pattern detection
- Connection monitoring logic

---

## Learning Outcomes

This project strengthened understanding of:
- Network communication protocols
- Traffic flow between systems and devices
- Low-level packet structure and behavior
- Real-time system and network interaction

It provides deeper insight into how modern applications and services communicate behind the scenes through structured network protocols.
