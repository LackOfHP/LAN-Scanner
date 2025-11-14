README - LAN-Scanner

Mini Sniffer — Lightweight Network Scanner & Packet Sniffer (Bash)

A simple, portable, and dependency-light local network scanner and packet sniffer written entirely in Bash. Shows connected devices and live transported packets without needing Wireshark.

Run Instantly (No Installation)
--------------------------------
Using curl:
curl -s https://raw.githubusercontent.com/LackOfHP/LAN-Scanner/refs/heads/main/LAN-scanner.sh | bash

Using wget:
wget -qO- https://raw.githubusercontent.com/LackOfHP/LAN-Scanner/refs/heads/main/LAN-scanner.sh | bash

Requirements
------------
Install required tools:
sudo apt install tcpdump arp-scan iputils-ping

Running Locally
---------------
git clone https://github.com/LackOfHP/LAN-scanner.git

cd LAN-scanner

chmod +x LAN-scanner.sh

sudo ./LAN-scanner.sh

What Mini Sniffer Does
----------------------
- Scans your local network
- Lists connected devices (IP, MAC, hostname)
- Displays live packet flow (source, destination, protocol, bytes)
- Saves captured packets into a .pcap file for Wireshark

Optional: Install as Global Command
-----------------------------------
sudo cp LAN-scanner.sh /usr/local/bin/LAN-scanner

sudo chmod +x /usr/local/bin/LAN-scanner

sudo LAN-scanner

License
-------
MIT License — free to modify and use.

Author
------
Your Name
GitHub: https://github.com/LackofHP
