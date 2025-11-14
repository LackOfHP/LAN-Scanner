README - Mini Sniffer

Mini Sniffer — Lightweight Network Scanner & Packet Sniffer (Bash)

A simple, portable, and dependency-light local network scanner and packet sniffer written entirely in Bash. Shows connected devices and live transported packets without needing Wireshark.

Run Instantly (No Installation)
--------------------------------
Using curl:
curl -s https://raw.githubusercontent.com/LackOfHP/LAN-Scanner/refs/heads/main/mini_sniffer.sh | bash

Using wget:
wget -qO- https://raw.githubusercontent.com/LackOfHP/LAN-Scanner/refs/heads/main/mini_sniffer.sh | bash

Requirements
------------
Install required tools:
sudo apt install tcpdump arp-scan iputils-ping

Running Locally
---------------
git clone https://github.com/LackOfHP/mini-sniffer.git
cd mini-sniffer
chmod +x mini_sniffer.sh
sudo ./mini_sniffer.sh

What Mini Sniffer Does
----------------------
- Scans your local network
- Lists connected devices (IP, MAC, hostname)
- Displays live packet flow (source, destination, protocol, bytes)
- Saves captured packets into a .pcap file for Wireshark

Optional: Install as Global Command
-----------------------------------
sudo cp mini_sniffer.sh /usr/local/bin/mini-sniffer
sudo chmod +x /usr/local/bin/mini-sniffer
sudo mini-sniffer

License
-------
MIT License — free to modify and use.

Author
------
Your Name
GitHub: https://github.com/LackofHP
