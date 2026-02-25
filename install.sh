#!/bin/bash
# install.sh

echo "🔧 Installing Phish-Spyd3r-Bot dependencies..."

# Update package list
sudo apt update

# Install Python and pip
sudo apt install -y python3 python3-pip python3-venv

# Install external tools
sudo apt install -y nmap curl wget dnsutils traceroute nikto crunch iptables

# Install Python dependencies
pip3 install -r requirements.txt

echo "✅ Installation complete!"