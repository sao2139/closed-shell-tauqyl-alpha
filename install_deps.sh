#!/bin/bash

echo "[+] Installing Tauqyl System Dependencies..."

# Instalar dependencias del sistema
sudo apt update
sudo apt install python3 python3-pip tor -y

# Instalar dependencias Python
pip3 install pysocks pycryptodome stem psutil

# Configurar directorios de log
sudo mkdir -p /var/log/tauqyl/
sudo touch /var/log/tauqyl_server.log
sudo chmod 666 /var/log/tauqyl_server.log

echo "[+] Dependencies installed successfully!"
echo "[+] To start server: python3 tauqyl_server.py"
echo "[+] To start client: python3 tauqyl_client.py"