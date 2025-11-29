#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Tauqyl Shell Server - Private Domain Handler

import socket
import subprocess
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import os

class TauqylShellServer:
    def __init__(self, password, port=11443):
        self.password = password
        self.port = port
        self.running = False
        
    def derive_key(self, password, salt):
        """Derivar clave AES-256 usando PBKDF2"""
        return PBKDF2(password, salt, 32, count=1000000)
    
    def encrypt(self, data, password):
        """Cifrar datos con AES-256-GCM"""
        salt = get_random_bytes(16)
        key = self.derive_key(password, salt)
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
        encrypted_data = salt + nonce + tag + ciphertext
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def decrypt(self, enc_data, password):
        """Descifrar datos con AES-256-GCM"""
        data = base64.b64decode(enc_data)
        salt = data[:16]
        nonce = data[16:28]
        tag = data[28:44]
        ciphertext = data[44:]
        key = self.derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    
    def handle_client(self, conn, addr):
        """Manejar cliente Tauqyl conectado"""
        print(f"[+] Tauqyl connection from {addr}")
        
        try:
            # Autenticación Tauqyl
            auth_data = conn.recv(1024).decode('utf-8')
            auth_msg = self.decrypt(auth_data, self.password)
            
            if auth_msg == "TAUQYL_AUTH_V1":
                conn.send(self.encrypt("TAUQYL_AUTH_SUCCESS", self.password).encode('utf-8'))
                print(f"[+] Client {addr} authenticated")
            else:
                conn.send(self.encrypt("AUTH_FAILED", self.password).encode('utf-8'))
                conn.close()
                return
            
            # Shell interactivo Tauqyl
            while True:
                encrypted_cmd = conn.recv(1024).decode('utf-8')
                command = self.decrypt(encrypted_cmd, self.password)
                
                if command.strip() in ['exit', 'quit']:
                    print(f"[+] Client {addr} disconnected")
                    break
                
                try:
                    # Ejecutar comando de forma segura
                    if command.startswith('cd '):
                        os.chdir(command[3:].strip())
                        output = f"Directory changed to: {os.getcwd()}"
                    else:
                        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
                        output = result.stdout 
                        if result.stderr:
                            output += f"\nError: {result.stderr}"
                            
                except Exception as e:
                    output = f"Command execution error: {e}"
                
                # Enviar respuesta cifrada
                encrypted_output = self.encrypt(output, self.password)
                conn.send(encrypted_output.encode('utf-8'))
                
        except Exception as e:
            print(f"[-] Client {addr} error: {e}")
        finally:
            conn.close()
    
    def start_server(self):
        """Iniciar servidor Tauqyl"""
        self.running = True
        host = '0.0.0.0'
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, self.port))
            s.listen(5)
            
            print(f"[+] Tauqyl Shell Server running on {host}:{self.port}")
            print(f"[+] Private domains: .clos .loky .dafy")
            print(f"[+] Encryption: AES-256-GCM active")
            print("[+] Waiting for Tauqyl connections...")
            
            while self.running:
                try:
                    conn, addr = s.accept()
                    self.handle_client(conn, addr)
                except KeyboardInterrupt:
                    print("\n[!] Tauqyl server stopped by user")
                    break
                except Exception as e:
                    print(f"[-] Server error: {e}")
                    continue

if __name__ == "__main__":
    # Configuración del servidor Tauqyl
    TAUQYL_PASSWORD = "Ancor127.0.0.1"  # Cambiar en producción
    TAUQYL_PORT = 11443
    
    server = TauqylShellServer(TAUQYL_PASSWORD, TAUQYL_PORT)
    server.start_server()