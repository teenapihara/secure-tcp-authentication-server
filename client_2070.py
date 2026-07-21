#!/usr/bin/env python3
# File: client_2070.py

import socket
import sys

def send_command(sock, cmd, token=None):
    """Send command using LEN format, attaching token if available"""

    if token and not cmd.upper().startswith("LOGIN") and not cmd.upper().startswith("REGISTER"):
        payload = f"{cmd} {token}"
    else:
        payload = cmd
        
    message = f"LEN:{len(payload)}\n{payload}"
    sock.sendall(message.encode())
    
    # Get response
    response = sock.recv(4096).decode()
    return response.strip()

def main():
    # Connect to server - UPDATED PORT
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", 50070)) 
    except ConnectionRefusedError:
        print("Error: Could not connect to server. Is it running?")
        return

    print("Commands: REGISTER <user> <pwd>, LOGIN <user> <pwd>, WHOAMI, LOGOUT, QUIT")
    
    token = None
    
    while True:
        cmd_input = input("> ").strip()
        
        if not cmd_input:
            continue
            
        if cmd_input.upper() == "QUIT":
            break
        
        response = send_command(sock, cmd_input, token)
        print(f"Server: {response}")
        
        # Save token
        if cmd_input.upper().startswith("LOGIN") and "OK 200" in response and "TK_" in response:
            try:
                token = response.split("SID:1020 ")[1].strip()
                print(f"[System] Token acquired and saved: {token}")
            except IndexError:
                print("[System] Error parsing token from server response.")

        # Clear token
        if "Logged out successfully" in response:
            token = None
            print(f"[System] Token cleared.")
    
    sock.close()

if __name__ == "__main__":
    main()
