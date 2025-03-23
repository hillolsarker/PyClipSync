import socket
import threading
import time
import logging
import netifaces as ni

from core.config import AppConfig

class PeerDiscovery:
    def __init__(self, config: AppConfig, local_public_key, callback):
        self.config = config
        self.local_ip = self.get_local_ip()
        self.public_key = local_public_key
        self.callback = callback
        self.peers = {}

    def get_local_ip(self):
        for iface in ni.interfaces():
            iface_details = ni.ifaddresses(iface)
            if ni.AF_INET in iface_details:
                ip = iface_details[ni.AF_INET][0]['addr']
                if not ip.startswith("127."):
                    return ip
        return "127.0.0.1"

    def broadcast_presence(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while True:
            message = f"CLIPBOARD_PEER {self.local_ip} {self.public_key.hex()}"
            sock.sendto(message.encode(), ('<broadcast>', self.config.broadcast_port))
            time.sleep(self.config.discovery_interval)

    def listen_for_peers(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", self.config.broadcast_port))

        while True:
            data, addr = sock.recvfrom(1024)
            peer_ip = addr[0]
            parts = data.decode().split()
            if parts[0] == "CLIPBOARD_PEER" and peer_ip != self.local_ip:
                logging.info(f"Discovered peer {peer_ip} with key {peer_pubkey.hex()}")
                peer_pubkey = bytes.fromhex(parts[2])
                self.peers[peer_ip] = peer_pubkey
                self.callback(peer_ip, peer_pubkey)

    def start(self):
        threading.Thread(target=self.broadcast_presence, daemon=True).start()
        threading.Thread(target=self.listen_for_peers, daemon=True).start()