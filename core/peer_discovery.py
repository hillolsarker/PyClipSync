import socket
import threading
import time
import logging
import netifaces as ni
from typing import Callable, Dict

from core.config import AppConfig

class PeerDiscovery:
    def __init__(
            self, 
            config: AppConfig, 
            local_public_key: bytes, 
            callback: Callable[[str, bytes], None]
        ):
        self.config: AppConfig = config
        self.local_ip: str = self.get_local_ip()
        self.public_key: bytes = local_public_key
        self.callback: Callable[[str, bytes], None] = callback
        self.peers: Dict[str, bytes] = {}
        self.lock: threading.Lock = threading.Lock()

    def get_local_ip(self) -> str:
        for iface in ni.interfaces():
            iface_details = ni.ifaddresses(iface)
            if ni.AF_INET in iface_details:
                ip = iface_details[ni.AF_INET][0]['addr']
                if not ip.startswith("127."):
                    return ip
        return "127.0.0.1"

    def broadcast_presence(self) -> None:
        logging.info("Broadcast thread started.")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while True:
            message = f"CLIPBOARD_PEER {self.local_ip} {self.public_key.hex()}"
            try:
                sock.sendto(message.encode(), ('<broadcast>', self.config.broadcast_port))
            except Exception as e:
                logging.warning(f"Broadcast failed: {e}")
            time.sleep(self.config.discovery_interval)

    def listen_for_peers(self) -> None:
        logging.info("Peer listener thread started.")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.bind(("", self.config.broadcast_port))
        except Exception as e:
            logging.error(f"Failed to bind UDP socket: {e}")
            return

        while True:
            try:
                data, addr = sock.recvfrom(1024)
                peer_ip = addr[0]
                parts = data.decode().split()
                if parts[0] == "CLIPBOARD_PEER" and peer_ip != self.local_ip:
                    peer_pubkey = bytes.fromhex(parts[2])
                    with self.lock:
                        if peer_ip not in self.peers:
                            self.peers[peer_ip] = peer_pubkey
                            self.callback(peer_ip, peer_pubkey)
                            logging.info(f"Discovered new peer: {peer_ip}")
                        else:
                            # Optional: update public key if needed
                            self.peers[peer_ip] = peer_pubkey
            except Exception as e:
                logging.warning(f"Error receiving peer info: {e}")

    def start(self) -> None:
        threading.Thread(target=self.broadcast_presence, daemon=True).start()
        threading.Thread(target=self.listen_for_peers, daemon=True).start()

    def get_peers_snapshot(self) -> Dict[str, bytes]:
        with self.lock:
            return dict(self.peers)