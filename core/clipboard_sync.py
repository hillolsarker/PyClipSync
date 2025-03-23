import threading
import socket
import struct
import time
import logging

from core.config import AppConfig

class ClipboardSync:
    def __init__(self, config: AppConfig, crypto_manager, clipboard_manager, peer_discovery):
        self.config = config
        self.crypto = crypto_manager
        self.clipboard = clipboard_manager
        self.peers = peer_discovery.peers
        self.peer_discovery = peer_discovery

    def start(self):
        threading.Thread(target=self.send_clipboard_loop, daemon=True).start()
        threading.Thread(target=self.receive_clipboard_loop, daemon=True).start()

    def send_clipboard_loop(self):
        while True:
            if self.clipboard.has_changed():
                content = self.clipboard.get_clipboard()
                logging.info(f"Clipboard changed. Sending to {len(self.peers)} peer(s).")
                for peer_ip, peer_pubkey in self.peers.items():
                    self.send_to_peer(peer_ip, content, peer_pubkey)
            time.sleep(1)

    def send_to_peer(self, peer_ip, content, pubkey):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_ip, self.config.clipboard_port))
            encrypted = self.crypto.encrypt(content, pubkey)
            sock.sendall(struct.pack("!I", len(encrypted)) + encrypted)
            sock.close()
            logging.info(f"Sent to {peer_ip}")
        except Exception as e:
            logging.warning(f"Send failed to {peer_ip}: {e}")
            self.peers.pop(peer_ip, None)

    def receive_clipboard_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("", self.config.clipboard_port))
        sock.listen(5)

        while True:
            conn, addr = sock.accept()
            peer_ip = addr[0]
            length_data = conn.recv(4)
            if not length_data:
                conn.close()
                continue
            msg_len = struct.unpack("!I", length_data)[0]
            encrypted_data = conn.recv(msg_len)
            conn.close()

            if peer_ip in self.peers:
                try:
                    text = self.crypto.decrypt(encrypted_data, self.peers[peer_ip])
                    logging.info(f"Received clipboard from {peer_ip}")
                    self.clipboard.copy_to_clipboard(text)
                except Exception as e:
                    logging.warning(f"Decrypt failed from {peer_ip}: {e}")