import socket
import threading
import pyperclip
import netifaces as ni
import time
import struct
import logging
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)

BROADCAST_PORT = 50000
CLIPBOARD_PORT = 50001
DISCOVERY_INTERVAL = 5
PEER_TIMEOUT = 10
peers = {}

# Generate local key pair
private_key = x25519.X25519PrivateKey.generate()
public_key = private_key.public_key().public_bytes_raw()

def get_local_ip():
    try:
        interfaces = ni.interfaces()
        for iface in interfaces:
            iface_details = ni.ifaddresses(iface)
            if ni.AF_INET in iface_details:
                ip = iface_details[ni.AF_INET][0]['addr']
                if not ip.startswith("127."):
                    return ip
        return "127.0.0.1"
    except Exception:
        return "127.0.0.1"

LOCAL_IP = get_local_ip()
logging.info(f"Local machine IP: {LOCAL_IP}")

def broadcast_presence():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    
    while True:
        message = f"CLIPBOARD_PEER {LOCAL_IP} {public_key.hex()}"
        sock.sendto(message.encode(), ('<broadcast>', BROADCAST_PORT))
        time.sleep(DISCOVERY_INTERVAL)

def listen_for_peers():
    global peers
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("", BROADCAST_PORT))

    while True:
        data, addr = sock.recvfrom(1024)
        peer_ip = addr[0]
        message_parts = data.decode().split()

        if message_parts[0] == "CLIPBOARD_PEER":
            peer_pubkey_hex = message_parts[2]
            if peer_ip != LOCAL_IP:
                peer_pubkey = bytes.fromhex(peer_pubkey_hex)
                peers[peer_ip] = peer_pubkey  # Store peer's public key
                logging.info(f"Discovered new peer: {peer_ip}")

def encrypt_message(plaintext, peer_public_key):
    shared_secret = private_key.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public_key))
    nonce = os.urandom(12)  # Unique per message
    aesgcm = AESGCM(shared_secret)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce + ciphertext  # Prepend nonce for decryption

def decrypt_message(encrypted_data, peer_public_key):
    shared_secret = private_key.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public_key))
    nonce, ciphertext = encrypted_data[:12], encrypted_data[12:]
    aesgcm = AESGCM(shared_secret)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

def send_clipboard():
    last_clipboard = ""

    while True:
        current_clipboard = pyperclip.paste()
        if current_clipboard and current_clipboard != last_clipboard:
            last_clipboard = current_clipboard
            logging.info(f"Clipboard changed. Sending to {len(peers)} peer(s).")
            for peer_ip, peer_pubkey in peers.items():
                send_to_peer(peer_ip, current_clipboard, peer_pubkey)
        time.sleep(1)

def send_to_peer(peer_ip, clipboard_text, peer_pubkey):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((peer_ip, CLIPBOARD_PORT))

        encrypted_data = encrypt_message(clipboard_text, peer_pubkey)
        length_prefix = struct.pack("!I", len(encrypted_data))
        sock.sendall(length_prefix + encrypted_data)

        logging.info(f"Sent encrypted clipboard to {peer_ip}")
        sock.close()
    except Exception as e:
        logging.warning(f"Failed to send to {peer_ip}: {e}")
        peers.pop(peer_ip, None)  # Remove unreachable peer

def receive_clipboard():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("", CLIPBOARD_PORT))
    sock.listen(5)

    while True:
        conn, addr = sock.accept()
        peer_ip = addr[0]

        length_data = conn.recv(4)
        if not length_data:
            conn.close()
            continue

        message_length = struct.unpack("!I", length_data)[0]
        encrypted_data = conn.recv(message_length)
        conn.close()

        if peer_ip in peers:
            try:
                clipboard_text = decrypt_message(encrypted_data, peers[peer_ip])
                logging.info(f"Received encrypted clipboard from {peer_ip}")
                pyperclip.copy(clipboard_text)
            except Exception as e:
                logging.warning(f"Failed to decrypt clipboard from {peer_ip}: {e}")

if __name__ == "__main__":
    threading.Thread(target=broadcast_presence, daemon=True).start()
    threading.Thread(target=listen_for_peers, daemon=True).start()
    threading.Thread(target=send_clipboard, daemon=True).start()
    threading.Thread(target=receive_clipboard, daemon=True).start()

    logging.info("Clipboard sharing service started securely. Running in background...")
    while True:
        time.sleep(60)