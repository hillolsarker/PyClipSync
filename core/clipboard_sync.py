import threading
import socket
import struct
import time
import logging

from typing import Dict

from core.config import AppConfig
from core.clipboard_manager import ClipboardManager
from core.crypto import CryptoManager
from core.peer_discovery import PeerDiscovery

class ClipboardSync:
    def __init__(
            self, 
            config: AppConfig, 
            crypto_manager: CryptoManager, 
            clipboard_manager: ClipboardManager, 
            peer_discovery: PeerDiscovery
        ):
        """
        Initializes the ClipboardSync class.

        Args:
            config (AppConfig): The application configuration object.
            crypto_manager (CryptoManager): The manager responsible for cryptographic operations.
            clipboard_manager (ClipboardManager): The manager responsible for clipboard operations.
            peer_discovery (PeerDiscovery): The component responsible for discovering peers in the network.
        """
        self.config = config
        self.crypto = crypto_manager
        self.clipboard = clipboard_manager
        self.peer_discovery = peer_discovery

    def start(self) -> None:
        """
        Starts the clipboard synchronization process by launching two separate threads:
        one for sending clipboard data and another for receiving clipboard data.

        This method runs both threads as daemon threads, ensuring they terminate
        when the main program exits.
        """
        threading.Thread(target=self.send_clipboard_loop, daemon=True).start()
        threading.Thread(target=self.receive_clipboard_loop, daemon=True).start()

    def send_clipboard_loop(self) -> None:
        """
        Continuously monitors the clipboard for changes and sends the updated content
        to all discovered peers.

        This method runs an infinite loop that checks if the clipboard content has
        changed. If a change is detected, it retrieves the updated content and sends
        it to all peers discovered via the peer discovery mechanism.

        The method performs the following steps:
        1. Checks if the clipboard content has changed.
        2. If changed, retrieves the updated clipboard content.
        3. Fetches a snapshot of the currently discovered peers.
        4. Logs the number of peers to which the content will be sent.
        5. Iterates over the list of peers and sends the clipboard content to each peer.
        6. Waits for 1 second before repeating the process.

        Note:
            This method runs indefinitely and should be executed in a separate thread
            or process to avoid blocking the main application.

        Raises:
            Any exceptions raised during peer communication or clipboard access
            should be handled appropriately within the method or by the caller.

        """
        while True:
            if self.clipboard.has_changed():
                content = self.clipboard.get_clipboard()
                peers = self.peer_discovery.get_peers_snapshot()
                logging.info(f"Clipboard changed. Sending to {len(peers)} peer(s).")
                for peer_ip, peer_pubkey in list(peers.items()):
                    self.send_to_peer(peer_ip, content, peer_pubkey)
            time.sleep(1)

    def send_to_peer(self, peer_ip: str, content: str, pubkey: bytes) -> None:
        """
        Sends encrypted clipboard content to a peer over a TCP connection.

        Args:
            peer_ip (str): The IP address of the peer to send the content to.
            content (str): The clipboard content to be sent.
            pubkey (bytes): The public key of the peer used for encrypting the content.

        Raises:
            Exception: Logs a warning and removes the peer from the peer discovery list
                       if the sending process fails.

        Notes:
            - The clipboard content is encrypted using the provided public key before sending.
            - The encrypted content is prefixed with its length (4 bytes, big-endian) 
              before being sent over the socket.
            - If the sending fails, the peer is removed from the peer discovery list.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_ip, self.config.clipboard_port))
            encrypted = self.crypto.encrypt(content, pubkey)
            logging.debug(f"Encrypted clipboard size: {len(encrypted)} bytes")
            sock.sendall(struct.pack("!I", len(encrypted)) + encrypted)
            sock.close()
            logging.info(f"Sent to {peer_ip}")
        except Exception as e:
            logging.warning(f"Send failed to {peer_ip}: {e}")
            self.peer_discovery.peers.pop(peer_ip, None)

    def receive_clipboard_loop(self) -> None:
        """
        Continuously listens for incoming clipboard data from peers, decrypts it, 
        and updates the local clipboard.

        This method sets up a socket server to listen for incoming connections on 
        the configured clipboard port. When a connection is established, it receives 
        encrypted clipboard data, decrypts it using the peer's public key, and updates 
        the local clipboard with the decrypted text.

        The method operates in an infinite loop to handle multiple incoming clipboard 
        updates from peers.

        Raises:
            Exception: If decryption of the received data fails.

        Workflow:
            1. Create and bind a socket to the configured clipboard port.
            2. Listen for incoming connections.
            3. Accept a connection and retrieve the peer's IP address.
            4. Receive the length of the incoming encrypted data.
            5. Read the encrypted data in chunks until the full message is received.
            6. Close the connection.
            7. Check if the peer's IP is in the discovered peers list.
            8. Decrypt the received data using the peer's public key.
            9. Update the local clipboard with the decrypted text.
            10. Log the success or failure of the decryption process.

        Note:
            This method assumes that the `self.peer_discovery.get_peers_snapshot()` 
            method provides a dictionary of peer IPs and their corresponding public keys.
            It also assumes that `self.crypto.decrypt()` handles the decryption process 
            and `self.clipboard.copy_to_clipboard()` updates the clipboard.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("", self.config.clipboard_port))
        sock.listen(5)

        while True:
            conn, addr = sock.accept()
            peer_ip: str = addr[0]
            length_data: bytes = conn.recv(4)
            if not length_data:
                conn.close()
                continue
            msg_len: int = struct.unpack("!I", length_data)[0]
            encrypted_data = b''
            while len(encrypted_data) < msg_len:
                chunk = conn.recv(msg_len - len(encrypted_data))
                if not chunk:
                    break
                encrypted_data += chunk
            conn.close()

            peers: Dict[str, bytes] = self.peer_discovery.get_peers_snapshot()
            if peer_ip in peers:
                try:
                    text = self.crypto.decrypt(encrypted_data, peers[peer_ip])
                    logging.info(f"Received clipboard from {peer_ip}")
                    self.clipboard.copy_to_clipboard(text)
                except Exception as e:
                    logging.warning(f"Decrypt failed from {peer_ip}: {e}")