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
        """
        Initializes the PeerDiscovery class.

        Args:
            config (AppConfig): The application configuration object.
            local_public_key (bytes): The local public key of the peer.
            callback (Callable[[str, bytes], None]): A callback function to handle 
                discovered peers. It takes the peer's IP address (str) and public 
                key (bytes) as arguments.

        Attributes:
            config (AppConfig): Stores the application configuration.
            local_ip (str): The local IP address of the peer.
            public_key (bytes): The local public key of the peer.
            callback (Callable[[str, bytes], None]): The callback function for 
                handling discovered peers.
            peers (Dict[str, bytes]): A dictionary mapping peer IP addresses to 
                their public keys.
            lock (threading.Lock): A threading lock to ensure thread-safe access 
                to shared resources.
        """
        self.config: AppConfig = config
        self.local_ip: str = self.get_local_ip()
        self.public_key: bytes = local_public_key
        self.callback: Callable[[str, bytes], None] = callback
        self.peers: Dict[str, bytes] = {}
        self.lock: threading.Lock = threading.Lock()

    def get_local_ip(self) -> str:
        """
        Retrieves the local IP address of the machine, excluding loopback addresses.

        This method iterates through all network interfaces on the machine and 
        checks for IPv4 addresses. It returns the first non-loopback IPv4 address 
        it finds. If no such address is found, it defaults to returning "127.0.0.1".

        Returns:
            str: The local IPv4 address of the machine, or "127.0.0.1" if no 
            non-loopback address is found.
        """
        for iface in ni.interfaces():
            iface_details = ni.ifaddresses(iface)
            if ni.AF_INET in iface_details:
                ip = iface_details[ni.AF_INET][0]['addr']
                if not ip.startswith("127."):
                    return ip
        return "127.0.0.1"

    def broadcast_presence(self) -> None:
        """
        Broadcasts the presence of the local peer to the network.

        This method runs in a loop, sending a UDP broadcast message at regular intervals
        to announce the local peer's presence. The broadcast message contains the peer's
        local IP address and public key.

        The method uses a UDP socket with broadcast enabled to send the message to the
        configured broadcast port. If an error occurs during the broadcast, it logs a
        warning message.

        The broadcast interval is determined by the `discovery_interval` attribute in
        the configuration.

        Logging:
            Logs an informational message when the broadcast thread starts.
            Logs a warning message if the broadcast fails.

        Raises:
            Any exceptions raised during socket operations are caught and logged.
        """
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
        """
        Listens for peer discovery messages on a UDP broadcast socket.

        This method runs in a separate thread and continuously listens for
        incoming UDP messages from peers. When a valid peer discovery message
        is received, it extracts the peer's IP address and public key, and
        updates the list of known peers. If a new peer is discovered, a callback
        is triggered.

        The expected message format is:
            "CLIPBOARD_PEER <peer_name> <peer_public_key_hex>"

        - If the message is valid and the peer is not already known, the peer's
          information is added to the `self.peers` dictionary.
        - If the peer is already known, the public key can optionally be updated.

        Logging is used to track the status of the listener and any errors
        encountered during execution.

        Raises:
            Logs exceptions if there are issues with binding the socket or
            receiving data.

        Note:
            This method assumes that `self.config.broadcast_port`, `self.local_ip`,
            `self.lock`, `self.peers`, and `self.callback` are properly initialized
            before calling this method.
        """
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
                            self.peers[peer_ip] = peer_pubkey
            except Exception as e:
                logging.warning(f"Error receiving peer info: {e}")

    def start(self) -> None:
        """
        Starts the peer discovery process by initiating two separate threads:
        one for broadcasting the presence of the peer and another for listening
        for other peers on the network.

        This method runs both threads as daemon threads, ensuring they do not
        block the program from exiting.
        """
        threading.Thread(target=self.broadcast_presence, daemon=True).start()
        threading.Thread(target=self.listen_for_peers, daemon=True).start()

    def get_peers_snapshot(self) -> Dict[str, bytes]:
        """
        Retrieve a snapshot of the current peers.

        This method returns a dictionary containing the current state of peers,
        where the keys are peer identifiers (as strings) and the values are
        associated data (as bytes). The method ensures thread-safe access to
        the peers data by acquiring a lock during the operation.

        Returns:
            Dict[str, bytes]: A dictionary representing the current peers and
            their associated data.
        """
        with self.lock:
            return dict(self.peers)