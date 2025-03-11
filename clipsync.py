import socket
import threading
import pyperclip
import netifaces as ni
import time
import struct
import logging

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)

# Configuration
BROADCAST_PORT = 50000
CLIPBOARD_PORT = 50001
DISCOVERY_INTERVAL = 5  # Seconds
PEER_TIMEOUT = 10  # Seconds before removing a peer
peers = set()  # Stores discovered peers

def get_local_ip():
    """
    Retrieves the local IP address of the machine.

    This function attempts to get the IP address of the 'en0' network interface.
    If the 'en0' interface is not found or an error occurs, it defaults to returning '127.0.0.1'.

    Returns:
        str: The local IP address or '127.0.0.1' if the IP address cannot be determined.
    """
    try:
        interfaces = ni.interfaces()
        for iface in interfaces:
            iface_details = ni.ifaddresses(iface)
            if ni.AF_INET in iface_details:
                ip = iface_details[ni.AF_INET][0]['addr']
                if not ip.startswith("127."):  # Ignore loopback
                    return ip
        return "127.0.0.1"
    except Exception:
        return "127.0.0.1"


LOCAL_IP = get_local_ip()
logging.info(f"Local machine IP: {LOCAL_IP}")

def broadcast_presence():
    """
    Periodically sends broadcast messages for discovery.
    This function creates a UDP socket and sends broadcast messages 
    containing the local IP address at regular intervals. These messages 
    are used for discovering other peers on the network.
    The function runs indefinitely, sending messages every DISCOVERY_INTERVAL 
    seconds.
    Variables:
    LOCAL_IP (str): The local IP address of the machine.
    BROADCAST_PORT (int): The port number used for broadcasting messages.
    DISCOVERY_INTERVAL (int): The interval in seconds between broadcast messages.
    Logging:
    Logs a debug message each time a broadcast message is sent.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    
    while True:
        message = f"CLIPBOARD_PEER {LOCAL_IP}"
        sock.sendto(message.encode(), ('<broadcast>', BROADCAST_PORT))
        logging.debug(f"Broadcasting presence: {message}")
        time.sleep(DISCOVERY_INTERVAL)

def listen_for_peers():
    """
    Listens for broadcast messages from other peers and updates the list of peers.

    This function creates a UDP socket to listen for broadcast messages on a specified port.
    When a message is received, it checks if the message is from a new peer and adds the peer's
    IP address to the global list of peers if it is not already present.

    Global Variables:
    - peers (set): A set of IP addresses representing discovered peers.
    - BROADCAST_PORT (int): The port number on which to listen for broadcast messages.
    - LOCAL_IP (str): The IP address of the local machine to avoid adding itself to the peers list.

    The function runs indefinitely, continuously listening for and processing incoming messages.

    Raises:
    - socket.error: If there is an error creating or binding the socket.
    """
    global peers
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("", BROADCAST_PORT))  # Listen to all addresses

    while True:
        data, addr = sock.recvfrom(1024)
        peer_ip = addr[0]
        message = data.decode()

        if message.startswith("CLIPBOARD_PEER"):
            if peer_ip != LOCAL_IP:  # Ignore self
                if peer_ip not in peers:
                    logging.info(f"Discovered new peer: {peer_ip}")
                peers.add(peer_ip)

def send_clipboard():
    """
    Monitors the system clipboard for changes and sends the updated clipboard content to connected peers.

    This function runs an infinite loop that continuously checks the clipboard content. If a change is detected,
    it updates the last known clipboard content and sends the new content to all connected peers.

    The function uses the `pyperclip` library to access the clipboard and the `logging` module to log information
    about clipboard changes and the number of peers being notified.

    Note:
        This function assumes that `peers` is a list of peer addresses and `send_to_peer` is a function that
        handles sending data to a peer. It also assumes that the `time` module is imported for the sleep function.

    Raises:
        Any exceptions raised by `pyperclip.paste()` or `send_to_peer()` will propagate up to the caller.

    """
    last_clipboard = ""

    while True:
        current_clipboard = pyperclip.paste()
        if current_clipboard and current_clipboard != last_clipboard:
            last_clipboard = current_clipboard
            logging.info(f"Clipboard changed. Sending to {len(peers)} peer(s).")
            for peer in list(peers):
                send_to_peer(peer, current_clipboard)
        time.sleep(1)


def send_to_peer(peer_ip, clipboard_text):
    """
    Sends the clipboard text to a peer over a TCP connection.

    Args:
        peer_ip (str): The IP address of the peer to send the clipboard text to.
        clipboard_text (str): The text from the clipboard to send.

    Raises:
        Exception: If there is an error in creating the socket, connecting to the peer, 
                   or sending the data, an exception is caught and logged.

    Notes:
        The function first creates a socket and connects to the peer using the specified IP address 
        and a predefined port (CLIPBOARD_PORT). It then encodes the clipboard text and sends it 
        with a 4-byte length prefix. If an error occurs, it logs a warning and removes the peer 
        from the list of reachable peers.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((peer_ip, CLIPBOARD_PORT))

        # Encode clipboard text and get its length
        data = clipboard_text.encode()
        length_prefix = struct.pack("!I", len(data))  # 4-byte length header

        # Send length header first, then actual clipboard data
        sock.sendall(length_prefix + data)
        logging.info(f"Sent clipboard to {peer_ip}: {clipboard_text[:50]}...")
        sock.close()
    except Exception as e:
        logging.warning(f"Failed to send clipboard to {peer_ip}: {e}")
        peers.discard(peer_ip)  # Remove unreachable peers

def receive_clipboard():
    """
    Listens for incoming clipboard data on a specified port, receives the data,
    and sets the local clipboard with the received content.
    The function creates a socket to listen for incoming connections. When a 
    connection is accepted, it reads the first 4 bytes to determine the length 
    of the incoming message. It then reads the full message based on the length 
    and decodes it to a string. The received clipboard text is then copied to 
    the local clipboard using the pyperclip library.
    The function runs indefinitely, accepting and processing incoming clipboard 
    data.
    Logging:
        Logs the IP address of the sender and the first 50 characters of the 
        received clipboard text.
    Raises:
        Any exceptions raised by socket operations or pyperclip are not handled 
        within this function and will propagate to the caller.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("", CLIPBOARD_PORT))
    sock.listen(5)

    while True:
        conn, addr = sock.accept()

        # Read the first 4 bytes (message length)
        length_data = conn.recv(4)
        if not length_data:
            conn.close()
            continue

        # Unpack length and read full message
        message_length = struct.unpack("!I", length_data)[0]
        data = b""
        while len(data) < message_length:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        
        conn.close()
        clipboard_text = data.decode()
        
        if clipboard_text:
            logging.info(f"Received clipboard from {addr[0]}: {clipboard_text[:50]}...")
            pyperclip.copy(clipboard_text)  # Set clipboard


if __name__ == "__main__":
    threading.Thread(target=broadcast_presence, daemon=True).start()
    threading.Thread(target=listen_for_peers, daemon=True).start()
    threading.Thread(target=send_clipboard, daemon=True).start()
    threading.Thread(target=receive_clipboard, daemon=True).start()

    logging.info("Clipboard sharing service started. Running in background...")
    while True:
        time.sleep(60)  # Keep main thread alive