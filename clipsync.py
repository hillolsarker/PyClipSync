import socket
import threading
import pyperclip
import time
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

# Get local machine's IP
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # External dummy connection
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
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

### Step 2: Share clipboard contents ###
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
            for peer in peers:
                send_to_peer(peer, current_clipboard)
        time.sleep(1)

def send_to_peer(peer_ip, clipboard_text):
    """
    Sends clipboard text to a specific peer.

    Args:
        peer_ip (str): The IP address of the peer to send the clipboard text to.
        clipboard_text (str): The text from the clipboard to send.

    Raises:
        Exception: If there is an error in creating the socket, connecting to the peer, or sending the data.

    Logs:
        Info: Logs the first 50 characters of the clipboard text sent to the peer.
        Warning: Logs a warning if sending the clipboard text fails and removes the peer from the list of reachable peers.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((peer_ip, CLIPBOARD_PORT))
        sock.sendall(clipboard_text.encode())
        logging.info(f"Sent clipboard to {peer_ip}: {clipboard_text[:50]}...")  # Log first 50 chars
        sock.close()
    except Exception as e:
        logging.warning(f"Failed to send clipboard to {peer_ip}: {e}")
        peers.discard(peer_ip)  # Remove unreachable peers

def receive_clipboard():
    """
    Listens for clipboard data from peers and updates local clipboard.

    This function creates a socket to listen for incoming clipboard data on a specified port.
    When data is received, it logs the source address and the first 50 characters of the data,
    then updates the local clipboard with the received data.

    Raises:
        OSError: If there is an issue with the socket connection.

    Note:
        Ensure that the `CLIPBOARD_PORT` is defined and `pyperclip` and `logging` modules are properly configured.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("", CLIPBOARD_PORT))
    sock.listen(5)

    while True:
        conn, addr = sock.accept()
        data = conn.recv(4096).decode()
        if data:
            logging.info(f"Received clipboard from {addr[0]}: {data[:50]}...")
            pyperclip.copy(data)  # Set clipboard
        conn.close()


if __name__ == "__main__":
    threading.Thread(target=broadcast_presence, daemon=True).start()
    threading.Thread(target=listen_for_peers, daemon=True).start()
    threading.Thread(target=send_clipboard, daemon=True).start()
    threading.Thread(target=receive_clipboard, daemon=True).start()

    logging.info("Clipboard sharing service started. Running in background...")
    while True:
        time.sleep(60)  # Keep main thread alive