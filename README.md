# PyClipSync

PyClipSync is a lightweight, cross-platform clipboard-sharing application that allows multiple devices on the same local network to synchronize their clipboards seamlessly. It uses a combination of UDP broadcast for peer discovery and TCP for clipboard content sharing.

## Features
- Automatic peer discovery over a local network
- Clipboard synchronization between multiple connected devices
- Lightweight and runs in the background
- Cross-platform support (Windows, macOS, Linux)

## Installation
### Prerequisites
Ensure you have Python 3 installed on your system. You can check your Python version using:
```sh
python --version
```

### Install Dependencies
Clone the repository and install the required dependencies using:
```sh
git clone https://github.com/yourusername/PyClipSync.git
cd PyClipSync
pip install -r requirements.txt
```

## Usage
Simply run the script on each device that you want to share the clipboard with:
```sh
python clipsync.py
```
This will start the clipboard-sharing service in the background.

## How It Works
- Each device broadcasts its presence via UDP on port `50000`.
- Devices listen for broadcasts and update the list of peers.
- When the clipboard changes on one device, it sends the clipboard content to all discovered peers over TCP port `50001`.
- Each receiving device updates its clipboard with the received content.

## Configuration
- `BROADCAST_PORT` (default: `50000`) - UDP port used for peer discovery.
- `CLIPBOARD_PORT` (default: `50001`) - TCP port used for clipboard sharing.
- `DISCOVERY_INTERVAL` (default: `5` seconds) - Interval for sending discovery broadcasts.
- `PEER_TIMEOUT` (default: `10` seconds) - Time before removing an unresponsive peer.

## Logging
The script logs important events such as peer discovery, clipboard updates, and connection errors. To enable debug logging, modify the logging level in `clipsync.py`:
```python
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.DEBUG,
)
```

## Known Issues
- Only text-based clipboard contents are supported.
- Network firewalls may block UDP/TCP communication between peers.
- Some Linux distributions may require `xclip` or `xsel` for `pyperclip` to work:
  ```sh
  sudo apt install xclip  # or
  sudo apt install xsel
  ```

## License
This project is licensed under the MIT License. Feel free to modify and contribute!

## Contributions
Contributions are welcome! If you find any issues or have feature requests, open an issue or submit a pull request on GitHub.

## Author
Developed by Hillol Sarker