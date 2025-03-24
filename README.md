# PyClipSync

PyClipSync is a lightweight, cross-platform clipboard-sharing application that allows multiple devices on the same local network to synchronize their clipboards seamlessly. It uses a combination of UDP broadcast for peer discovery and TCP for clipboard content sharing, with optional end-to-end encryption.

## Features
- Automatic peer discovery over a local network
- Encrypted clipboard synchronization between trusted devices
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
git clone https://github.com/hillolsarker/PyClipSync.git
cd PyClipSync
pip install -r requirements.txt
```

## Usage
Simply run the script on each device you want to share the clipboard with:
```sh
python clipsync.py
```
This will start the clipboard-sharing service in the background.

**Note:** If you encounter firewall-related issues, a quick workaround is to run the script with elevated privileges:
```sh
sudo python clipsync.py
```

## How It Works
- Each device broadcasts its presence via UDP on port `50000`.
- Devices listen for broadcasts and maintain a list of discovered peers.
- When the clipboard changes on one device, it encrypts and sends the content to all discovered peers over TCP port `50001`.
- Each receiving device decrypts and updates its local clipboard.

## Configuration
Configurations are defined in `conf/config.yaml`. You can customize the following parameters:

```yaml
clipboard:
  port: 50001            # TCP port for clipboard sync
  poll_interval: 1       # Polling interval for detecting clipboard changes

discovery:
  broadcast_port: 50000  # UDP port for broadcasting peer presence
  interval: 5            # Broadcast interval in seconds

crypto:
  encryption: true       # Enable or disable end-to-end encryption

logging:
  level: INFO            # Logging level (e.g., DEBUG, INFO, WARNING)
```

## Logging
The script logs peer discovery, clipboard updates, encryption status, and errors. To enable debug logging, update the logging level in `conf/config.yaml`:
```yaml
logging:
  level: DEBUG
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

