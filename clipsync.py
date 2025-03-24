import time
import logging
import hydra
from omegaconf import DictConfig
from core.crypto import CryptoManager
from core.clipboard_manager import ClipboardManager
from core.peer_discovery import PeerDiscovery
from core.clipboard_sync import ClipboardSync
from core.config import AppConfig

@hydra.main(config_path="conf", config_name="config", version_base=None)
def main(config: DictConfig):
    """
    Entry point for the clipboard sharing service.

    This function initializes and starts the necessary components for the 
    clipboard sharing service, including logging, configuration, cryptography, 
    clipboard management, peer discovery, and clipboard synchronization.

    Args:
        config (DictConfig): The configuration object containing settings 
                             for logging, application behavior, and other 
                             parameters.

    Components:
        - Logging: Configures the logging system based on the provided 
          configuration.
        - AppConfig: Wraps the configuration for easier access and management.
        - CryptoManager: Handles cryptographic operations, such as generating 
          public/private keys.
        - ClipboardManager: Manages clipboard operations.
        - PeerDiscovery: Discovers peers on the network and handles peer 
          communication.
        - ClipboardSync: Synchronizes clipboard content across discovered peers.

    Behavior:
        - Starts the peer discovery and clipboard synchronization services.
        - Logs the service startup message.
        - Keeps the service running indefinitely with periodic sleep intervals.

    Note:
        This function runs an infinite loop to keep the service active. 
        Ensure proper termination handling when integrating into larger systems.
    """
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=config.logging.level
    )

    app_config = AppConfig(config)

    crypto = CryptoManager()
    clipboard = ClipboardManager()
    discovery = PeerDiscovery(app_config, crypto.public_key, lambda ip, pk: None)
    sync = ClipboardSync(app_config, crypto, clipboard, discovery)

    discovery.start()
    sync.start()

    logging.info("Clipboard sharing service started.")
    while True:
        time.sleep(60)

if __name__ == "__main__":
    main()