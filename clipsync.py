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