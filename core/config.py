from omegaconf import DictConfig

class AppConfig:
    def __init__(self, config: DictConfig):
        self.clipboard_port = config.clipboard.port
        self.broadcast_port = config.discovery.broadcast_port
        self.discovery_interval = config.discovery.interval
        self.poll_interval = config.clipboard.poll_interval
        self.encryption_enabled = config.crypto.encryption