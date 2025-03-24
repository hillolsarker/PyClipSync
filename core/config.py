from omegaconf import DictConfig

class AppConfig:
    def __init__(self, config: DictConfig):
        self.clipboard_port: int = config.clipboard.port
        self.broadcast_port: int = config.discovery.broadcast_port
        self.discovery_interval: int = config.discovery.interval
        self.poll_interval: int = config.clipboard.poll_interval
        self.encryption_enabled: bool = config.crypto.encryption