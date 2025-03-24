from omegaconf import DictConfig

class AppConfig:
    def __init__(self, config: DictConfig):
        """
        Initializes the configuration settings for the application.

        Args:
            config (DictConfig): A configuration object containing the following attributes:
                - clipboard.port (int): The port number used for clipboard synchronization.
                - discovery.broadcast_port (int): The port number used for discovery broadcasts.
                - discovery.interval (int): The interval (in seconds) for discovery operations.
                - clipboard.poll_interval (int): The interval (in seconds) for polling clipboard changes.
                - crypto.encryption (bool): A flag indicating whether encryption is enabled.
                - input.port (int): The port number used for input operations.
        """
        self.clipboard_port: int = config.clipboard.port
        self.broadcast_port: int = config.discovery.broadcast_port
        self.discovery_interval: int = config.discovery.interval
        self.poll_interval: int = config.clipboard.poll_interval
        self.encryption_enabled: bool = config.crypto.encryption
        self.input_port: int = config.input.port