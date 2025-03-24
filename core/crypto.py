from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
import os

class CryptoManager:
    def __init__(self):
        """
        Initializes a new instance of the class, generating a private key and 
        deriving the corresponding public key.

        Attributes:
            private_key (X25519PrivateKey): The generated private key using the X25519 algorithm.
            public_key (bytes): The raw public key bytes derived from the private key.
        """
        self.private_key: X25519PrivateKey = x25519.X25519PrivateKey.generate()
        self.public_key: bytes = self.private_key.public_key().public_bytes_raw()

    def encrypt(self, plaintext, peer_public_key_bytes) -> bytes:
        """
        Encrypts the given plaintext using the recipient's public key and AES-GCM.

        This method performs the following steps:
        1. Derives a shared secret using the private key of the sender and the public key of the recipient.
        2. Uses the shared secret to initialize an AES-GCM cipher.
        3. Generates a random nonce for encryption.
        4. Encrypts the plaintext using AES-GCM with the generated nonce.

        Args:
            plaintext (str): The plaintext message to be encrypted.
            peer_public_key_bytes (bytes): The recipient's public key in bytes format.

        Returns:
            bytes: The encrypted message, which includes the nonce concatenated with the ciphertext.
        """
        shared_secret: bytes = self.private_key.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes))
        aesgcm = AESGCM(shared_secret)
        nonce : bytes = os.urandom(12)
        ciphertext: bytes = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return nonce + ciphertext

    def decrypt(self, encrypted_data: bytes, peer_public_key_bytes: bytes) -> str:
        """
        Decrypts the provided encrypted data using the peer's public key and the private key of this instance.

        Args:
            encrypted_data (bytes): The encrypted data to be decrypted. The first 12 bytes are expected to be the nonce,
                                    and the remaining bytes are the ciphertext.
            peer_public_key_bytes (bytes): The public key of the peer in bytes format, used to derive the shared secret.

        Returns:
            str: The decrypted plaintext as a string.

        Raises:
            cryptography.exceptions.InvalidTag: If the decryption fails due to an invalid authentication tag.
            ValueError: If the input data is improperly formatted or invalid.
        """
        shared_secret = self.private_key.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes))
        aesgcm = AESGCM(shared_secret)
        nonce: bytes  = encrypted_data[:12]
        ciphertext: bytes = encrypted_data[12:]
        return aesgcm.decrypt(nonce, ciphertext, None).decode()