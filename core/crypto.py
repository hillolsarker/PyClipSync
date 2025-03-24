from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
import os

class CryptoManager:
    def __init__(self):
        self.private_key: X25519PrivateKey = x25519.X25519PrivateKey.generate()
        self.public_key: bytes = self.private_key.public_key().public_bytes_raw()

    def encrypt(self, plaintext, peer_public_key_bytes) -> bytes:
        shared_secret: bytes = self.private_key.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes))
        aesgcm = AESGCM(shared_secret)
        nonce : bytes = os.urandom(12)
        ciphertext: bytes = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return nonce + ciphertext

    def decrypt(self, encrypted_data: bytes, peer_public_key_bytes: bytes) -> str:
        shared_secret = self.private_key.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes))
        aesgcm = AESGCM(shared_secret)
        nonce: bytes  = encrypted_data[:12]
        ciphertext: bytes = encrypted_data[12:]
        return aesgcm.decrypt(nonce, ciphertext, None).decode()