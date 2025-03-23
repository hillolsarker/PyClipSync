from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class CryptoManager:
    def __init__(self):
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key().public_bytes_raw()

    def encrypt(self, plaintext, peer_public_key_bytes):
        shared_secret = self.private_key.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes))
        aesgcm = AESGCM(shared_secret)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return nonce + ciphertext

    def decrypt(self, encrypted_data, peer_public_key_bytes):
        shared_secret = self.private_key.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes))
        aesgcm = AESGCM(shared_secret)
        nonce, ciphertext = encrypted_data[:12], encrypted_data[12:]
        return aesgcm.decrypt(nonce, ciphertext, None).decode()