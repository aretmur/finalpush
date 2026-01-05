"""
Cryptographic Key Management for AAPM
Handles Ed25519 key generation, rotation, and storage.
"""
import os
import uuid
import hashlib
import base64
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet


# In-memory key store for demo (production would use database)
_key_store: Dict[str, Dict[str, Any]] = {}
_active_key_id: Dict[str, str] = {}  # org_id -> active key_id


def get_encryption_key() -> bytes:
    """
    Get the master encryption key for encrypting private keys at rest.
    In production, this would come from a KMS or HSM.
    """
    key = os.getenv("AAPM_MASTER_KEY")
    if key:
        return base64.urlsafe_b64decode(key)
    # Generate a default key for demo (NOT for production)
    return Fernet.generate_key()


def encrypt_private_key(private_key_pem: bytes) -> str:
    """Encrypt private key for storage."""
    f = Fernet(get_encryption_key())
    return f.encrypt(private_key_pem).decode('utf-8')


def decrypt_private_key(encrypted_key: str) -> bytes:
    """Decrypt private key from storage."""
    f = Fernet(get_encryption_key())
    return f.decrypt(encrypted_key.encode('utf-8'))


def generate_key_pair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate a new Ed25519 key pair."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_private_key(private_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Serialize private key to PEM format."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def serialize_public_key(public_key: ed25519.Ed25519PublicKey) -> str:
    """Serialize public key to PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')


def load_public_key(public_key_pem: str) -> ed25519.Ed25519PublicKey:
    """Load public key from PEM string."""
    key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError("Invalid Ed25519 public key")
    return key


def load_private_key(private_key_pem: bytes) -> ed25519.Ed25519PrivateKey:
    """Load private key from PEM bytes."""
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("Invalid Ed25519 private key")
    return key


class KeyManager:
    """
    Manages cryptographic keys for an organization.
    Supports key generation, rotation, and retrieval.
    """
    
    def __init__(self, org_id: str):
        self.org_id = org_id
    
    def create_key(self, key_type: str = "signing") -> Dict[str, Any]:
        """
        Create a new key pair and store it.
        Returns key metadata (without private key).
        """
        key_id = f"aapm-{key_type}-{uuid.uuid4().hex[:8]}"
        private_key, public_key = generate_key_pair()
        
        # Serialize keys
        private_key_pem = serialize_private_key(private_key)
        public_key_pem = serialize_public_key(public_key)
        
        # Encrypt private key for storage
        encrypted_private_key = encrypt_private_key(private_key_pem)
        
        # Store key
        key_data = {
            "id": key_id,
            "org_id": self.org_id,
            "key_type": key_type,
            "public_key": public_key_pem,
            "private_key_encrypted": encrypted_private_key,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "active": True,
            "algorithm": "Ed25519"
        }
        
        # Store in memory (production: database)
        if self.org_id not in _key_store:
            _key_store[self.org_id] = {}
        _key_store[self.org_id][key_id] = key_data
        _active_key_id[self.org_id] = key_id
        
        return {
            "id": key_id,
            "org_id": self.org_id,
            "key_type": key_type,
            "public_key": public_key_pem,
            "created_at": key_data["created_at"],
            "active": True,
            "algorithm": "Ed25519"
        }
    
    def rotate_key(self) -> Dict[str, Any]:
        """
        Rotate the active signing key.
        Creates a new key and marks the old one as inactive.
        """
        # Deactivate old key
        old_key_id = _active_key_id.get(self.org_id)
        if old_key_id and self.org_id in _key_store:
            if old_key_id in _key_store[self.org_id]:
                _key_store[self.org_id][old_key_id]["active"] = False
        
        # Create new key
        new_key = self.create_key("signing")
        
        return {
            "new_key": new_key,
            "old_key_id": old_key_id,
            "rotated_at": datetime.utcnow().isoformat() + "Z"
        }
    
    def get_active_key(self) -> Optional[Dict[str, Any]]:
        """Get the currently active signing key metadata."""
        key_id = _active_key_id.get(self.org_id)
        if not key_id:
            # Auto-create a key if none exists
            return self.create_key("signing")
        
        if self.org_id in _key_store and key_id in _key_store[self.org_id]:
            key_data = _key_store[self.org_id][key_id]
            return {
                "id": key_data["id"],
                "org_id": key_data["org_id"],
                "key_type": key_data["key_type"],
                "public_key": key_data["public_key"],
                "created_at": key_data["created_at"],
                "active": key_data["active"],
                "algorithm": key_data["algorithm"]
            }
        return None
    
    def get_key_by_id(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Get key metadata by key ID."""
        if self.org_id in _key_store and key_id in _key_store[self.org_id]:
            key_data = _key_store[self.org_id][key_id]
            return {
                "id": key_data["id"],
                "org_id": key_data["org_id"],
                "key_type": key_data["key_type"],
                "public_key": key_data["public_key"],
                "created_at": key_data["created_at"],
                "active": key_data["active"],
                "algorithm": key_data["algorithm"]
            }
        return None
    
    def get_all_keys(self) -> List[Dict[str, Any]]:
        """Get all keys for the organization."""
        if self.org_id not in _key_store:
            return []
        
        return [
            {
                "id": key_data["id"],
                "org_id": key_data["org_id"],
                "key_type": key_data["key_type"],
                "public_key": key_data["public_key"],
                "created_at": key_data["created_at"],
                "active": key_data["active"],
                "algorithm": key_data["algorithm"]
            }
            for key_data in _key_store[self.org_id].values()
        ]
    
    def sign_data(self, data: str) -> Optional[Dict[str, str]]:
        """
        Sign data with the active private key.
        Returns signature dict with hex-encoded signature and key_id.
        """
        key_id = _active_key_id.get(self.org_id)
        if not key_id or self.org_id not in _key_store:
            # Auto-create key
            self.create_key("signing")
            key_id = _active_key_id.get(self.org_id)
        
        if not key_id:
            return None
        
        key_data = _key_store[self.org_id].get(key_id)
        if not key_data:
            return None
        
        try:
            # Decrypt and load private key
            private_key_pem = decrypt_private_key(key_data["private_key_encrypted"])
            private_key = load_private_key(private_key_pem)
            
            # Sign
            signature = private_key.sign(data.encode('utf-8'))
            
            return {
                "signature": signature.hex(),
                "key_id": key_id,
                "algorithm": "Ed25519",
                "signed_at": datetime.utcnow().isoformat() + "Z"
            }
        except Exception as e:
            print(f"Signing error: {e}")
            return None
    
    def verify_signature(self, data: str, signature_hex: str, key_id: str) -> bool:
        """
        Verify a signature using the specified key.
        """
        key_data = self.get_key_by_id(key_id)
        if not key_data:
            return False
        
        try:
            public_key = load_public_key(key_data["public_key"])
            signature = bytes.fromhex(signature_hex)
            public_key.verify(signature, data.encode('utf-8'))
            return True
        except Exception:
            return False


def get_key_manager(org_id: str) -> KeyManager:
    """Factory function to get a KeyManager for an organization."""
    return KeyManager(org_id)
