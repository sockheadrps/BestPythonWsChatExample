import pytest
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


class TestRSAKeyGeneration:
    """Test RSA key generation functionality."""
    
    def test_generate_rsa_key_pair(self):
        """Test generating an RSA key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        
        assert private_key is not None
        assert public_key is not None
        assert private_key.key_size == 2048
        assert public_key.key_size == 2048
    
    def test_public_key_serialization(self):
        """Test public key serialization to base64."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        
        # Serialize public key to SPKI format
        public_key_spki = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_b64 = base64.b64encode(public_key_spki).decode('utf-8')
        
        assert len(public_key_b64) > 0
        assert isinstance(public_key_b64, str)
        # Should be valid base64
        base64.b64decode(public_key_b64)


class TestRSAEncryption:
    """Test RSA encryption and decryption."""
    
    def test_encrypt_decrypt_message(self, rsa_key_pair):
        """Test encrypting and decrypting a message."""
        private_key = rsa_key_pair["private_key"]
        public_key = rsa_key_pair["public_key"]
        
        original_message = "Hello, this is a secret message!"
        
        # Encrypt with public key
        encrypted = public_key.encrypt(
            original_message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt with private key
        decrypted = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        decrypted_message = decrypted.decode('utf-8')
        
        assert decrypted_message == original_message
        assert encrypted != original_message.encode('utf-8')
    
    def test_encrypt_with_base64_public_key(self, rsa_key_pair):
        """Test encrypting with a base64-encoded public key."""
        private_key = rsa_key_pair["private_key"]
        public_key_b64 = rsa_key_pair["public_key_b64"]
        
        original_message = "Test message for encryption"
        
        # Deserialize public key from base64
        public_key_der = base64.b64decode(public_key_b64)
        public_key = serialization.load_der_public_key(public_key_der)
        
        # Encrypt
        encrypted = public_key.encrypt(
            original_message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt with private key
        decrypted = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        decrypted_message = decrypted.decode('utf-8')
        assert decrypted_message == original_message


class TestEncryptionIntegration:
    """Test encryption integration scenarios."""
    
    def test_full_encryption_workflow(self):
        """Test the complete encryption workflow from key generation to decryption."""
        # Generate keys (like the bot does)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        
        # Serialize public key for transmission (like in WebSocket messages)
        public_key_spki = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_b64 = base64.b64encode(public_key_spki).decode('utf-8')
        
        # Recipient deserializes public key (like bot storing user keys)
        received_public_key_der = base64.b64decode(public_key_b64)
        received_public_key = serialization.load_der_public_key(received_public_key_der)
        
        # Encrypt message with received public key
        original_message = "Hello from the chat application!"
        encrypted = received_public_key.encrypt(
            original_message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Encode encrypted message for transmission
        encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
        
        # Recipient decodes and decrypts
        received_encrypted = base64.b64decode(encrypted_b64)
        decrypted = private_key.decrypt(
            received_encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        final_message = decrypted.decode('utf-8')
        assert final_message == original_message
    
    def test_unicode_message_encryption(self, rsa_key_pair):
        """Test encrypting and decrypting Unicode messages."""
        private_key = rsa_key_pair["private_key"]
        public_key = rsa_key_pair["public_key"]
        
        # Unicode message with emojis and various scripts
        unicode_message = "Hello 🌍! こんにちは Привет Bonjour"
        
        # Encrypt
        encrypted = public_key.encrypt(
            unicode_message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt
        decrypted = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        decrypted_message = decrypted.decode('utf-8')
        assert decrypted_message == unicode_message
    
    def test_empty_message_encryption(self, rsa_key_pair):
        """Test encrypting and decrypting empty messages."""
        private_key = rsa_key_pair["private_key"]
        public_key = rsa_key_pair["public_key"]
        
        empty_message = ""
        
        # Encrypt
        encrypted = public_key.encrypt(
            empty_message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt
        decrypted = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        decrypted_message = decrypted.decode('utf-8')
        assert decrypted_message == empty_message 