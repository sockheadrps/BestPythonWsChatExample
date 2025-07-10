import asyncio
import json
import random
import base64
from typing import Dict, List, Optional
from fastapi import WebSocket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from server.chat.manager import ConnectionManager
from server.chat.private_manager import PrivateConnectionManager
from server.chat.bot_responses import BotResponses
from server.utils.models import (
    PmAcceptMessage, PmTextMessage, PubkeyRequestMessage, PubkeyResponseMessage
)


class BotWebSocket:
    """Mock WebSocket for the bot user"""
    
    def __init__(self, bot_username: str):
        self.bot_username = bot_username
        self.is_connected = True
        
    async def accept(self):
        pass
    
    async def send_json(self, data):
        # Bot receives messages but doesn't need to do anything with most of them
        # We'll handle specific message types in the bot logic
        pass
    
    async def receive_json(self):
        # This won't be called for the bot
        pass
    
    async def close(self, code: int = 1000):
        self.is_connected = False


class ChatBot:
    def __init__(self, username: str = "ChatBot"):
        self.username = username
        self.websocket = BotWebSocket(username)
        self.active_conversations: Dict[str, List[str]] = {}
        
        # RSA encryption keys
        self.private_key = None
        self.public_key = None
        self.public_key_pem = None
        self.user_public_keys: Dict[str, bytes] = {}  # Store other users' public keys
        
        # Response system
        self.response_system = BotResponses()
        
        # Generate RSA key pair for the bot
        self._generate_key_pair()
    
    def _generate_key_pair(self):
        """Generate RSA key pair for the bot"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()
        
        # Export public key in SPKI format (same as client-side)
        public_key_spki = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.public_key_pem = base64.b64encode(public_key_spki).decode('utf-8')
        print(f"🔐 Generated RSA key pair for {self.username}")
    
    def encrypt_message(self, message: str, recipient_username: str) -> str:
        """Encrypt a message for a specific recipient"""
        if recipient_username not in self.user_public_keys:
            raise ValueError(f"No public key available for {recipient_username}")
        
        # Import the recipient's public key
        public_key_der = self.user_public_keys[recipient_username]
        recipient_public_key = serialization.load_der_public_key(public_key_der)
        
        # Encrypt the message
        message_bytes = message.encode('utf-8')
        encrypted = recipient_public_key.encrypt(
            message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Return base64 encoded ciphertext
        return base64.b64encode(encrypted).decode('utf-8')
    
    def decrypt_message(self, ciphertext: str) -> str:
        """Decrypt a message sent to the bot"""
        try:
            encrypted_bytes = base64.b64decode(ciphertext)
            decrypted = self.private_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted.decode('utf-8')
        except Exception as e:
            print(f"🤖 Error decrypting message: {e}")
            return ciphertext  # Return as plain text if decryption fails
    
    def store_user_public_key(self, username: str, public_key_b64: str):
        """Store a user's public key for encryption"""
        try:
            public_key_der = base64.b64decode(public_key_b64)
            self.user_public_keys[username] = public_key_der
            print(f"🔐 Stored public key for {username}")
        except Exception as e:
            print(f"🤖 Error storing public key for {username}: {e}")
        
    async def initialize(self, manager: ConnectionManager, private_manager: PrivateConnectionManager):
        """Initialize the bot by connecting to both managers"""
        self.manager = manager
        self.private_manager = private_manager
        
        # Connect the bot to both managers
        await manager.connect(self.websocket, self.username)
        await private_manager.connect(self.websocket, self.username)
        
        print(f"✅ {self.username} is now online and ready to chat!")
        
    def get_response(self, user: str, message: str) -> str:
        """Generate a response based on the user and their message"""
        return self.response_system.get_response(user, message, self.active_conversations)
    
    def customize_responses(self, **kwargs):
        """Allow customization of bot responses"""
        self.response_system.customize_responses(**kwargs)
    
    async def handle_pm_invite(self, from_user: str):
        """Automatically accept all PM invites"""
        print(f"🤖 {self.username} received PM invite from {from_user} - auto-accepting")
        
        # Track the PM session when bot accepts
        self.private_manager.add_pm_session(self.username, from_user)
        
        # Send acceptance back through the private manager
        accept_msg = PmAcceptMessage(sender=self.username)
        await self.private_manager.send_to_user(from_user, accept_msg)
        
        # Request the user's public key for encryption
        request_msg = PubkeyRequestMessage(sender=self.username)
        await self.private_manager.send_to_user(from_user, request_msg)
    
    async def handle_pubkey_request(self, from_user: str):
        """Respond to public key requests by sending bot's public key"""
        print(f"🤖 {self.username} sending public key to {from_user}")
        
        response_msg = PubkeyResponseMessage(
            sender=self.username,
            public_key=self.public_key_pem
        )
        await self.private_manager.send_to_user(from_user, response_msg)
    
    async def handle_pubkey_response(self, from_user: str, public_key: str):
        """Store a user's public key when they send it"""
        self.store_user_public_key(from_user, public_key)
    
    async def handle_pm_message(self, from_user: str, ciphertext: str):
        """Respond to private messages"""
        # Decrypt the incoming message
        try:
            message = self.decrypt_message(ciphertext)
            print(f"🤖 {self.username} received message from {from_user}: {message}")
        except Exception as e:
            print(f"🤖 Error decrypting message from {from_user}: {e}")
            message = "I couldn't understand your message. Could you try sending it again?"
        
        # Generate a response
        response = self.get_response(from_user, message)
        
        # Wait a bit to simulate "typing" (makes it feel more natural)
        await asyncio.sleep(random.uniform(1.0, 3.0))
        
        # Encrypt and send the response back
        try:
            if from_user in self.user_public_keys:
                encrypted_response = self.encrypt_message(response, from_user)
                message = PmTextMessage(
                    sender=self.username,
                    ciphertext=encrypted_response
                )
                await self.private_manager.send_to_user(from_user, message)
                print(f"🤖 {self.username} responded to {from_user}: {response}")
            else:
                print(f"🤖 No public key available for {from_user}, requesting key first")
                # Request public key and queue the response
                request_msg = PubkeyRequestMessage(sender=self.username)
                await self.private_manager.send_to_user(from_user, request_msg)
        except Exception as e:
            print(f"🤖 Error sending encrypted response to {from_user}: {e}")
    
    async def handle_pm_disconnect(self, from_user: str):
        """Handle when a user disconnects from PM"""
        print(f"🤖 {self.username} - {from_user} disconnected from PM")
        
        # Remove the PM session
        self.private_manager.remove_pm_session(self.username, from_user)
        
        # Clean up conversation history and keys for this user
        if from_user in self.active_conversations:
            del self.active_conversations[from_user]
        if from_user in self.user_public_keys:
            del self.user_public_keys[from_user]


# Global bot instance
chat_bot = None

async def initialize_bot(manager: ConnectionManager, private_manager: PrivateConnectionManager):
    """Initialize the global chat bot"""
    global chat_bot
    if chat_bot is None:
        chat_bot = ChatBot("ChatBot")
        await chat_bot.initialize(manager, private_manager)
    return chat_bot

def get_bot() -> ChatBot:
    """Get the global bot instance"""
    return chat_bot 