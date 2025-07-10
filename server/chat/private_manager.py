from fastapi import WebSocket
import json
from typing import Union, Set
from server.utils.models import PrivateMessage, PmDisconnectMessage

class PrivateConnectionManager:
    def __init__(self):
        self.private_connections: dict[str, WebSocket] = {}
        self.public_keys: dict[str, str] = {}
        self.active_pm_sessions: dict[str, Set[str]] = {}

    async def connect(self, websocket: WebSocket, username: str):
        self.private_connections[username] = websocket

    def disconnect(self, username: str):
        self.private_connections.pop(username, None)
        self.public_keys.pop(username, None)

    async def disconnect_and_notify_partners(self, username: str):
        """Disconnect a user and notify their PM partners."""
        partners = self.active_pm_sessions.get(username, set()).copy()

        for partner in partners:
            await self.send_to_user(partner, PmDisconnectMessage(sender=username))
            self.active_pm_sessions.get(partner, set()).discard(username)
            if not self.active_pm_sessions.get(partner):
                self.active_pm_sessions.pop(partner, None)

        self.active_pm_sessions.pop(username, None)
        self.disconnect(username)

    def add_pm_session(self, user1: str, user2: str):
        """Track that user1 and user2 are in a PM session."""
        self.active_pm_sessions.setdefault(user1, set()).add(user2)
        self.active_pm_sessions.setdefault(user2, set()).add(user1)

    def remove_pm_session(self, user1: str, user2: str):
        """Remove PM session between user1 and user2."""
        for a, b in [(user1, user2), (user2, user1)]:
            if a in self.active_pm_sessions:
                self.active_pm_sessions[a].discard(b)
                if not self.active_pm_sessions[a]:
                    self.active_pm_sessions.pop(a)

    def register_pubkey(self, username: str, pubkey: str):
        self.public_keys[username] = pubkey
        print(f"Registered public key for {username}")

    def get_pubkey(self, username: str) -> str:
        key = self.public_keys.get(username)
        print(f"Public key lookup for {username}: {'found' if key else 'not found'}")
        return key

    async def send_to_user(self, username: str, payload: PrivateMessage):
        """Send a validated Pydantic message to a user if connected."""
        websocket = self.private_connections.get(username)
        if not websocket:
            return

        try:
            message = payload.model_dump(by_alias=True, mode='json')
            await websocket.send_json(message)
        except Exception as e:
            print(f"Failed to send message to {username}: {e}")
            self.private_connections.pop(username, None)


    def _validate_message(self, payload: dict) -> PrivateMessage:
        """Validate a raw dictionary payload into a typed Pydantic message."""
        msg_type = payload.get("type")
        if not msg_type:
            raise ValueError("Missing 'type' in message")

        from server.utils.models import (
            PmInviteMessage, PmAcceptMessage, PmDeclineMessage, 
            PmTextMessage, PmDisconnectMessage, 
            PubkeyRequestMessage, PubkeyResponseMessage,
        )

        type_map = {
            "pm_invite": PmInviteMessage,
            "pm_accept": PmAcceptMessage,
            "pm_decline": PmDeclineMessage,
            "pm_message": PmTextMessage,
            "pm_disconnect": PmDisconnectMessage,
            "pubkey_request": PubkeyRequestMessage,
            "pubkey_response": PubkeyResponseMessage,
        }

        model_class = type_map.get(msg_type)
        if not model_class:
            raise ValueError(f"Unknown message type: {msg_type}")
        
        return model_class.model_validate(payload)
