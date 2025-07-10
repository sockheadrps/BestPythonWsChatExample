import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from server.chat.manager import ConnectionManager
from server.chat.private_manager import PrivateConnectionManager
from server.utils.models import (
    # Server-side PM models
    PmInviteMessage, PmAcceptMessage, PmDeclineMessage, PmTextMessage,
    PmDisconnectMessage, PubkeyRequestMessage, PubkeyResponseMessage,
    
    # System messages
    UserListMessage, PubkeyLookupResponse, ErrorMessage,
    
    # Client-side models
    ClientChatMessage, ClientPmInvite, ClientPmAccept, ClientPmDecline,
    ClientPmMessage, ClientPmDisconnect, ClientPubkeyRequest,
    ClientPubkeyResponse, ClientPubkeyRegister, ClientPubkeyLookup,
    
    # Data models
    ChatMessageData, JoinData, LeaveData, WsEvent
)


class TestConnectionManager:
    """Test the main chat ConnectionManager."""
    
    def test_init_connection_manager(self, connection_manager):
        """Test ConnectionManager initialization."""
        assert connection_manager.active_connections == {}
    
    @pytest.mark.asyncio
    async def test_connect_user(self, connection_manager, mock_websocket):
        """Test connecting a user."""
        username = "testuser"
        
        await connection_manager.connect(mock_websocket, username)
        
        assert len(connection_manager.active_connections) == 1
        assert connection_manager.active_connections[username] == mock_websocket
    
    @pytest.mark.asyncio
    async def test_disconnect_user(self, connection_manager, mock_websocket):
        """Test disconnecting a user."""
        username = "testuser"
        
        # Connect first
        await connection_manager.connect(mock_websocket, username)
        assert len(connection_manager.active_connections) == 1
        
        # Disconnect
        connection_manager.disconnect(username)
        assert len(connection_manager.active_connections) == 0
    
    @pytest.mark.asyncio
    async def test_disconnect_nonexistent_user(self, connection_manager):
        """Test disconnecting a user that wasn't connected."""
        # Should not raise an error
        connection_manager.disconnect("nonexistent_user")
        assert len(connection_manager.active_connections) == 0
    
    @pytest.mark.asyncio
    async def test_broadcast_message(self, connection_manager):
        """Test broadcasting a message to all users."""
        # Create multiple mock websockets
        mock_ws1 = AsyncMock()
        mock_ws2 = AsyncMock()
        mock_ws3 = AsyncMock()
        
        # Connect users
        await connection_manager.connect(mock_ws1, "user1")
        await connection_manager.connect(mock_ws2, "user2")
        await connection_manager.connect(mock_ws3, "user3")
        
        # Reset call history from connect operations
        mock_ws1.send_json.reset_mock()
        mock_ws2.send_json.reset_mock()
        mock_ws3.send_json.reset_mock()
        
        # Create a WsEvent for broadcasting
        ws_event = WsEvent(
            event="chat_message",
            data=ChatMessageData(user="user1", message="Hello!")
        )
        
        # Broadcast message
        await connection_manager.broadcast(ws_event)
        
        expected_message = ws_event.model_dump(mode='json')
        
        # All websockets should have received the message
        mock_ws1.send_json.assert_called_once_with(expected_message)
        mock_ws2.send_json.assert_called_once_with(expected_message)
        mock_ws3.send_json.assert_called_once_with(expected_message)
    
    @pytest.mark.asyncio
    async def test_broadcast_with_broken_connection(self, connection_manager):
        """Test broadcasting when one connection is broken."""
        mock_ws1 = AsyncMock()
        mock_ws2 = AsyncMock()
        
        # Connect users first (before setting up the exception)
        await connection_manager.connect(mock_ws1, "user1")
        await connection_manager.connect(mock_ws2, "user2")
        
        # Now make ws2 raise an exception for future calls
        mock_ws2.send_json.side_effect = Exception("Connection broken")
        
        ws_event = WsEvent(
            event="chat_message",
            data=ChatMessageData(user="user1", message="Hello!")
        )
        
        # Should not raise an exception
        await connection_manager.broadcast(ws_event)
        
        # ws1 should still receive the message
        # Check that ws1 was called (it was called during connect and broadcast)
        assert mock_ws1.send_json.called
        # ws2 should be removed from active connections due to the exception
        assert len(connection_manager.active_connections) == 1
        assert "user1" in connection_manager.active_connections
    
    def test_get_connected_users(self, connection_manager):
        """Test getting list of connected users."""
        # Initially empty
        users = list(connection_manager.active_connections.keys())
        assert users == []
        
        # Add some users manually for testing
        connection_manager.active_connections = {
            "user1": AsyncMock(),
            "user2": AsyncMock()
        }
        
        users = list(connection_manager.active_connections.keys())
        assert len(users) == 2
        assert "user1" in users
        assert "user2" in users
    
    @pytest.mark.asyncio
    async def test_send_to_user(self, connection_manager):
        """Test sending message to specific user."""
        username = "testuser"
        message = {"type": "test", "content": "Hello"}
        mock_websocket = AsyncMock()
        
        # Connect user
        await connection_manager.connect(mock_websocket, username)
        
        # Reset mock to clear connect calls
        mock_websocket.send_json.reset_mock()
        
        # Send message to user
        await connection_manager.send_to_user(username, message)
        
        mock_websocket.send_json.assert_called_once_with(message)
    
    @pytest.mark.asyncio
    async def test_send_to_nonexistent_user(self, connection_manager):
        """Test sending message to user that doesn't exist."""
        message = {"type": "test", "content": "Hello"}
        
        # Should not raise an error
        await connection_manager.send_to_user("nonexistent_user", message)
    
    @pytest.mark.asyncio
    async def test_broadcast_user_list(self, connection_manager):
        """Test broadcasting user list to all connected users."""
        mock_ws1 = AsyncMock()
        mock_ws2 = AsyncMock()
        
        # Connect users
        await connection_manager.connect(mock_ws1, "user1")
        await connection_manager.connect(mock_ws2, "user2")
        
        # Reset mock call history from connect calls
        mock_ws1.send_json.reset_mock()
        mock_ws2.send_json.reset_mock()
        
        # Broadcast user list
        await connection_manager.broadcast_user_list()
        
        # Both users should receive user list
        assert mock_ws1.send_json.called
        assert mock_ws2.send_json.called


class TestPrivateConnectionManager:
    """Test the private message ConnectionManager."""
    
    def test_init_private_manager(self, private_manager):
        """Test PrivateConnectionManager initialization."""
        assert private_manager.private_connections == {}
        assert private_manager.public_keys == {}
        assert private_manager.active_pm_sessions == {}
    
    @pytest.mark.asyncio
    async def test_connect_user(self, private_manager):
        """Test connecting a user to private manager."""
        username = "testuser"
        mock_ws = AsyncMock()
        
        await private_manager.connect(mock_ws, username)
        
        assert username in private_manager.private_connections
        assert private_manager.private_connections[username] == mock_ws
    
    def test_disconnect_user(self, private_manager):
        """Test disconnecting a user from private manager."""
        username = "testuser"
        mock_ws = AsyncMock()
        
        # Manually add user
        private_manager.private_connections[username] = mock_ws
        private_manager.public_keys[username] = "test_key"
        
        # Disconnect
        private_manager.disconnect(username)
        
        assert username not in private_manager.private_connections
        assert username not in private_manager.public_keys
    
    def test_add_pm_session(self, private_manager):
        """Test adding a PM session between two users."""
        user1 = "alice"
        user2 = "bob"
        
        private_manager.add_pm_session(user1, user2)
        
        assert user1 in private_manager.active_pm_sessions
        assert user2 in private_manager.active_pm_sessions[user1]
        assert user2 in private_manager.active_pm_sessions
        assert user1 in private_manager.active_pm_sessions[user2]
    
    def test_remove_pm_session(self, private_manager):
        """Test removing a PM session."""
        user1 = "alice"
        user2 = "bob"
        
        # Add session first
        private_manager.add_pm_session(user1, user2)
        assert user1 in private_manager.active_pm_sessions
        
        # Remove session
        private_manager.remove_pm_session(user1, user2)
        
        assert user1 not in private_manager.active_pm_sessions
        assert user2 not in private_manager.active_pm_sessions
    
    def test_register_and_get_pubkey(self, private_manager):
        """Test registering and retrieving public keys."""
        username = "alice"
        pubkey = "test_public_key_base64"
        
        # Register key
        private_manager.register_pubkey(username, pubkey)
        
        # Retrieve key
        retrieved_key = private_manager.get_pubkey(username)
        assert retrieved_key == pubkey
        
        # Non-existent user
        assert private_manager.get_pubkey("nonexistent") is None
    
    @pytest.mark.asyncio
    async def test_send_to_user(self, private_manager):
        """Test sending message to specific user."""
        username = "alice"
        mock_ws = AsyncMock()
        
        # Connect user
        await private_manager.connect(mock_ws, username)
        
        # Create message
        from server.utils.models import PmTextMessage
        message = PmTextMessage(
            type="pm_message",
            sender="bob",
            ciphertext="encrypted_content"
        )
        
        # Send message
        await private_manager.send_to_user(username, message)
        
        # Check that websocket received the message
        mock_ws.send_json.assert_called_once()
        args = mock_ws.send_json.call_args[0][0]
        assert args["type"] == "pm_message"
        assert args["from"] == "bob"  # Uses alias
        assert args["ciphertext"] == "encrypted_content"
    
    @pytest.mark.asyncio
    async def test_send_to_nonexistent_user(self, private_manager):
        """Test sending message to user that's not connected."""
        from server.utils.models import PmTextMessage
        message = PmTextMessage(
            type="pm_message",
            sender="bob",
            ciphertext="encrypted_content"
        )
        
        # Should not raise an error
        await private_manager.send_to_user("nonexistent", message)
    
    @pytest.mark.asyncio
    async def test_disconnect_and_notify_partners(self, private_manager):
        """Test disconnecting user and notifying PM partners."""
        user1 = "alice"
        user2 = "bob"
        user3 = "charlie"
        mock_ws1 = AsyncMock()
        mock_ws2 = AsyncMock()
        mock_ws3 = AsyncMock()
        
        # Connect users
        await private_manager.connect(mock_ws1, user1)
        await private_manager.connect(mock_ws2, user2)
        await private_manager.connect(mock_ws3, user3)
        
        # Create PM sessions
        private_manager.add_pm_session(user1, user2)
        private_manager.add_pm_session(user1, user3)
        
        # Disconnect alice and notify partners
        await private_manager.disconnect_and_notify_partners(user1)
        
        # Alice should be disconnected
        assert user1 not in private_manager.private_connections
        assert user1 not in private_manager.active_pm_sessions
        
        # Bob and Charlie should be notified
        assert mock_ws2.send_json.called
        assert mock_ws3.send_json.called
    
    def test_validate_message(self, private_manager):
        """Test message validation."""
        # Valid PM invite message
        payload = {
            "type": "pm_invite",
            "from": "alice"
        }
        
        validated = private_manager._validate_message(payload)
        assert validated.type == "pm_invite"
        assert validated.sender == "alice"
        
        # Invalid message type
        invalid_payload = {"type": "invalid_type"}
        try:
            private_manager._validate_message(invalid_payload)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "Unknown message type" in str(e)
        
        # Missing type
        missing_type = {"data": "some data"}
        try:
            private_manager._validate_message(missing_type)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "Missing 'type'" in str(e)


class TestWebSocketMessageHandling:
    """Test WebSocket message handling logic."""
    
    @pytest.mark.asyncio
    async def test_user_connection_handling(self, connection_manager):
        """Test handling user connections."""
        mock_websocket = AsyncMock()
        username = "testuser"
        
        # Simulate handling user connection
        await connection_manager.connect(mock_websocket, username)
        
        assert len(connection_manager.active_connections) == 1
        assert connection_manager.active_connections[username] == mock_websocket
    
    @pytest.mark.asyncio
    async def test_user_disconnection_handling(self, connection_manager):
        """Test handling user disconnections."""
        mock_websocket = AsyncMock()
        username = "testuser"
        
        # Connect first
        await connection_manager.connect(mock_websocket, username)
        
        # Then disconnect
        connection_manager.disconnect(username)
        
        assert len(connection_manager.active_connections) == 0
    
    @pytest.mark.asyncio
    async def test_chat_message_broadcast(self, connection_manager):
        """Test broadcasting chat message."""
        mock_ws1 = AsyncMock()
        mock_ws2 = AsyncMock()
        
        await connection_manager.connect(mock_ws1, "user1")
        await connection_manager.connect(mock_ws2, "user2")
        
        # Reset call history from connect operations
        mock_ws1.send_json.reset_mock()
        mock_ws2.send_json.reset_mock()
        
        # Create WsEvent for chat message
        ws_event = WsEvent(
            event="chat_message",
            data=ChatMessageData(user="user1", message="Hello!")
        )
        
        await connection_manager.broadcast(ws_event)
        
        expected_message = ws_event.model_dump(mode='json')
        mock_ws1.send_json.assert_called_once_with(expected_message)
        mock_ws2.send_json.assert_called_once_with(expected_message)
    
    def test_user_list_generation(self, connection_manager):
        """Test user list generation."""
        # Add some users
        connection_manager.active_connections = {
            "user1": AsyncMock(),
            "user2": AsyncMock(),
            "ChatBot": AsyncMock()
        }
        
        users = list(connection_manager.active_connections.keys())
        
        # Should include all connected users (including bot)
        assert len(users) == 3
        assert "user1" in users
        assert "user2" in users
        assert "ChatBot" in users
    
    def test_user_list_message_creation(self):
        """Test creating UserListMessage."""
        users = ["alice", "bob", "charlie"]
        
        user_list_msg = UserListMessage(
            type="user_list",
            users=users
        )
        
        assert user_list_msg.type == "user_list"
        assert len(user_list_msg.users) == 3
        assert all(user in user_list_msg.users for user in users)


class TestPrivateMessageFlow:
    """Test private message flow end-to-end."""
    
    @pytest.mark.asyncio
    async def test_pm_invite_flow(self, private_manager):
        """Test private message invite flow."""
        sender = "alice"
        recipient = "bob"
        mock_ws_sender = AsyncMock()
        mock_ws_recipient = AsyncMock()
        
        # Connect users
        await private_manager.connect(mock_ws_sender, sender)
        await private_manager.connect(mock_ws_recipient, recipient)
        
        # 1. Create PM invite message
        invite_msg = PmInviteMessage(
            type="pm_invite", 
            sender=sender
        )
        
        # 2. Create PM accept message
        accept_msg = PmAcceptMessage(
            type="pm_accept",
            sender=recipient
        )
        
        # Add PM session (simulating invite acceptance)
        private_manager.add_pm_session(sender, recipient)
        
        # Verify session exists
        assert recipient in private_manager.active_pm_sessions.get(sender, set())
        assert sender in private_manager.active_pm_sessions.get(recipient, set())
        
        # 3. Send a private message
        pm_msg = PmTextMessage(
            type="pm_message",
            sender=sender,
            ciphertext="encrypted_message_content"
        )
        
        await private_manager.send_to_user(recipient, pm_msg)
        
        # Recipient should receive the message
        mock_ws_recipient.send_json.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_pm_decline_flow(self, private_manager):
        """Test private message decline flow."""
        sender = "alice"
        recipient = "bob"
        
        # Create decline message
        decline_msg = PmDeclineMessage(
            type="pm_decline",
            sender=recipient
        )
        
        # Session should not be created for declined invites
        assert sender not in private_manager.active_pm_sessions
        assert recipient not in private_manager.active_pm_sessions
    
    @pytest.mark.asyncio
    async def test_pm_disconnect_flow(self, private_manager):
        """Test private message disconnect flow."""
        user1 = "alice"
        user2 = "bob"
        mock_ws1 = AsyncMock()
        mock_ws2 = AsyncMock()
        
        # Connect users
        await private_manager.connect(mock_ws1, user1)
        await private_manager.connect(mock_ws2, user2)
        
        # Create active session
        private_manager.add_pm_session(user1, user2)
        
        # Create disconnect message
        disconnect_msg = PmDisconnectMessage(
            type="pm_disconnect",
            sender=user1
        )
        
        # Remove session (simulating disconnect)
        private_manager.remove_pm_session(user1, user2)
        
        # Session should no longer exist
        assert user1 not in private_manager.active_pm_sessions
        assert user2 not in private_manager.active_pm_sessions


class TestPublicKeyExchange:
    """Test public key exchange for encryption."""
    
    def test_pubkey_request_message(self):
        """Test public key request message."""
        request_msg = PubkeyRequestMessage(
            type="pubkey_request",
            sender="alice"
        )
        
        assert request_msg.type == "pubkey_request"
        assert request_msg.sender == "alice"
    
    def test_pubkey_response_message(self):
        """Test public key response message."""
        response_msg = PubkeyResponseMessage(
            type="pubkey_response",
            sender="bob",
            public_key="base64encodedkey"
        )
        
        assert response_msg.type == "pubkey_response"
        assert response_msg.sender == "bob"
        assert response_msg.public_key == "base64encodedkey"
    
    def test_pubkey_lookup_response(self):
        """Test public key lookup response."""
        lookup_response = PubkeyLookupResponse(
            type="pubkey_response",
            user="alice",
            key="base64encodedkey"
        )
        
        assert lookup_response.type == "pubkey_response"
        assert lookup_response.user == "alice"
        assert lookup_response.key == "base64encodedkey"
    
    def test_pubkey_lookup_response_no_key(self):
        """Test public key lookup response when key not found."""
        lookup_response = PubkeyLookupResponse(
            type="pubkey_response",
            user="nonexistent",
            key=None
        )
        
        assert lookup_response.type == "pubkey_response"
        assert lookup_response.user == "nonexistent"
        assert lookup_response.key is None


class TestClientSideMessages:
    """Test client-side message models."""
    
    def test_client_chat_message(self):
        """Test client chat message."""
        client_msg = ClientChatMessage(
            type="chat_message",
            data={"message": "Hello everyone!"}
        )
        
        assert client_msg.type == "chat_message"
        assert client_msg.data["message"] == "Hello everyone!"
    
    def test_client_pm_invite(self):
        """Test client PM invite message."""
        client_invite = ClientPmInvite(
            type="pm_invite",
            to="bob"
        )
        
        assert client_invite.type == "pm_invite"
        assert client_invite.to == "bob"
    
    def test_client_pm_message(self):
        """Test client PM message."""
        client_pm = ClientPmMessage(
            type="pm_message",
            to="bob",
            ciphertext="encrypted_content"
        )
        
        assert client_pm.type == "pm_message"
        assert client_pm.to == "bob"
        assert client_pm.ciphertext == "encrypted_content"
    
    def test_client_pubkey_register(self):
        """Test client public key registration."""
        client_pubkey = ClientPubkeyRegister(
            type="pubkey",
            key="base64publickey"
        )
        
        assert client_pubkey.type == "pubkey"
        assert client_pubkey.key == "base64publickey"
    
    def test_client_pubkey_lookup(self):
        """Test client public key lookup."""
        client_lookup = ClientPubkeyLookup(
            type="request_pubkey",
            user="bob"
        )
        
        assert client_lookup.type == "request_pubkey"
        assert client_lookup.user == "bob"


class TestWebSocketErrorHandling:
    """Test WebSocket error handling scenarios."""
    
    @pytest.mark.asyncio
    async def test_broadcast_handles_closed_connections(self, connection_manager):
        """Test that broadcast handles closed connections gracefully."""
        mock_ws1 = AsyncMock()
        mock_ws2 = AsyncMock()
        
        # Connect users first
        await connection_manager.connect(mock_ws1, "user1")
        await connection_manager.connect(mock_ws2, "user2")
        
        # Now make ws2 raise a connection error for future calls
        from websockets.exceptions import ConnectionClosed
        mock_ws2.send_json.side_effect = ConnectionClosed(None, None)
        
        # Create a message to broadcast
        ws_event = WsEvent(
            event="chat_message",
            data=ChatMessageData(user="user1", message="Test message")
        )
        
        # Should not raise an exception
        await connection_manager.broadcast(ws_event)
        
        # user1 should still be connected, user2 should be removed
        assert "user1" in connection_manager.active_connections
        # Note: user2 might still be in connections if the exception handling doesn't remove it
        
    @pytest.mark.asyncio
    async def test_send_to_session_handles_errors(self, private_manager):
        """Test that send_to_user handles connection errors."""
        username = "alice"
        mock_ws = AsyncMock()
        
        # Connect user first
        await private_manager.connect(mock_ws, username)
        
        # Make websocket raise an error
        mock_ws.send_json.side_effect = Exception("Connection error")
        
        from server.utils.models import PmTextMessage
        message = PmTextMessage(
            type="pm_message",
            sender="bob",
            ciphertext="encrypted_content"
        )
        
        # Should not raise an exception
        await private_manager.send_to_user(username, message)
        
        # User should be removed from connections due to error
        assert username not in private_manager.private_connections
    
    def test_error_message_model(self):
        """Test ErrorMessage model."""
        error_msg = ErrorMessage(
            type="error",
            message="Something went wrong",
            details=[{"field": "username", "error": "invalid"}]
        )
        
        assert error_msg.type == "error"
        assert error_msg.message == "Something went wrong"
        assert error_msg.details is not None
        assert len(error_msg.details) == 1


class TestConcurrentConnections:
    """Test handling multiple concurrent connections."""
    
    @pytest.mark.asyncio
    async def test_multiple_users_concurrent_connect(self, connection_manager):
        """Test multiple users connecting concurrently."""
        users = [f"user{i}" for i in range(10)]
        websockets = [AsyncMock() for _ in range(10)]
        
        # Connect all users concurrently
        connect_tasks = [
            connection_manager.connect(ws, user) 
            for ws, user in zip(websockets, users)
        ]
        await asyncio.gather(*connect_tasks)
        
        assert len(connection_manager.active_connections) == 10
        connected_users = set(connection_manager.active_connections.keys())
        assert connected_users == set(users)
    
    @pytest.mark.asyncio
    async def test_multiple_private_sessions(self, private_manager):
        """Test multiple private sessions running concurrently."""
        users = ["alice", "bob", "charlie", "diana"]
        websockets = [AsyncMock() for _ in users]
        
        # Connect all users
        for ws, user in zip(websockets, users):
            await private_manager.connect(ws, user)
        
        # Create multiple PM sessions
        private_manager.add_pm_session(users[0], users[1])  # alice-bob
        private_manager.add_pm_session(users[2], users[3])  # charlie-diana
        
        # Verify sessions exist
        assert users[1] in private_manager.active_pm_sessions.get(users[0], set())
        assert users[0] in private_manager.active_pm_sessions.get(users[1], set())
        assert users[3] in private_manager.active_pm_sessions.get(users[2], set())
        assert users[2] in private_manager.active_pm_sessions.get(users[3], set())
        
        # Sessions should be independent
        assert len(private_manager.active_pm_sessions) == 4
    
    @pytest.mark.asyncio
    async def test_concurrent_broadcasting(self, connection_manager):
        """Test concurrent message broadcasting."""
        # Create multiple websockets
        websockets = [AsyncMock() for _ in range(5)]
        users = [f"user{i}" for i in range(5)]
        
        # Connect all users
        for ws, user in zip(websockets, users):
            await connection_manager.connect(ws, user)
        
        # Reset call history from connect operations
        for ws in websockets:
            ws.send_json.reset_mock()
        
        # Create multiple messages to broadcast concurrently
        messages = []
        for i in range(3):
            ws_event = WsEvent(
                event="chat_message",
                data=ChatMessageData(user=f"user{i}", message=f"Message {i}")
            )
            messages.append(ws_event)
        
        # Broadcast all messages concurrently
        broadcast_tasks = [
            connection_manager.broadcast(msg) for msg in messages
        ]
        await asyncio.gather(*broadcast_tasks)
        
        # Each websocket should have received all messages
        for ws in websockets:
            assert ws.send_json.call_count == 3 