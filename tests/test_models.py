import pytest
from pydantic import ValidationError
from datetime import datetime

from server.utils.models import (
    # Data models
    ChatMessageData, JoinData, LeaveData, ServerBroadcastData,
    
    # Server-side PM models
    PmInviteMessage, PmAcceptMessage, PmDeclineMessage, PmTextMessage,
    PmDisconnectMessage, PubkeyRequestMessage, PubkeyResponseMessage,
    
    # System messages
    UserListMessage, PubkeyLookupResponse, ErrorMessage,
    
    # Client-side models
    ClientChatMessage, ClientPmInvite, ClientPmAccept, ClientPmDecline,
    ClientPmMessage, ClientPmDisconnect, ClientPubkeyRequest,
    ClientPubkeyResponse, ClientPubkeyRegister, ClientPubkeyLookup,
    
    # Event model
    WsEvent,
    
    # Union types
    PrivateMessage, ClientMessage
)


class TestDataModels:
    """Test basic data models for chat events."""
    
    def test_chat_message_data_valid(self):
        """Test valid ChatMessageData model."""
        data = {
            "user": "testuser",
            "message": "Hello, world!"
        }
        
        chat_data = ChatMessageData(**data)
        
        assert chat_data.user == "testuser"
        assert chat_data.message == "Hello, world!"
        assert isinstance(chat_data.timestamp, datetime)
    
    def test_chat_message_data_empty_message(self):
        """Test ChatMessageData with empty message."""
        data = {
            "user": "testuser",
            "message": ""
        }
        
        # Empty message should be allowed
        chat_data = ChatMessageData(**data)
        assert chat_data.message == ""
    
    def test_join_data_valid(self):
        """Test valid JoinData model."""
        data = {"user": "testuser"}
        
        join_data = JoinData(**data)
        
        assert join_data.user == "testuser"
    
    def test_leave_data_valid(self):
        """Test valid LeaveData model."""
        data = {"user": "testuser"}
        
        leave_data = LeaveData(**data)
        
        assert leave_data.user == "testuser"
    
    def test_server_broadcast_data_valid(self):
        """Test valid ServerBroadcastData model."""
        data = {"message": "Server is restarting in 5 minutes"}
        
        broadcast_data = ServerBroadcastData(**data)
        
        assert broadcast_data.message == "Server is restarting in 5 minutes"


class TestServerSidePrivateMessageModels:
    """Test server-side private message models."""
    
    def test_pm_invite_message_valid(self):
        """Test valid PmInviteMessage model."""
        data = {
            "type": "pm_invite",
            "from": "alice"
        }
        
        message = PmInviteMessage(**data)
        
        assert message.type == "pm_invite"
        assert message.sender == "alice"
    
    def test_pm_invite_message_alias(self):
        """Test PmInviteMessage with sender alias."""
        data = {
            "type": "pm_invite",
            "sender": "alice"
        }
        
        message = PmInviteMessage(**data)
        
        assert message.type == "pm_invite"
        assert message.sender == "alice"
    
    def test_pm_accept_message_valid(self):
        """Test valid PmAcceptMessage model."""
        data = {
            "type": "pm_accept",
            "from": "bob"
        }
        
        message = PmAcceptMessage(**data)
        
        assert message.type == "pm_accept"
        assert message.sender == "bob"
    
    def test_pm_decline_message_valid(self):
        """Test valid PmDeclineMessage model."""
        data = {
            "type": "pm_decline",
            "from": "bob"
        }
        
        message = PmDeclineMessage(**data)
        
        assert message.type == "pm_decline"
        assert message.sender == "bob"
    
    def test_pm_text_message_valid(self):
        """Test valid PmTextMessage model."""
        data = {
            "type": "pm_message",
            "from": "alice",
            "ciphertext": "encrypted_message_content"
        }
        
        message = PmTextMessage(**data)
        
        assert message.type == "pm_message"
        assert message.sender == "alice"
        assert message.ciphertext == "encrypted_message_content"
    
    def test_pm_disconnect_message_valid(self):
        """Test valid PmDisconnectMessage model."""
        data = {
            "type": "pm_disconnect",
            "from": "alice"
        }
        
        message = PmDisconnectMessage(**data)
        
        assert message.type == "pm_disconnect"
        assert message.sender == "alice"
    
    def test_pubkey_request_message_valid(self):
        """Test valid PubkeyRequestMessage model."""
        data = {
            "type": "pubkey_request",
            "from": "alice"
        }
        
        message = PubkeyRequestMessage(**data)
        
        assert message.type == "pubkey_request"
        assert message.sender == "alice"
    
    def test_pubkey_response_message_valid(self):
        """Test valid PubkeyResponseMessage model."""
        data = {
            "type": "pubkey_response",
            "from": "bob",
            "public_key": "base64encodedkey"
        }
        
        message = PubkeyResponseMessage(**data)
        
        assert message.type == "pubkey_response"
        assert message.sender == "bob"
        assert message.public_key == "base64encodedkey"


class TestSystemMessages:
    """Test system message models."""
    
    def test_user_list_message_valid(self):
        """Test valid UserListMessage model."""
        data = {
            "type": "user_list",
            "users": ["alice", "bob", "charlie"]
        }
        
        message = UserListMessage(**data)
        
        assert message.type == "user_list"
        assert len(message.users) == 3
        assert "alice" in message.users
        assert "bob" in message.users
        assert "charlie" in message.users
    
    def test_user_list_message_empty(self):
        """Test UserListMessage with empty user list."""
        data = {
            "type": "user_list",
            "users": []
        }
        
        message = UserListMessage(**data)
        
        assert message.type == "user_list"
        assert len(message.users) == 0
    
    def test_pubkey_lookup_response_valid(self):
        """Test valid PubkeyLookupResponse model."""
        data = {
            "type": "pubkey_response",
            "user": "alice",
            "key": "base64encodedkey"
        }
        
        response = PubkeyLookupResponse(**data)
        
        assert response.type == "pubkey_response"
        assert response.user == "alice"
        assert response.key == "base64encodedkey"
    
    def test_pubkey_lookup_response_no_key(self):
        """Test PubkeyLookupResponse with no key found."""
        data = {
            "type": "pubkey_response",
            "user": "nonexistent",
            "key": None
        }
        
        response = PubkeyLookupResponse(**data)
        
        assert response.type == "pubkey_response"
        assert response.user == "nonexistent"
        assert response.key is None
    
    def test_error_message_valid(self):
        """Test valid ErrorMessage model."""
        data = {
            "type": "error",
            "message": "Something went wrong"
        }
        
        error = ErrorMessage(**data)
        
        assert error.type == "error"
        assert error.message == "Something went wrong"
        assert error.details is None
    
    def test_error_message_with_details(self):
        """Test ErrorMessage with details."""
        data = {
            "type": "error",
            "message": "Validation failed",
            "details": [{"field": "username", "error": "too short"}]
        }
        
        error = ErrorMessage(**data)
        
        assert error.type == "error"
        assert error.message == "Validation failed"
        assert error.details is not None
        assert len(error.details) == 1


class TestClientSideModels:
    """Test client-side WebSocket message models."""
    
    def test_client_chat_message_valid(self):
        """Test valid ClientChatMessage model."""
        data = {
            "type": "chat_message",
            "data": {"message": "Hello everyone!"}
        }
        
        message = ClientChatMessage(**data)
        
        assert message.type == "chat_message"
        assert message.data["message"] == "Hello everyone!"
    
    def test_client_chat_message_invalid_data(self):
        """Test ClientChatMessage with invalid data."""
        data = {
            "type": "chat_message",
            "data": {"no_message_field": "value"}
        }
        
        with pytest.raises(ValidationError):
            ClientChatMessage(**data)
    
    def test_client_pm_invite_valid(self):
        """Test valid ClientPmInvite model."""
        data = {
            "type": "pm_invite",
            "to": "bob"
        }
        
        message = ClientPmInvite(**data)
        
        assert message.type == "pm_invite"
        assert message.to == "bob"
    
    def test_client_pm_accept_valid(self):
        """Test valid ClientPmAccept model."""
        data = {
            "type": "pm_accept",
            "to": "alice"
        }
        
        message = ClientPmAccept(**data)
        
        assert message.type == "pm_accept"
        assert message.to == "alice"
    
    def test_client_pm_decline_valid(self):
        """Test valid ClientPmDecline model."""
        data = {
            "type": "pm_decline",
            "to": "alice"
        }
        
        message = ClientPmDecline(**data)
        
        assert message.type == "pm_decline"
        assert message.to == "alice"
    
    def test_client_pm_message_valid(self):
        """Test valid ClientPmMessage model."""
        data = {
            "type": "pm_message",
            "to": "bob",
            "ciphertext": "encrypted_content"
        }
        
        message = ClientPmMessage(**data)
        
        assert message.type == "pm_message"
        assert message.to == "bob"
        assert message.ciphertext == "encrypted_content"
    
    def test_client_pm_disconnect_valid(self):
        """Test valid ClientPmDisconnect model."""
        data = {
            "type": "pm_disconnect",
            "to": "bob"
        }
        
        message = ClientPmDisconnect(**data)
        
        assert message.type == "pm_disconnect"
        assert message.to == "bob"
    
    def test_client_pubkey_request_valid(self):
        """Test valid ClientPubkeyRequest model."""
        data = {
            "type": "pubkey_request",
            "to": "bob"
        }
        
        message = ClientPubkeyRequest(**data)
        
        assert message.type == "pubkey_request"
        assert message.to == "bob"
    
    def test_client_pubkey_response_valid(self):
        """Test valid ClientPubkeyResponse model."""
        data = {
            "type": "pubkey_response",
            "to": "alice",
            "public_key": "base64key"
        }
        
        message = ClientPubkeyResponse(**data)
        
        assert message.type == "pubkey_response"
        assert message.to == "alice"
        assert message.public_key == "base64key"
    
    def test_client_pubkey_register_valid(self):
        """Test valid ClientPubkeyRegister model."""
        data = {
            "type": "pubkey",
            "key": "base64publickey"
        }
        
        message = ClientPubkeyRegister(**data)
        
        assert message.type == "pubkey"
        assert message.key == "base64publickey"
    
    def test_client_pubkey_lookup_valid(self):
        """Test valid ClientPubkeyLookup model."""
        data = {
            "type": "request_pubkey",
            "user": "bob"
        }
        
        message = ClientPubkeyLookup(**data)
        
        assert message.type == "request_pubkey"
        assert message.user == "bob"


class TestWsEventModel:
    """Test WebSocket event model."""
    
    def test_ws_event_chat_message(self):
        """Test WsEvent with chat message."""
        data = {
            "event": "chat_message",
            "data": {
                "user": "alice",
                "message": "Hello everyone!"
            }
        }
        
        event = WsEvent(**data)
        
        assert event.event == "chat_message"
        assert isinstance(event.data, ChatMessageData)
        assert event.data.user == "alice"
        assert event.data.message == "Hello everyone!"
    
    def test_ws_event_user_join(self):
        """Test WsEvent with user join."""
        data = {
            "event": "user_join",
            "data": {"user": "bob"}
        }
        
        event = WsEvent(**data)
        
        assert event.event == "user_join"
        assert isinstance(event.data, JoinData)
        assert event.data.user == "bob"
    
    def test_ws_event_user_leave(self):
        """Test WsEvent with user leave."""
        data = {
            "event": "user_leave",
            "data": {"user": "charlie"}
        }
        
        event = WsEvent(**data)
        
        assert event.event == "user_leave"
        assert isinstance(event.data, LeaveData)
        assert event.data.user == "charlie"
    
    def test_ws_event_server_broadcast(self):
        """Test WsEvent with server broadcast."""
        data = {
            "event": "server_broadcast",
            "data": {"message": "Server maintenance in 10 minutes"}
        }
        
        event = WsEvent(**data)
        
        assert event.event == "server_broadcast"
        assert isinstance(event.data, ServerBroadcastData)
        assert event.data.message == "Server maintenance in 10 minutes"
    
    def test_ws_event_invalid_event_type(self):
        """Test WsEvent with invalid event type."""
        data = {
            "event": "invalid_event",
            "data": {"user": "test"}
        }
        
        with pytest.raises(ValidationError):
            WsEvent(**data)
    
    def test_ws_event_mismatched_data(self):
        """Test WsEvent with mismatched event and data."""
        data = {
            "event": "chat_message",
            "data": {"user": "test"}  # Missing required 'message' field
        }
        
        with pytest.raises(ValidationError):
            WsEvent(**data)


class TestUnionTypes:
    """Test union type models."""
    
    def test_private_message_union_pm_invite(self):
        """Test PrivateMessage union with PmInviteMessage."""
        data = {
            "type": "pm_invite",
            "from": "alice"
        }
        
        # Should be able to create any of the PM message types
        message = PmInviteMessage(**data)
        assert message.type == "pm_invite"
        assert message.sender == "alice"
    
    def test_private_message_union_pm_text(self):
        """Test PrivateMessage union with PmTextMessage."""
        data = {
            "type": "pm_message",
            "from": "alice",
            "ciphertext": "encrypted"
        }
        
        message = PmTextMessage(**data)
        assert message.type == "pm_message"
        assert message.sender == "alice"
        assert message.ciphertext == "encrypted"
    
    def test_client_message_union_chat(self):
        """Test ClientMessage union with ClientChatMessage."""
        data = {
            "type": "chat_message",
            "data": {"message": "Hello!"}
        }
        
        message = ClientChatMessage(**data)
        assert message.type == "chat_message"
        assert message.data["message"] == "Hello!"
    
    def test_client_message_union_pm_invite(self):
        """Test ClientMessage union with ClientPmInvite."""
        data = {
            "type": "pm_invite",
            "to": "bob"
        }
        
        message = ClientPmInvite(**data)
        assert message.type == "pm_invite"
        assert message.to == "bob"


class TestModelSerialization:
    """Test model serialization and deserialization."""
    
    def test_model_to_dict(self):
        """Test converting model to dictionary."""
        data = {
            "user": "testuser",
            "message": "Hello!"
        }
        
        message = ChatMessageData(**data)
        result_dict = message.model_dump()
        
        assert result_dict["user"] == "testuser"
        assert result_dict["message"] == "Hello!"
        assert "timestamp" in result_dict
    
    def test_model_to_json(self):
        """Test converting model to JSON."""
        data = {
            "type": "pm_invite",
            "from": "alice"
        }
        
        message = PmInviteMessage(**data)
        json_str = message.model_dump_json()
        
        assert "pm_invite" in json_str
        assert "alice" in json_str
    
    def test_model_from_json(self):
        """Test creating model from JSON."""
        json_data = '{"type": "user_list", "users": ["alice", "bob"]}'
        
        message = UserListMessage.model_validate_json(json_data)
        
        assert message.type == "user_list"
        assert len(message.users) == 2
        assert "alice" in message.users
        assert "bob" in message.users


class TestModelEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_empty_user_list(self):
        """Test empty user list."""
        data = {
            "type": "user_list",
            "users": []
        }
        
        message = UserListMessage(**data)
        assert len(message.users) == 0
    
    def test_long_message_content(self):
        """Test very long message content."""
        long_message = "A" * 10000
        
        data = {
            "user": "testuser",
            "message": long_message
        }
        
        chat_data = ChatMessageData(**data)
        assert chat_data.message == long_message
    
    def test_unicode_content(self):
        """Test Unicode content in messages."""
        unicode_message = "Hello! 👋 This has émojis and ünïcöde 🚀"
        
        data = {
            "user": "testuser",
            "message": unicode_message
        }
        
        chat_data = ChatMessageData(**data)
        assert chat_data.message == unicode_message
    
    def test_type_literal_validation(self):
        """Test that Literal types are strictly enforced."""
        # Valid type
        data = {
            "type": "pm_invite",
            "from": "alice"
        }
        message = PmInviteMessage(**data)
        assert message.type == "pm_invite"
        
        # Invalid type should fail during validation
        invalid_data = {
            "type": "invalid_type",
            "from": "alice"
        }
        
        with pytest.raises(ValidationError):
            PmInviteMessage(**invalid_data) 