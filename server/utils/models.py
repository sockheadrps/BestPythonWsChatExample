from pydantic import BaseModel, Field, model_validator
from typing import Literal, Union, List, Optional
from datetime import datetime

class ChatMessageData(BaseModel):
    user: str = Field(..., title="Username of the sender")
    message: str = Field(..., title="Text of the chat message")
    timestamp: datetime = Field(default_factory=datetime.utcnow, title="UTC timestamp of when the message was sent")


class JoinData(BaseModel):
    user: str = Field(..., title="Username of the user joining")


class LeaveData(BaseModel):
    user: str = Field(..., title="Username of the user leaving")


class ServerBroadcastData(BaseModel):
    message: str = Field(..., title="System-wide broadcast message (server-generated)")


# Private Message Models
class PmInviteMessage(BaseModel):
    model_config = {"populate_by_name": True}
    
    type: Literal["pm_invite"] = "pm_invite"
    sender: str = Field(..., alias="from", title="Username of the sender")


class PmAcceptMessage(BaseModel):
    model_config = {"populate_by_name": True}
    
    type: Literal["pm_accept"] = "pm_accept"
    sender: str = Field(..., alias="from", title="Username of the sender")


class PmDeclineMessage(BaseModel):
    model_config = {"populate_by_name": True}
    
    type: Literal["pm_decline"] = "pm_decline"
    sender: str = Field(..., alias="from", title="Username of the sender")


class PmTextMessage(BaseModel):
    model_config = {"populate_by_name": True}
    
    type: Literal["pm_message"] = "pm_message"
    sender: str = Field(..., alias="from", title="Username of the sender")
    ciphertext: str = Field(..., title="Encrypted message content")


class PmDisconnectMessage(BaseModel):
    model_config = {"populate_by_name": True}
    
    type: Literal["pm_disconnect"] = "pm_disconnect"
    sender: str = Field(..., alias="from", title="Username of the sender")


class PubkeyRequestMessage(BaseModel):
    model_config = {"populate_by_name": True}
    
    type: Literal["pubkey_request"] = "pubkey_request"
    sender: str = Field(..., alias="from", title="Username requesting the public key")


class PubkeyResponseMessage(BaseModel):
    model_config = {"populate_by_name": True}
    
    type: Literal["pubkey_response"] = "pubkey_response"
    sender: str = Field(..., alias="from", title="Username sending the public key")
    public_key: str = Field(..., title="Base64 encoded public key")


# System Messages
class UserListMessage(BaseModel):
    type: Literal["user_list"] = "user_list"
    users: List[str] = Field(..., title="List of online usernames")


class PubkeyLookupResponse(BaseModel):
    type: Literal["pubkey_response"] = "pubkey_response"
    user: str = Field(..., title="Username whose public key is being returned")
    key: Optional[str] = Field(None, title="Base64 encoded public key (null if not found)")


class ErrorMessage(BaseModel):
    type: Literal["error"] = "error"
    message: str = Field(..., title="Error description")
    details: Optional[List[dict]] = Field(None, title="Detailed error information")


# Client-side WebSocket message models (what clients send)
class ClientChatMessage(BaseModel):
    type: Literal["chat_message"] = "chat_message"
    data: dict = Field(..., title="Chat message data")

    @model_validator(mode="after")
    def validate_data(self):
        # Validate that data contains required message field
        if not isinstance(self.data, dict) or "message" not in self.data:
            raise ValueError("data must contain 'message' field")
        if not isinstance(self.data["message"], str):
            raise ValueError("message must be a string")
        return self


class ClientPmInvite(BaseModel):
    type: Literal["pm_invite"] = "pm_invite" 
    to: str = Field(..., title="Recipient username")


class ClientPmAccept(BaseModel):
    type: Literal["pm_accept"] = "pm_accept"
    to: str = Field(..., title="Recipient username")


class ClientPmDecline(BaseModel):
    type: Literal["pm_decline"] = "pm_decline"
    to: str = Field(..., title="Recipient username")


class ClientPmMessage(BaseModel):
    type: Literal["pm_message"] = "pm_message"
    to: str = Field(..., title="Recipient username")
    ciphertext: str = Field(..., title="Encrypted message content")


class ClientPmDisconnect(BaseModel):
    type: Literal["pm_disconnect"] = "pm_disconnect" 
    to: str = Field(..., title="Recipient username")


class ClientPubkeyRequest(BaseModel):
    type: Literal["pubkey_request"] = "pubkey_request"
    to: str = Field(..., title="Recipient username")


class ClientPubkeyResponse(BaseModel):
    type: Literal["pubkey_response"] = "pubkey_response"
    to: str = Field(..., title="Recipient username")
    public_key: str = Field(..., title="Base64 encoded public key")


class ClientPubkeyRegister(BaseModel):
    type: Literal["pubkey"] = "pubkey"
    key: str = Field(..., title="Base64 encoded public key")


class ClientPubkeyLookup(BaseModel):
    type: Literal["request_pubkey"] = "request_pubkey"
    user: str = Field(..., title="Username to lookup public key for")


# Union of all server-side private message types (what server sends)
PrivateMessage = Union[
    PmInviteMessage,
    PmAcceptMessage, 
    PmDeclineMessage,
    PmTextMessage,
    PmDisconnectMessage,
    PubkeyRequestMessage,
    PubkeyResponseMessage
]


# Union of all client-side WebSocket message types (what clients send)
ClientMessage = Union[
    ClientChatMessage,
    ClientPmInvite,
    ClientPmAccept,
    ClientPmDecline,
    ClientPmMessage,
    ClientPmDisconnect,
    ClientPubkeyRequest,
    ClientPubkeyResponse,
    ClientPubkeyRegister,
    ClientPubkeyLookup
]


class WsEvent(BaseModel):
    event: Literal["chat_message", "user_join", "user_leave", "server_broadcast"]
    data: Union[ChatMessageData, JoinData, LeaveData, ServerBroadcastData]

    @model_validator(mode="before")
    @classmethod
    def validate_event_type(cls, values):
        event = values.get("event")
        data = values.get("data")

        expected_data_types = {
            "chat_message": ChatMessageData,
            "user_join": JoinData,
            "user_leave": LeaveData,
            "server_broadcast": ServerBroadcastData,
        }

        if event not in expected_data_types:
            raise ValueError(f"Invalid event: {event}. Allowed: {list(expected_data_types.keys())}")

        expected_type = expected_data_types[event]
        try:
            values["data"] = expected_type.model_validate(data)  # <-- cast and assign!
        except Exception as e:
            raise ValueError(f"Data validation failed for event '{event}': {e}")

        return values

