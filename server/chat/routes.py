from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, HTTPException
from jose import jwt, JWTError
from typing import List, Union
import json
from pydantic import ValidationError
from server.chat.manager import ConnectionManager
from server.auth.auth import SECRET_KEY, ALGORITHM
from server.utils.models import (
    WsEvent, ChatMessageData, JoinData, LeaveData, ServerBroadcastData,
    PmInviteMessage, PmAcceptMessage, PmDeclineMessage, PmTextMessage,
    PmDisconnectMessage, PubkeyRequestMessage, PubkeyResponseMessage,
    PubkeyLookupResponse, ErrorMessage,
    # Client message models for validation
    ClientMessage, ClientChatMessage, ClientPmInvite, ClientPmAccept, 
    ClientPmDecline, ClientPmMessage, ClientPmDisconnect, ClientPubkeyRequest,
    ClientPubkeyResponse, ClientPubkeyRegister, ClientPubkeyLookup
)
from server.chat.private_manager import PrivateConnectionManager
from server.chat.bot_user import initialize_bot, get_bot


def validate_client_message(data: dict) -> ClientMessage:
    """Validate incoming WebSocket message against Pydantic models"""
    try:
        # First try to parse the message type
        msg_type = data.get("type")
        if not msg_type:
            raise ValidationError.from_exception_data("ValidationError", [{"type": "missing", "loc": ["type"], "msg": "Field required", "input": data}])
        
        # Map message types to their models for better error messages
        type_to_model = {
            "chat_message": ClientChatMessage,
            "pm_invite": ClientPmInvite,
            "pm_accept": ClientPmAccept,
            "pm_decline": ClientPmDecline,
            "pm_message": ClientPmMessage,
            "pm_disconnect": ClientPmDisconnect,
            "pubkey_request": ClientPubkeyRequest,
            "pubkey_response": ClientPubkeyResponse,
            "pubkey": ClientPubkeyRegister,
            "request_pubkey": ClientPubkeyLookup,
        }
        
        if msg_type not in type_to_model:
            raise ValidationError.from_exception_data("ValidationError", [{"type": "enum", "loc": ["type"], "msg": f"Invalid message type: {msg_type}", "input": msg_type}])
        
        # Validate using the specific model
        model_class = type_to_model[msg_type]
        return model_class.model_validate(data)
        
    except ValidationError:
        raise
    except Exception as e:
        raise ValidationError.from_exception_data("ValidationError", [{"type": "value_error", "loc": [], "msg": f"Message validation failed: {str(e)}", "input": data}])


router = APIRouter()
manager = ConnectionManager()
private_manager = PrivateConnectionManager()


def is_bot_recipient(recipient: str, bot) -> bool:
    """Check if the recipient is the bot user"""
    return bot is not None and recipient == bot.username





@router.post("/chat")
async def send_event(request: WsEvent):
    try:
        await manager.broadcast(request)
        return {"status": "Event sent successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send event: {str(e)}")


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = Query(...)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            await websocket.close(code=1008)
            return
    except JWTError:
        await websocket.close(code=1008)
        return

    await manager.connect(websocket, username)
    await private_manager.connect(websocket, username)
    
    # Initialize bot if not already done and get reference
    bot = get_bot()
    if bot is None:
        await initialize_bot(manager, private_manager)
        bot = get_bot()

    try:
        while True:
            raw_data = await websocket.receive_json()
            
            # Validate the incoming message
            try:
                validated_message = validate_client_message(raw_data)
            except ValidationError as e:
                # Send error back to client and continue
                error_msg = ErrorMessage(
                    message=f"Invalid message format: {e}",
                    details=e.errors()
                )
                await websocket.send_json(error_msg.model_dump(mode='json'))
                continue
            except Exception as e:
                # Send generic error back to client and continue
                error_msg = ErrorMessage(message=f"Message processing error: {str(e)}")
                await websocket.send_json(error_msg.model_dump(mode='json'))
                continue
            
            msg_type = validated_message.type

            if msg_type == "chat_message":
                # Use validated message data and create properly validated WsEvent
                chat_msg = validated_message
                chat_data = ChatMessageData(
                    user=username,
                    message=chat_msg.data["message"]
                )
                ws_event = WsEvent(event="chat_message", data=chat_data)
                await manager.broadcast(ws_event)

            elif msg_type == "pm_invite":
                # Use validated message data
                pm_invite = validated_message
                recipient = pm_invite.to
                
                # Check if the recipient is the bot
                if is_bot_recipient(recipient, bot):
                    # Bot automatically accepts PM invites
                    await bot.handle_pm_invite(username)
                else:
                    # Send invite to regular user
                    invite_msg = PmInviteMessage(sender=username)
                    await private_manager.send_to_user(recipient, invite_msg)

            elif msg_type == "pm_accept":
                # Use validated message data
                pm_accept = validated_message
                recipient = pm_accept.to
                
                # Track the PM session when accepted
                private_manager.add_pm_session(username, recipient)
                
                # Check if the recipient is the bot
                if is_bot_recipient(recipient, bot):
                    # Bot automatically accepts PM invites
                    await bot.handle_pm_invite(username)
                else:
                    accept_msg = PmAcceptMessage(sender=username)
                    await private_manager.send_to_user(recipient, accept_msg)

            elif msg_type == "pm_decline":
                # Use validated message data
                pm_decline = validated_message
                recipient = pm_decline.to
                decline_msg = PmDeclineMessage(sender=username)
                await private_manager.send_to_user(recipient, decline_msg)

            elif msg_type == "pm_message":
                # Use validated message data
                pm_message = validated_message
                recipient = pm_message.to
                ciphertext = pm_message.ciphertext
                
                # Track the PM session when messages are sent (in case accept was missed)
                private_manager.add_pm_session(username, recipient)
                
                # Check if the recipient is the bot
                if is_bot_recipient(recipient, bot):
                    # Bot handles the message and responds
                    await bot.handle_pm_message(username, ciphertext)
                else:
                    # Send message to regular user
                    msg = PmTextMessage(sender=username, ciphertext=ciphertext)
                    await private_manager.send_to_user(recipient, msg)

            elif msg_type == "pm_disconnect":
                # Use validated message data
                pm_disconnect = validated_message
                recipient = pm_disconnect.to
                
                # Remove the PM session when manually disconnected
                private_manager.remove_pm_session(username, recipient)
                
                # Check if the recipient is the bot
                if is_bot_recipient(recipient, bot):
                    # Bot handles disconnect
                    await bot.handle_pm_disconnect(username)
                else:
                    # Send disconnect to regular user
                    disconnect_msg = PmDisconnectMessage(sender=username)
                    await private_manager.send_to_user(recipient, disconnect_msg)

            elif msg_type == "pubkey_request":
                # Use validated message data
                pubkey_request = validated_message
                recipient = pubkey_request.to
                
                # Check if the recipient is the bot
                if is_bot_recipient(recipient, bot):
                    # Bot handles the public key request
                    await bot.handle_pubkey_request(username)
                else:
                    # Send pubkey request to regular user
                    request_msg = PubkeyRequestMessage(sender=username)
                    await private_manager.send_to_user(recipient, request_msg)

            elif msg_type == "pubkey_response":
                # Use validated message data
                pubkey_response = validated_message
                recipient = pubkey_response.to
                public_key = pubkey_response.public_key
                
                # Check if the recipient is the bot
                if is_bot_recipient(recipient, bot):
                    # Bot stores the user's public key
                    await bot.handle_pubkey_response(username, public_key)
                else:
                    # Send pubkey response to regular user
                    response_msg = PubkeyResponseMessage(sender=username, public_key=public_key)
                    await private_manager.send_to_user(recipient, response_msg)

            elif msg_type == "pubkey":
                # Use validated message data
                pubkey_register = validated_message
                private_manager.register_pubkey(username, pubkey_register.key)

            elif msg_type == "request_pubkey":
                # Use validated message data
                pubkey_lookup = validated_message
                target = pubkey_lookup.user
                pubkey = private_manager.get_pubkey(target)
                lookup_response = PubkeyLookupResponse(user=target, key=pubkey)
                await websocket.send_json(lookup_response.model_dump(mode='json'))

            else:
                await manager.send_message("Unknown message type", websocket)

    except WebSocketDisconnect:
        # Notify PM partners before disconnecting
        await private_manager.disconnect_and_notify_partners(username)
        manager.disconnect(username)
        # Broadcast updated user list to all remaining users
        await manager.broadcast_user_list()
    except Exception as e:
        # Handle any other exceptions that might occur
        print(f"WebSocket error for user {username}: {e}")
        # Notify PM partners before disconnecting
        await private_manager.disconnect_and_notify_partners(username)
        manager.disconnect(username)
        # Broadcast updated user list to all remaining users
        await manager.broadcast_user_list()
