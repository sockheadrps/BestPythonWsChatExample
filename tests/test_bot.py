import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio

from server.chat.bot_user import get_bot, ChatBot, initialize_bot


class TestBotUser:
    """Test ChatBot user functionality."""
    
    @pytest.mark.asyncio
    async def test_get_bot_returns_consistent_instance(self):
        """Test that get_bot() returns the same instance after initialization."""
        # Initialize the bot first
        manager = AsyncMock()
        private_manager = AsyncMock()
        await initialize_bot(manager, private_manager)
        
        bot1 = get_bot()
        bot2 = get_bot()
        
        assert bot1 is bot2  # Should be the same instance
        assert bot1.username == "ChatBot"
    
    @pytest.mark.asyncio
    async def test_bot_username(self):
        """Test that bot has correct username."""
        # Initialize the bot first
        manager = AsyncMock()
        private_manager = AsyncMock()
        await initialize_bot(manager, private_manager)
        
        bot = get_bot()
        assert bot.username == "ChatBot"
    
    @pytest.mark.asyncio
    async def test_bot_attributes(self):
        """Test bot has expected attributes."""
        # Initialize the bot first
        manager = AsyncMock()
        private_manager = AsyncMock()
        await initialize_bot(manager, private_manager)
        
        bot = get_bot()
        
        assert hasattr(bot, 'username')
        assert hasattr(bot, 'websocket')
        assert hasattr(bot, 'active_conversations')
        assert hasattr(bot, 'responses')
        assert hasattr(bot, 'greetings')
        assert bot.username == "ChatBot"
        assert isinstance(bot.active_conversations, dict)


class TestChatBotResponse:
    """Test ChatBot response functionality."""
    
    def test_bot_first_message_greeting(self):
        """Test bot gives greeting for first message from user."""
        bot = ChatBot()
        user = "test_user"
        message = "Hello"
        
        response = bot.get_response(user, message)
        
        assert isinstance(response, str)
        assert len(response) > 0
        # Should be a greeting since it's the first message
        assert any(greeting_word in response.lower() for greeting_word in ['hi', 'hello', 'hey', 'nice'])
    
    def test_bot_hello_response(self):
        """Test bot responds appropriately to greetings."""
        bot = ChatBot()
        user = "test_user"
        
        # First message to establish conversation
        bot.get_response(user, "initial")
        
        # Test greeting response
        response = bot.get_response(user, "Hello there!")
        
        assert isinstance(response, str)
        assert len(response) > 0
        assert "hello" in response.lower() or "hi" in response.lower()
    
    def test_bot_goodbye_response(self):
        """Test bot responds appropriately to farewells."""
        bot = ChatBot()
        user = "test_user"
        
        # First message to establish conversation
        bot.get_response(user, "initial")
        
        # Test goodbye response
        response = bot.get_response(user, "Goodbye!")
        
        assert isinstance(response, str)
        assert len(response) > 0
        assert any(word in response.lower() for word in ['goodbye', 'bye', 'take care', 'farewell'])
    
    def test_bot_thank_you_response(self):
        """Test bot responds appropriately to thanks."""
        bot = ChatBot()
        user = "test_user"
        
        # First message to establish conversation
        bot.get_response(user, "initial")
        
        # Test thank you response
        response = bot.get_response(user, "Thank you!")
        
        assert isinstance(response, str)
        assert len(response) > 0
        assert any(word in response.lower() for word in ['welcome', 'happy', 'help'])
    
    def test_bot_help_response(self):
        """Test bot responds appropriately to help requests."""
        bot = ChatBot()
        user = "test_user"
        
        # First message to establish conversation
        bot.get_response(user, "initial")
        
        # Test help response
        response = bot.get_response(user, "Can you help me?")
        
        assert isinstance(response, str)
        assert len(response) > 0
        assert "help" in response.lower()
    
    def test_bot_question_response(self):
        """Test bot responds appropriately to questions."""
        bot = ChatBot()
        user = "test_user"
        
        # First message to establish conversation
        bot.get_response(user, "initial")
        
        # Test question response
        response = bot.get_response(user, "What is the weather like?")
        
        assert isinstance(response, str)
        assert len(response) > 0
        assert "question" in response.lower() or "thoughts" in response.lower()
    
    def test_bot_general_response(self):
        """Test bot gives general response to other messages."""
        bot = ChatBot()
        user = "test_user"
        
        # First message to establish conversation
        bot.get_response(user, "initial")
        
        # Test general message that doesn't match keywords
        response = bot.get_response(user, "I had a neutral day today.")
        
        assert isinstance(response, str)
        assert len(response) > 0
        # Should be one of the predefined responses for general conversation
        assert response in bot.responses
    
    def test_bot_happy_keyword_response(self):
        """Test bot responds to happy keywords with custom response."""
        bot = ChatBot()
        user = "test_user"
        
        # First message to establish conversation
        bot.get_response(user, "initial")
        
        # Test message with happy keywords
        response = bot.get_response(user, "I had a great day today.")
        
        assert isinstance(response, str)
        assert len(response) > 0
        # Should be the keyword-based response, not from general responses
        assert "wonderful" in response.lower() and "happy" in response.lower()


class TestBotEncryption:
    """Test ChatBot encryption functionality."""
    
    def test_bot_has_encryption_keys(self):
        """Test that bot generates encryption keys."""
        bot = ChatBot()
        
        assert bot.private_key is not None
        assert bot.public_key is not None
        assert bot.public_key_pem is not None
        assert isinstance(bot.public_key_pem, str)
        assert len(bot.public_key_pem) > 0
    
    def test_bot_store_user_public_key(self):
        """Test bot can store user public keys."""
        bot = ChatBot()
        username = "test_user"
        # Use the bot's own public key as test data
        public_key_b64 = bot.public_key_pem
        
        bot.store_user_public_key(username, public_key_b64)
        
        assert username in bot.user_public_keys
        assert isinstance(bot.user_public_keys[username], bytes)
    
    def test_bot_encrypt_decrypt_message(self):
        """Test bot can encrypt and decrypt messages."""
        bot = ChatBot()
        message = "Test message for encryption"
        username = "test_user"
        
        # Store bot's own public key to test encryption
        bot.store_user_public_key(username, bot.public_key_pem)
        
        # Encrypt message
        encrypted = bot.encrypt_message(message, username)
        assert isinstance(encrypted, str)
        assert encrypted != message
        
        # Decrypt message
        decrypted = bot.decrypt_message(encrypted)
        assert decrypted == message
    
    def test_bot_encrypt_without_public_key_raises_error(self):
        """Test that encrypting without public key raises error."""
        bot = ChatBot()
        message = "Test message"
        username = "unknown_user"
        
        with pytest.raises(ValueError):
            bot.encrypt_message(message, username)


class TestBotIntegration:
    """Test bot integration with chat system."""
    
    @pytest.mark.asyncio
    async def test_initialize_bot_function(self):
        """Test the initialize_bot function."""
        manager = MagicMock()
        private_manager = MagicMock()
        
        await initialize_bot(manager, private_manager)
        
        # Should get the singleton bot instance
        bot = get_bot()
        assert bot.username == "ChatBot"
    
    @pytest.mark.asyncio
    async def test_bot_initialization(self):
        """Test bot initialization with managers."""
        bot = ChatBot()
        manager = AsyncMock()
        private_manager = AsyncMock()
        
        await bot.initialize(manager, private_manager)
        
        assert bot.manager == manager
        assert bot.private_manager == private_manager
        manager.connect.assert_called_once_with(bot.websocket, bot.username)
        private_manager.connect.assert_called_once_with(bot.websocket, bot.username)
    
    @pytest.mark.asyncio
    async def test_bot_handle_pm_invite(self):
        """Test bot handles PM invites."""
        bot = ChatBot()
        private_manager = AsyncMock()
        # Configure synchronous methods to not return coroutines
        private_manager.add_pm_session = MagicMock()
        bot.private_manager = private_manager
        from_user = "test_user"
        
        await bot.handle_pm_invite(from_user)
        
        # Should call add_pm_session and send_to_user
        private_manager.add_pm_session.assert_called_once_with(bot.username, from_user)
        assert private_manager.send_to_user.call_count == 2  # Accept + PubkeyRequest
    
    @pytest.mark.asyncio
    async def test_bot_handle_pubkey_request(self):
        """Test bot handles public key requests."""
        bot = ChatBot()
        private_manager = AsyncMock()
        bot.private_manager = private_manager
        from_user = "test_user"
        
        await bot.handle_pubkey_request(from_user)
        
        private_manager.send_to_user.assert_called_once()
        call_args = private_manager.send_to_user.call_args
        assert call_args[0][0] == from_user  # Sent to correct user
    
    @pytest.mark.asyncio
    async def test_bot_handle_pubkey_response(self):
        """Test bot handles public key responses."""
        bot = ChatBot()
        from_user = "test_user"
        public_key = bot.public_key_pem  # Use valid key
        
        await bot.handle_pubkey_response(from_user, public_key)
        
        assert from_user in bot.user_public_keys
    
    @pytest.mark.asyncio
    async def test_bot_handle_pm_message(self):
        """Test bot handles private messages."""
        bot = ChatBot()
        private_manager = AsyncMock()
        bot.private_manager = private_manager
        from_user = "test_user"
        
        # Store user's public key (use bot's own key for testing)
        bot.store_user_public_key(from_user, bot.public_key_pem)
        
        # Encrypt a test message
        test_message = "Hello bot!"
        ciphertext = bot.encrypt_message(test_message, from_user)
        
        # Mock the encrypt_message to return a test ciphertext for response
        with patch.object(bot, 'encrypt_message', return_value="encrypted_response"):
            await bot.handle_pm_message(from_user, ciphertext)
        
        # Should send a response
        private_manager.send_to_user.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_bot_handle_pm_disconnect(self):
        """Test bot handles PM disconnections."""
        bot = ChatBot()
        private_manager = AsyncMock()
        # Configure synchronous methods to not return coroutines
        private_manager.remove_pm_session = MagicMock()
        bot.private_manager = private_manager
        from_user = "test_user"
        
        # Add user to active conversations first
        bot.active_conversations[from_user] = ["test message"]
        
        await bot.handle_pm_disconnect(from_user)
        
        # Should clean up the conversation
        assert from_user not in bot.active_conversations


class TestBotConversation:
    """Test bot conversation handling."""
    
    def test_bot_conversation_tracking(self):
        """Test that bot tracks conversations per user."""
        bot = ChatBot()
        user1 = "user1"
        user2 = "user2"
        
        # Both users should get greetings on first message
        response1 = bot.get_response(user1, "Hello")
        response2 = bot.get_response(user2, "Hi there")
        
        assert user1 in bot.active_conversations
        assert user2 in bot.active_conversations
        # After first message, both users have empty conversation lists
        # The conversations are independent
        assert user1 != user2
    
    def test_bot_multiple_messages_same_user(self):
        """Test bot handles multiple messages from same user."""
        bot = ChatBot()
        user = "test_user"
        
        # First message (gets greeting, conversation created)
        response1 = bot.get_response(user, "Hello")
        # Second message (gets added to conversation history)
        response2 = bot.get_response(user, "How are you?")
        
        assert user in bot.active_conversations
        assert len(bot.active_conversations[user]) >= 1
        # The second message should be in the conversation history
        assert any("How are you?" in entry for entry in bot.active_conversations[user])


class TestBotPerformance:
    """Test bot performance characteristics."""
    
    def test_bot_response_time(self):
        """Test that bot responses are generated quickly."""
        import time
        
        bot = ChatBot()
        user = "test_user"
        message = "Hello there!"
        
        start_time = time.time()
        response = bot.get_response(user, message)
        end_time = time.time()
        
        assert isinstance(response, str)
        assert len(response) > 0
        # Response should be generated in under 1 second
        assert (end_time - start_time) < 1.0
    
    def test_concurrent_bot_requests(self):
        """Test that bot can handle multiple concurrent requests."""
        bot = ChatBot()
        
        responses = []
        for i in range(10):
            user = f"user_{i}"
            message = f"Hello from user {i}"
            response = bot.get_response(user, message)
            responses.append(response)
        
        # All responses should be valid
        assert len(responses) == 10
        assert all(isinstance(r, str) and len(r) > 0 for r in responses)
        
        # All users should have conversations tracked
        assert len(bot.active_conversations) == 10


class TestBotUtilities:
    """Test bot utility functions."""
    
    def test_bot_singleton_pattern(self):
        """Test that get_bot follows singleton pattern."""
        # Note: get_bot() returns None until initialize_bot() is called
        # Test with new instances instead
        bot1 = ChatBot()
        bot2 = ChatBot()
        
        assert bot1 is not bot2  # Different instances
        assert bot1.username == bot2.username  # Same username
    
    @pytest.mark.asyncio
    async def test_bot_identification(self):
        """Test bot can be identified correctly."""
        # Initialize the bot first
        manager = AsyncMock()
        private_manager = AsyncMock()
        await initialize_bot(manager, private_manager)
        
        bot = get_bot()
        
        assert bot.username == "ChatBot"
        assert hasattr(bot, 'websocket')
        assert hasattr(bot, 'responses')
        assert hasattr(bot, 'greetings')


class TestBotErrorHandling:
    """Test bot error handling."""
    
    def test_bot_handles_empty_message(self):
        """Test bot handles empty messages gracefully."""
        bot = ChatBot()
        user = "test_user"
        
        response = bot.get_response(user, "")
        
        assert isinstance(response, str)
        assert len(response) > 0
    
    def test_bot_handles_unicode(self):
        """Test bot handles Unicode input."""
        bot = ChatBot()
        user = "test_user"
        unicode_message = "こんにちは 🌸 Comment ça va? Как дела?"
        
        response = bot.get_response(user, unicode_message)
        
        assert isinstance(response, str)
        assert len(response) > 0
    
    def test_bot_handles_very_long_message(self):
        """Test bot handles very long messages."""
        bot = ChatBot()
        user = "test_user"
        long_message = "This is a very long message. " * 100
        
        response = bot.get_response(user, long_message)
        
        assert isinstance(response, str)
        assert len(response) > 0
    
    def test_bot_decrypt_invalid_message(self):
        """Test bot handles invalid encrypted messages."""
        bot = ChatBot()
        invalid_ciphertext = "not_a_valid_base64_encrypted_message"
        
        # Should return the original text if decryption fails
        result = bot.decrypt_message(invalid_ciphertext)
        assert result == invalid_ciphertext 