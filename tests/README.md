# FastAPI Chat Application Test Suite

This directory contains comprehensive tests for the FastAPI WebSocket chat application with end-to-end encryption.

## Test Coverage Overview

The test suite provides **280+ tests** across 7 test files, covering all major components:

### 1. Authentication Tests (`test_auth.py`) - 92 tests

- **Password Security**: bcrypt hashing, verification, salt uniqueness
- **User Management**: Registration, authentication, duplicate handling
- **JWT Tokens**: Creation, validation, expiration, signature verification
- **Security**: SQL injection protection, timing attack resistance, concurrent access
- **OAuth2 Integration**: FastAPI OAuth2PasswordRequestForm compatibility

### 2. Database Tests (`test_database.py`) - 42 tests

- **User Model**: CRUD operations, constraints, validation
- **PublicKeyStorage Model**: Key storage, retrieval, user relationships
- **Transactions**: Rollback behavior, concurrent operations
- **Performance**: Bulk operations, query optimization
- **Schema**: Migration compatibility, constraint enforcement

### 3. Model Validation Tests (`test_models.py`) - 45 tests

- **Data Models**: `ChatMessageData`, `JoinData`, `LeaveData`, `ServerBroadcastData`
- **Server-side PM Models**: `PmInviteMessage`, `PmAcceptMessage`, `PmDeclineMessage`, `PmTextMessage`, `PmDisconnectMessage`
- **Public Key Models**: `PubkeyRequestMessage`, `PubkeyResponseMessage`, `PubkeyLookupResponse`
- **Client-side Models**: `ClientChatMessage`, `ClientPmInvite`, `ClientPmAccept`, etc.
- **System Messages**: `UserListMessage`, `ErrorMessage`
- **Event Model**: `WsEvent` with data validation
- **Union Types**: `PrivateMessage`, `ClientMessage` validation
- **Serialization**: JSON conversion, Unicode handling

### 4. Encryption Tests (`test_encryption.py`) - 28 tests

- **RSA Key Generation**: 2048-bit keys, format validation
- **Encryption/Decryption**: RSA-OAEP with SHA-256, base64 encoding
- **Security**: Key tampering detection, padding validation
- **Performance**: Large message handling, concurrent operations
- **Integration**: End-to-end encryption workflow simulation

### 5. WebSocket Tests (`test_websockets.py`) - 38 tests

- **ConnectionManager**: User connect/disconnect, broadcasting, error handling
- **PrivateConnectionManager**: PM sessions, WebSocket management
- **Message Flow**: Chat messages, PM invites/accepts/declines
- **Public Key Exchange**: Request/response handling
- **Error Resilience**: Broken connections, concurrent operations
- **Client/Server Models**: Message type validation

### 6. Bot Tests (`test_bot.py`) - 35 tests

- **AI Responses**: Conversation handling, greeting logic
- **Bot Management**: Singleton pattern, initialization
- **PM Integration**: Auto-accept invites, encrypted messaging
- **Public Key Exchange**: Automatic key sharing
- **Error Handling**: Malformed input, connection issues
- **Concurrent Requests**: Multiple simultaneous conversations

### 7. Integration Tests (distributed across files)

- **Full Authentication Flow**: Registration → Login → Token → User retrieval
- **Complete PM Flow**: Invite → Accept → Encrypted messaging → Disconnect
- **Public Key Workflow**: Registration → Lookup → Exchange → Encryption
- **WebSocket Lifecycle**: Connect → Message → Broadcast → Disconnect

## Key Testing Features

### Async Testing with pytest-asyncio

```python
@pytest.mark.asyncio
async def test_websocket_functionality():
    # Tests WebSocket connections and bot interactions
```

### Database Isolation

- Fresh SQLite in-memory database per test
- Automatic rollback after each test
- No cross-test contamination

### Comprehensive Mocking

```python
class MockWebSocket:
    async def send_json(self, data): pass
    async def receive_json(self): pass
```

### Security-First Testing

- **Encryption validation**: RSA-OAEP, base64 encoding
- **Authentication security**: bcrypt, JWT, timing attacks
- **Input validation**: SQL injection, XSS prevention
- **Error handling**: Graceful failure, no information leakage

### Performance Testing

- **Concurrent connections**: Multiple simultaneous users
- **Bulk operations**: Database performance under load
- **Memory usage**: Large message handling
- **Response times**: Bot interaction latency

## Running Tests

### Run All Tests

```bash
pytest
```

### Run Specific Test Categories

```bash
# Authentication tests
pytest tests/test_auth.py

# WebSocket functionality
pytest tests/test_websockets.py

# Database operations
pytest tests/test_database.py

# Model validation
pytest tests/test_models.py

# Encryption/security
pytest tests/test_encryption.py

# Bot functionality
pytest tests/test_bot.py
```

### Run with Coverage

```bash
pytest --cov=server --cov-report=html
```

### Run with Verbose Output

```bash
pytest -v
```

### Run Parallel Tests

```bash
pytest -n auto  # Requires pytest-xdist
```

## Test Configuration

### pytest.ini

```ini
[tool:pytest]
minversion = 6.0
addopts = -ra -q --strict-markers
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
asyncio_mode = auto
```

### Fixtures (`conftest.py`)

- **Database fixtures**: `test_db`, `sample_user`
- **WebSocket mocks**: `mock_websocket`, `connection_manager`, `private_manager`
- **Encryption fixtures**: `rsa_key_pair`, `encrypted_message_pair`
- **Authentication helpers**: `auth_headers`, `sample_user_data`

## Model Architecture Tested

### Current Pydantic Models

The tests validate the actual models in the codebase:

**Data Models:**

- `ChatMessageData` - Chat message with user, message, timestamp
- `JoinData` - User join events
- `LeaveData` - User leave events
- `ServerBroadcastData` - System announcements

**Server-side Private Message Models:**

- `PmInviteMessage` - PM invitation from sender
- `PmAcceptMessage` - PM acceptance response
- `PmDeclineMessage` - PM decline response
- `PmTextMessage` - Encrypted PM content
- `PmDisconnectMessage` - PM session termination
- `PubkeyRequestMessage` - Public key request
- `PubkeyResponseMessage` - Public key sharing

**Client-side Models:**

- `ClientChatMessage` - Client chat input
- `ClientPmInvite` - Client PM invite
- `ClientPmAccept` - Client PM accept
- `ClientPmDecline` - Client PM decline
- `ClientPmMessage` - Client encrypted PM
- `ClientPmDisconnect` - Client PM disconnect
- `ClientPubkeyRequest` - Client key request
- `ClientPubkeyResponse` - Client key response
- `ClientPubkeyRegister` - Client key registration
- `ClientPubkeyLookup` - Client key lookup

**System Models:**

- `UserListMessage` - Online users list
- `PubkeyLookupResponse` - Key lookup results
- `ErrorMessage` - Error responses
- `WsEvent` - WebSocket event wrapper

## CI/CD Integration

### GitHub Actions Ready

```yaml
- name: Run tests
  run: |
    pip install -r requirements.txt
    pytest --cov=server --cov-report=xml
```

### Test Database

- Uses SQLite in-memory for speed
- Supports PostgreSQL/MySQL for production testing
- Automatic schema creation and cleanup

### Coverage Goals

- **Overall coverage**: >90%
- **Critical paths**: 100% (auth, encryption, WebSocket)
- **Edge cases**: Comprehensive error condition testing

## Security Testing

### Encryption Validation

- RSA-2048 key generation and validation
- OAEP padding with SHA-256
- Base64 encoding/decoding integrity
- Key tampering detection

### Authentication Security

- bcrypt password hashing (12 rounds)
- JWT token validation and expiration
- SQL injection prevention testing
- Timing attack resistance validation

### WebSocket Security

- Connection validation
- Message type enforcement
- Error message sanitization
- Rate limiting considerations

## Performance Benchmarks

### Target Performance

- **Authentication**: <100ms per request
- **WebSocket connections**: <50ms connection time
- **Message broadcasting**: <200ms for 100 users
- **Database operations**: <10ms per query
- **Encryption/Decryption**: <50ms per message

### Load Testing Scenarios

- 100 concurrent users
- 1000 messages per minute
- 50 simultaneous PM sessions
- Bulk user registration/authentication

## Debugging Tests

### Common Issues

1. **Async test failures**: Ensure `@pytest.mark.asyncio` is used
2. **Database issues**: Check fixture dependencies
3. **WebSocket mocking**: Verify mock methods match actual interface
4. **Import errors**: Ensure all dependencies are installed

### Debug Mode

```bash
pytest --pdb  # Drop into debugger on failure
pytest -s     # Show print statements
pytest --tb=short  # Shorter tracebacks
```

### Logging

Tests include comprehensive logging for debugging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

This test suite ensures the chat application is production-ready with enterprise-grade reliability, security, and performance characteristics.
