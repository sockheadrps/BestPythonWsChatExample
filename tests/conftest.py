import pytest
import asyncio
from typing import Generator
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from server.main import app
from server.db.dbmodels import Base, User
from server.db.db import get_db
from server.chat.manager import ConnectionManager
from server.chat.private_manager import PrivateConnectionManager
from server.auth.hash import hash_password


# Test database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def db_session():
    """Create a fresh database session for each test."""
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def test_db():
    """Create a fresh test database session (alias for db_session)."""
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def sample_user(test_db):
    """Create a sample user in the test database."""
    username = "testuser"
    password = "testpassword123"
    hashed_password = hash_password(password)
    
    user = User(username=username, password=hashed_password)
    test_db.add(user)
    test_db.commit()
    test_db.refresh(user)
    
    return user


@pytest.fixture
def client(db_session):
    """Create a test client with dependency overrides."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def connection_manager():
    """Create a fresh ConnectionManager for testing."""
    return ConnectionManager()


@pytest.fixture
def private_manager():
    """Create a fresh PrivateConnectionManager for testing."""
    return PrivateConnectionManager()


@pytest.fixture
def sample_user_data():
    """Sample user data for testing."""
    return {
        "username": "testuser",
        "password": "testpassword123"
    }


@pytest.fixture
def sample_user_data_2():
    """Second sample user for multi-user testing."""
    return {
        "username": "testuser2", 
        "password": "testpassword456"
    }


@pytest.fixture
def rsa_key_pair():
    """Generate RSA key pair for encryption testing."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    import base64
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    # Export public key in SPKI format
    public_key_spki = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_b64 = base64.b64encode(public_key_spki).decode('utf-8')
    
    return {
        "private_key": private_key,
        "public_key": public_key,
        "public_key_b64": public_key_b64
    }


@pytest.fixture
def encrypted_message_pair(rsa_key_pair):
    """Create an encrypted message pair for testing."""
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    import base64
    
    message = "Hello, this is a test message!"
    
    # Encrypt the message
    encrypted = rsa_key_pair["public_key"].encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    ciphertext = base64.b64encode(encrypted).decode('utf-8')
    
    return {
        "plaintext": message,
        "ciphertext": ciphertext,
        "private_key": rsa_key_pair["private_key"],
        "public_key": rsa_key_pair["public_key"]
    }


class MockWebSocket:
    """Mock WebSocket for testing."""
    
    def __init__(self, username: str = "testuser"):
        self.username = username
        self.messages = []
        self.closed = False
        
    async def accept(self):
        pass
        
    async def send_json(self, data):
        self.messages.append(data)
        
    async def receive_json(self):
        # This would be overridden in specific tests
        return {"type": "test_message"}
        
    async def close(self, code: int = 1000):
        self.closed = True


@pytest.fixture
def mock_websocket():
    """Create a mock WebSocket for testing."""
    return MockWebSocket()


@pytest.fixture
def auth_headers(client, sample_user_data):
    """Create authenticated headers for testing protected endpoints."""
    # Register user
    client.post("/register", data=sample_user_data)
    
    # Login and get token
    response = client.post("/login", data=sample_user_data)
    
    # Extract token from cookie
    cookies = response.cookies
    token = cookies.get("access_token")
    
    return {"Authorization": f"Bearer {token}"} if token else {}


@pytest.fixture
def valid_jwt_token(client, sample_user_data):
    """Get a valid JWT token for testing."""
    # Register user
    client.post("/register", data=sample_user_data)
    
    # Login and get token
    response = client.post("/login", data=sample_user_data)
    
    # Extract token from cookie
    cookies = response.cookies
    return cookies.get("access_token") 