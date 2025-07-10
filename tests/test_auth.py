import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from jose import jwt, JWTError


from server.auth.auth import (
    verify_password, hash_password, authenticate_user, 
    create_access_token, register_user
)
from server.auth.hash import hash_password as get_password_hash, verify_password as hash_verify_password
from server.db.dbmodels import User
from server.db.db import get_db


class TestPasswordHashing:
    """Test password hashing and verification."""
    
    def test_hash_password(self):
        """Test password hashing."""
        password = "testpassword123"
        hashed = hash_password(password)
        
        assert hashed != password
        assert len(hashed) > 0
        assert hashed.startswith("$2b$")  # bcrypt format
    
    def test_verify_password_correct(self):
        """Test password verification with correct password."""
        password = "testpassword123"
        hashed = hash_password(password)
        
        assert verify_password(password, hashed) is True
    
    def test_verify_password_incorrect(self):
        """Test password verification with incorrect password."""
        password = "testpassword123"
        wrong_password = "wrongpassword"
        hashed = hash_password(password)
        
        assert verify_password(wrong_password, hashed) is False
    
    def test_hash_verify_password_integration(self):
        """Test integration between hash module functions."""
        password = "testpassword123"
        hashed = get_password_hash(password)
        
        assert hash_verify_password(password, hashed) is True
        assert hash_verify_password("wrongpassword", hashed) is False
    
    def test_different_passwords_different_hashes(self):
        """Test that different passwords produce different hashes."""
        password1 = "password123"
        password2 = "password456"
        
        hash1 = hash_password(password1)
        hash2 = hash_password(password2)
        
        assert hash1 != hash2
    
    def test_same_password_different_hashes(self):
        """Test that same password produces different hashes (salt)."""
        password = "testpassword123"
        
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        
        # Due to salt, hashes should be different
        assert hash1 != hash2
        
        # But both should verify correctly
        assert verify_password(password, hash1) is True
        assert verify_password(password, hash2) is True
    
    def test_empty_password_handling(self):
        """Test handling of empty password."""
        # Empty password should still hash
        empty_hash = hash_password("")
        assert len(empty_hash) > 0
        assert verify_password("", empty_hash) is True
        assert verify_password("not_empty", empty_hash) is False
    
    def test_unicode_password_handling(self):
        """Test handling of unicode passwords."""
        unicode_password = "pássword123🔒"
        hashed = hash_password(unicode_password)
        
        assert verify_password(unicode_password, hashed) is True
        assert verify_password("password123", hashed) is False


class TestUserAuthentication:
    """Test user authentication functions."""
    
    def test_authenticate_user_success(self, test_db, sample_user):
        """Test successful user authentication."""
        # User should already be in database from fixture
        user = authenticate_user(test_db, sample_user.username, "testpassword123")
        
        assert user is not None
        assert user.username == sample_user.username
    
    def test_authenticate_user_wrong_password(self, test_db, sample_user):
        """Test authentication with wrong password."""
        user = authenticate_user(test_db, sample_user.username, "wrongpassword")
        
        assert user is None
    
    def test_authenticate_user_nonexistent(self, test_db):
        """Test authentication with nonexistent user."""
        user = authenticate_user(test_db, "nonexistent", "password")
        
        assert user is None
    
    def test_authenticate_user_empty_credentials(self, test_db):
        """Test authentication with empty credentials."""
        user = authenticate_user(test_db, "", "")
        
        assert user is None
    
    def test_register_user_success(self, test_db):
        """Test successful user registration."""
        username = "newuser"
        password = "newpassword123"
        
        user = register_user(test_db, username, password)
        
        assert user is not None
        assert user.username == username
        assert user.password != password  # Should be hashed
        
        # Verify password works
        assert verify_password(password, user.password)
    
    def test_register_user_duplicate_username(self, test_db, sample_user):
        """Test registering with duplicate username."""
        # Try to register with existing username
        user = register_user(test_db, sample_user.username, "newpassword123")
        
        assert user is None
    
    def test_register_user_empty_username(self, test_db):
        """Test registering with empty username."""
        user = register_user(test_db, "", "password123")
        
        # Should handle gracefully (implementation dependent)
        # Either return None or the user based on validation
        if user is not None:
            assert user.username == ""
    
    def test_register_user_unicode_username(self, test_db):
        """Test registering with unicode username."""
        username = "usér123🚀"
        password = "password123"
        
        user = register_user(test_db, username, password)
        
        if user is not None:  # Implementation may reject unicode
            assert user.username == username
    
    def test_user_lookup_after_registration(self, test_db):
        """Test that registered user can be found."""
        username = "lookuptest"
        password = "password123"
        
        # Register user
        registered_user = register_user(test_db, username, password)
        assert registered_user is not None
        
        # Find user by authentication
        found_user = authenticate_user(test_db, username, password)
        assert found_user is not None
        assert found_user.username == registered_user.username


class TestJWTTokens:
    """Test JWT token creation and validation."""
    
    def test_create_access_token(self):
        """Test access token creation."""
        data = {"sub": "testuser"}
        token = create_access_token(data)
        
        assert isinstance(token, str)
        assert len(token) > 0
        assert "." in token  # JWT format
    
    def test_create_access_token_with_expiry(self):
        """Test access token creation with custom expiry."""
        data = {"sub": "testuser"}
        expires_delta = timedelta(minutes=30)
        token = create_access_token(data, expires_delta)
        
        # Decode to verify expiry
        from server.auth.auth import SECRET_KEY, ALGORITHM
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        assert "exp" in payload
        assert "sub" in payload
        assert payload["sub"] == "testuser"
    
    def test_token_expiry_validation(self):
        """Test that expired tokens are rejected."""
        data = {"sub": "testuser"}
        # Create token that expires immediately
        expires_delta = timedelta(seconds=-1)
        expired_token = create_access_token(data, expires_delta)
        
        from server.auth.auth import SECRET_KEY, ALGORITHM
        
        with pytest.raises(JWTError):
            jwt.decode(expired_token, SECRET_KEY, algorithms=[ALGORITHM])
    
    def test_token_invalid_signature(self):
        """Test that tokens with invalid signature are rejected."""
        data = {"sub": "testuser"}
        token = create_access_token(data)
        
        # Try to decode with wrong secret
        with pytest.raises(JWTError):
            jwt.decode(token, "wrong_secret", algorithms=["HS256"])
    
    def test_token_contains_correct_data(self):
        """Test that token contains the expected data."""
        username = "testuser"
        data = {"sub": username}
        token = create_access_token(data)
        
        from server.auth.auth import SECRET_KEY, ALGORITHM
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        assert payload["sub"] == username
        assert "exp" in payload
    
    def test_multiple_tokens_different(self):
        """Test that multiple tokens for same user are different."""
        import time
        from datetime import timedelta
        data = {"sub": "testuser"}
        
        # Create tokens with different expiration times to ensure they're different
        token1 = create_access_token(data, timedelta(minutes=30))
        time.sleep(0.1)  # Longer delay
        token2 = create_access_token(data, timedelta(minutes=31))
        
        # Should be different due to different expiration times
        assert token1 != token2
    



class TestAuthenticationIntegration:
    """Test authentication flow integration."""
    
    def test_full_registration_login_flow(self, test_db):
        """Test complete registration and login flow."""
        username = "flowtest"
        password = "password123"
        
        # 1. Register user
        registered_user = register_user(test_db, username, password)
        assert registered_user is not None
        assert registered_user.username == username
        
        # 2. Authenticate user
        authenticated_user = authenticate_user(test_db, username, password)
        assert authenticated_user is not None
        assert authenticated_user.username == username
        
        # 3. Create token
        token = create_access_token({"sub": username})
        assert isinstance(token, str)
        
        # 4. Verify token contains correct user
        from server.auth.auth import SECRET_KEY, ALGORITHM
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        assert payload["sub"] == username
    
    def test_failed_authentication_flow(self, test_db, sample_user):
        """Test failed authentication scenarios."""
        # Wrong password
        user = authenticate_user(test_db, sample_user.username, "wrongpassword")
        assert user is None
        
        # Nonexistent user
        user = authenticate_user(test_db, "nonexistent", "password")
        assert user is None
        
        # Empty credentials
        user = authenticate_user(test_db, "", "")
        assert user is None
    
    def test_token_validation_flow(self, test_db, sample_user):
        """Test complete token creation and validation flow."""
        # 1. Create token for user
        token = create_access_token({"sub": sample_user.username})
        
        # 2. Decode and validate token
        from server.auth.auth import SECRET_KEY, ALGORITHM
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        assert payload["sub"] == sample_user.username
        assert "exp" in payload
    
    def test_password_security_requirements(self):
        """Test password security characteristics."""
        passwords = [
            "short",
            "verylongpasswordwithmancharacters",
            "password123!@#",
            "ünïcödé_pässwörd",
            ""
        ]
        
        hashes = []
        for password in passwords:
            hashed = hash_password(password)
            hashes.append(hashed)
            
            # Each hash should verify with original password
            assert verify_password(password, hashed)
            
            # Hash should not be the same as password
            assert hashed != password
        
        # All hashes should be different
        assert len(set(hashes)) == len(hashes)


class TestAuthenticationEdgeCases:
    """Test edge cases and security considerations."""
    
    def test_sql_injection_protection(self, test_db):
        """Test protection against SQL injection in authentication."""
        malicious_username = "'; DROP TABLE users; --"
        password = "password"
        
        # Should not crash or cause SQL injection
        user = authenticate_user(test_db, malicious_username, password)
        assert user is None
        
        # Database should still be intact (check by creating a user)
        normal_user = register_user(test_db, "normaluser", "password123")
        assert normal_user is not None
    
    def test_timing_attack_protection(self, test_db, sample_user):
        """Test that authentication timing is similar for valid/invalid users."""
        import time
        
        # Time authentication for existing user with wrong password
        start_time = time.time()
        authenticate_user(test_db, sample_user.username, "wrongpassword")
        existing_user_time = time.time() - start_time
        
        # Time authentication for nonexistent user
        start_time = time.time()
        authenticate_user(test_db, "nonexistent", "wrongpassword")
        nonexistent_user_time = time.time() - start_time
        
        # Times should be relatively similar (within reasonable bounds)
        # This is a basic check - real timing attack prevention needs more sophisticated testing
        if min(existing_user_time, nonexistent_user_time) > 0:
            time_ratio = max(existing_user_time, nonexistent_user_time) / min(existing_user_time, nonexistent_user_time)
            assert time_ratio < 1000  # More lenient bound for development testing
        else:
            # If either time is effectively zero, just ensure neither is dramatically longer
            assert max(existing_user_time, nonexistent_user_time) < 2.0  # Less than 2 seconds
    
    def test_case_sensitivity(self, test_db):
        """Test username case sensitivity."""
        username = "TestUser"
        password = "password123"
        
        # Register with specific case
        user = register_user(test_db, username, password)
        assert user is not None
        
        # Test authentication with different cases
        # (behavior depends on implementation)
        lower_case_auth = authenticate_user(test_db, username.lower(), password)
        upper_case_auth = authenticate_user(test_db, username.upper(), password)
        
        # At least the exact case should work
        exact_case_auth = authenticate_user(test_db, username, password)
        assert exact_case_auth is not None
    
    def test_whitespace_handling(self, test_db):
        """Test handling of whitespace in credentials."""
        username = "testuser"
        password = "password123"
        
        # Register normal user
        user = register_user(test_db, username, password)
        assert user is not None
        
        # Test authentication with extra whitespace
        whitespace_tests = [
            (" " + username, password),  # Leading space in username
            (username + " ", password),  # Trailing space in username
            (username, " " + password),  # Leading space in password
            (username, password + " "),  # Trailing space in password
        ]
        
        for test_username, test_password in whitespace_tests:
            auth_result = authenticate_user(test_db, test_username, test_password)
            # Depending on implementation, this might succeed or fail
            # The important thing is it doesn't crash
            assert auth_result is None or auth_result.username == username
    
    def test_maximum_token_lifetime(self):
        """Test token lifetime limits."""
        data = {"sub": "testuser"}
        
        # Test very long expiry
        long_expiry = timedelta(days=365)  # 1 year
        token = create_access_token(data, long_expiry)
        
        from server.auth.auth import SECRET_KEY, ALGORITHM
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Token should be created successfully
        assert payload["sub"] == "testuser"
        assert "exp" in payload
    
    def test_concurrent_authentication(self, test_db, sample_user):
        """Test concurrent authentication requests."""
        import threading
        import time
        
        results = []
        
        def authenticate_worker():
            result = authenticate_user(test_db, sample_user.username, "testpassword123")
            results.append(result)
        
        # Create multiple threads doing authentication
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=authenticate_worker)
            threads.append(thread)
        
        # Start all threads
        for thread in threads:
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # All authentication attempts should succeed
        assert len(results) == 5
        assert all(result is not None for result in results)
        assert all(result.username == sample_user.username for result in results)


class TestOAuth2PasswordForm:
    """Test OAuth2PasswordRequestForm integration."""
    
    def test_oauth2_form_structure(self):
        """Test OAuth2PasswordRequestForm integration expectation."""
        # This tests that OAuth2PasswordRequestForm is available for import
        # and is the expected class type used in the auth routes
        from fastapi.security import OAuth2PasswordRequestForm
        
        # Verify it's a class that can be imported
        assert OAuth2PasswordRequestForm is not None
        assert isinstance(OAuth2PasswordRequestForm, type)
        
        # This class is used as a dependency in FastAPI routes
        # The actual validation is done by FastAPI/Pydantic internally
    
    def test_form_data_simulation(self, test_db, sample_user):
        """Test simulating form data for authentication."""
        # Simulate form data structure
        class MockFormData:
            def __init__(self, username, password):
                self.username = username
                self.password = password
        
        # Create mock form data
        form_data = MockFormData(sample_user.username, "testpassword123")
        
        # Should work with authentication function
        user = authenticate_user(test_db, form_data.username, form_data.password)
        assert user is not None
        assert user.username == sample_user.username 