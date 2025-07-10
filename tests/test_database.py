import pytest
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from server.db.dbmodels import User
from server.db.db import get_db
from server.auth.auth import register_user, get_user_by_username
from server.auth.hash import verify_password


class TestUserModel:
    """Test the User database model."""
    
    def test_create_user(self, db_session: Session):
        """Test creating a user in the database."""
        user = User(username="testuser", password="hashedpassword")
        db_session.add(user)
        db_session.commit()
        
        # Retrieve user
        retrieved_user = db_session.query(User).filter(User.username == "testuser").first()
        
        assert retrieved_user is not None
        assert retrieved_user.username == "testuser"
        assert retrieved_user.password == "hashedpassword"
        assert retrieved_user.id is not None
    
    def test_user_unique_username(self, db_session: Session):
        """Test that usernames must be unique."""
        # Create first user
        user1 = User(username="testuser", password="password1")
        db_session.add(user1)
        db_session.commit()
        
        # Try to create second user with same username
        user2 = User(username="testuser", password="password2")
        db_session.add(user2)
        
        with pytest.raises(IntegrityError):
            db_session.commit()
    
    def test_user_required_fields(self, db_session: Session):
        """Test that required fields are enforced."""
        # Username is required
        with pytest.raises((IntegrityError, ValueError)):
            user = User(username=None, password="password")
            db_session.add(user)
            db_session.commit()
        
        # Rollback after the failed transaction
        db_session.rollback()
        
        # Password is required
        with pytest.raises((IntegrityError, ValueError)):
            user = User(username="testuser", password=None)
            db_session.add(user)
            db_session.commit()
    
    def test_user_string_representation(self, db_session: Session):
        """Test user string representation."""
        user = User(username="testuser", password="password")
        db_session.add(user)
        db_session.commit()
        
        # User model doesn't have custom __str__, so test object type instead
        user_str = str(user)
        assert "User" in user_str
        # Test that we can access the username attribute
        assert user.username == "testuser"
    
    def test_multiple_users(self, db_session: Session):
        """Test creating multiple users."""
        users_data = [
            ("user1", "password1"),
            ("user2", "password2"),
            ("user3", "password3")
        ]
        
        for username, password in users_data:
            user = User(username=username, password=password)
            db_session.add(user)
        
        db_session.commit()
        
        # Check all users exist
        all_users = db_session.query(User).all()
        assert len(all_users) == 3
        
        usernames = [user.username for user in all_users]
        assert "user1" in usernames
        assert "user2" in usernames
        assert "user3" in usernames


class TestDatabaseOperations:
    """Test database operations and queries."""
    
    def test_user_registration_database_integration(self, db_session: Session):
        """Test user registration with database."""
        username = "testuser"
        password = "testpassword123"
        
        user = register_user(db_session, username, password)
        
        assert user is not None
        assert user.username == username
        # Password should be hashed
        assert user.password != password
        assert verify_password(password, user.password)
        
        # Check in database
        db_user = db_session.query(User).filter(User.username == username).first()
        assert db_user is not None
        assert db_user.username == username
    
    def test_get_user_by_username_database(self, db_session: Session):
        """Test getting user by username from database."""
        # Create test user
        user = User(username="testuser", password="password")
        db_session.add(user)
        db_session.commit()
        
        # Retrieve using auth function
        retrieved_user = get_user_by_username(db_session, "testuser")
        
        assert retrieved_user is not None
        assert retrieved_user.username == "testuser"
        assert retrieved_user.password == "password"
    
    def test_query_multiple_users(self, db_session: Session):
        """Test querying multiple users."""
        # Create multiple users
        for i in range(5):
            user = User(username=f"user{i}", password=f"password{i}")
            db_session.add(user)
        
        db_session.commit()
        
        # Query all users
        all_users = db_session.query(User).all()
        assert len(all_users) == 5
        
        # Query specific users
        user_2 = db_session.query(User).filter(User.username == "user2").first()
        assert user_2 is not None
        assert user_2.username == "user2" 