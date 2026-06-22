import pytest
from cryptography.exceptions import InvalidTag
import os

from core.auth.auth_manager import AuthManager
from core.crypto.key_manager import KeyManager
from core.crypto.kdf import KDFEngine

@pytest.fixture
def auth_env(tmp_path):
    system_db_path = str(tmp_path / "system.db")
    vault_db_path = str(tmp_path / "vault.db")
    data_dir = str(tmp_path / "data")
    
    # Fast KDF for testing
    fast_kdf = KDFEngine(time_cost=1, memory_cost=1024)
    key_manager = KeyManager(fast_kdf)
    
    manager = AuthManager(system_db_path, vault_db_path, data_dir, key_manager)
    return manager

def test_setup_and_authenticate(auth_env):
    password = "CorrectPassword123"
    
    # Setup new vault
    auth_env.setup_new_vault(password)
    assert auth_env.get_remaining_attempts() == 3
    
    # Authenticate successfully
    storage = auth_env.authenticate(password)
    assert storage is not None
    assert auth_env.get_remaining_attempts() == 3

def test_wrong_password_decrements_attempts(auth_env):
    password = "CorrectPassword123"
    auth_env.setup_new_vault(password)
    
    with pytest.raises(InvalidTag):
        auth_env.authenticate("WrongPassword")
        
    assert auth_env.get_remaining_attempts() == 2

def test_lockout_trigger(auth_env):
    password = "CorrectPassword123"
    auth_env.setup_new_vault(password)
    
    # 3 Failed attempts
    for _ in range(3):
        with pytest.raises(InvalidTag):
            auth_env.authenticate("WrongPassword")
            
    assert auth_env.is_locked_out() == True
    assert auth_env.get_remaining_attempts() == 0
    
    # 4th attempt should throw PermissionError before checking password
    with pytest.raises(PermissionError):
        auth_env.authenticate("CorrectPassword123")

def test_successful_auth_resets_attempts(auth_env):
    password = "CorrectPassword123"
    auth_env.setup_new_vault(password)
    
    with pytest.raises(InvalidTag):
        auth_env.authenticate("WrongPassword")
        
    assert auth_env.get_remaining_attempts() == 2
    
    # Successful auth should reset counter back to 3
    auth_env.authenticate(password)
    assert auth_env.get_remaining_attempts() == 3
