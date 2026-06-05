import pytest
from core.crypto.kdf import KDFEngine

def test_kdf_engine_initialization():
    engine = KDFEngine(time_cost=2, memory_cost=1024)
    assert engine.time_cost == 2
    assert engine.memory_cost == 1024
    assert engine.hash_len == 32
    assert engine.salt_len == 16

def test_kdf_generate_salt():
    engine = KDFEngine()
    salt1 = engine.generate_salt()
    salt2 = engine.generate_salt()
    
    assert len(salt1) == 16
    assert salt1 != salt2

def test_kdf_derive_key():
    # Use small parameters for fast testing
    engine = KDFEngine(time_cost=1, memory_cost=1024)
    
    password = "MySecurePassword123!"
    salt = b"\x00" * 16
    
    key1 = engine.derive_key(password, salt)
    assert len(key1) == 32
    
    # Deterministic output for same inputs
    key2 = engine.derive_key(password, salt)
    assert key1 == key2

def test_kdf_different_passwords():
    engine = KDFEngine(time_cost=1, memory_cost=1024)
    salt = b"\x00" * 16
    
    key1 = engine.derive_key("passwordA", salt)
    key2 = engine.derive_key("passwordB", salt)
    
    assert key1 != key2

def test_kdf_different_salts():
    engine = KDFEngine(time_cost=1, memory_cost=1024)
    password = "same_password"
    
    key1 = engine.derive_key(password, b"\x00" * 16)
    key2 = engine.derive_key(password, b"\x01" * 16)
    
    assert key1 != key2

def test_kdf_invalid_inputs():
    engine = KDFEngine()
    salt = b"\x00" * 16
    
    with pytest.raises(ValueError):
        engine.derive_key("", salt)
        
    with pytest.raises(ValueError):
        engine.derive_key("password", b"\x00" * 15)  # Wrong salt length
