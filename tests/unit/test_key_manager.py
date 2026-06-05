import pytest
from cryptography.exceptions import InvalidTag

from core.crypto.key_manager import KeyManager
from core.crypto.kdf import KDFEngine

@pytest.fixture
def test_key_manager():
    # Use fast KDF settings for tests
    fast_kdf = KDFEngine(time_cost=1, memory_cost=1024)
    return KeyManager(kdf_engine=fast_kdf)

def test_generate_mek(test_key_manager):
    mek = test_key_manager.generate_mek()
    assert len(mek) == 32

def test_derive_kek(test_key_manager):
    salt = b"\x00" * 16
    kek = test_key_manager.derive_kek("password", salt)
    assert len(kek) == 32

def test_wrap_and_unwrap_mek(test_key_manager):
    password = "SuperSecretPassword"
    original_mek = test_key_manager.generate_mek()
    
    # Wrap
    blob = test_key_manager.wrap_mek(password, original_mek)
    assert blob.salt is not None
    assert blob.nonce is not None
    assert blob.wrapped_key_with_tag is not None
    
    # Unwrap
    unwrapped_mek = test_key_manager.unwrap_mek(password, blob)
    assert unwrapped_mek == original_mek

def test_unwrap_with_wrong_password(test_key_manager):
    password = "CorrectPassword"
    wrong_password = "WrongPassword"
    original_mek = test_key_manager.generate_mek()
    
    blob = test_key_manager.wrap_mek(password, original_mek)
    
    with pytest.raises(InvalidTag):
        test_key_manager.unwrap_mek(wrong_password, blob)

def test_unwrap_tampered_blob(test_key_manager):
    password = "CorrectPassword"
    original_mek = test_key_manager.generate_mek()
    
    blob = test_key_manager.wrap_mek(password, original_mek)
    
    # Tamper with the ciphertext
    tampered = bytearray(blob.wrapped_key_with_tag)
    tampered[0] ^= 0x01
    blob.wrapped_key_with_tag = bytes(tampered)
    
    with pytest.raises(InvalidTag):
        test_key_manager.unwrap_mek(password, blob)
