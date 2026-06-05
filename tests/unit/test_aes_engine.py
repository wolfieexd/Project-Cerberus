import pytest
from cryptography.exceptions import InvalidTag

from core.crypto.aes_engine import AESEngine, NonceManager

# NIST SP 800-38D GCM Test Vector (Test Case 14)
NIST_KEY = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
NIST_IV = bytes.fromhex("000000000000000000000000")
NIST_PLAINTEXT = bytes.fromhex("00000000000000000000000000000000")
NIST_CIPHERTEXT = bytes.fromhex("cea7403d4d606b6e074ec5d3baf39d18")
NIST_TAG = bytes.fromhex("d0d1c8a799996bf0265b98b5d48ab919")

def test_aes_engine_initialization():
    key = bytes([0] * 32)
    engine = AESEngine(key)
    assert engine._key == key
    
def test_aes_engine_invalid_key_length():
    with pytest.raises(ValueError):
        AESEngine(bytes([0] * 16))

def test_aes_engine_encrypt_decrypt():
    key = bytes([1] * 32)
    engine = AESEngine(key)
    plaintext = b"Secret data for encryption"
    
    nonce, ciphertext = engine.encrypt(plaintext)
    
    assert nonce != b""
    assert len(nonce) == 12
    assert ciphertext != plaintext
    
    decrypted = engine.decrypt(nonce, ciphertext)
    assert decrypted == plaintext

def test_aes_engine_tampered_ciphertext():
    key = bytes([2] * 32)
    engine = AESEngine(key)
    plaintext = b"Another secret"
    
    nonce, ciphertext = engine.encrypt(plaintext)
    
    # Tamper with the ciphertext (flip a bit)
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0x01
    
    with pytest.raises(InvalidTag):
        engine.decrypt(nonce, bytes(tampered))

def test_aes_engine_nist_vector():
    engine = AESEngine(NIST_KEY)
    
    # Normally we generate nonces randomly, but we'll test the raw library for the vector
    # since our encrypt method generates its own nonce.
    # We will test decryption with the NIST vector.
    
    ciphertext_with_tag = NIST_CIPHERTEXT + NIST_TAG
    decrypted = engine.decrypt(NIST_IV, ciphertext_with_tag)
    
    assert decrypted == NIST_PLAINTEXT

def test_nonce_manager():
    manager = NonceManager()
    nonce1 = manager.generate_nonce()
    nonce2 = manager.generate_nonce()
    
    assert len(nonce1) == 12
    assert nonce1 != nonce2
