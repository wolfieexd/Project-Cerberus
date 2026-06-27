import pytest
import os
import json

from core.forensics.audit_logger import AuditLogger

@pytest.fixture
def audit_logger(tmp_path):
    db_path = str(tmp_path / "audit.db")
    return AuditLogger(db_path)

def test_log_chaining_and_verification(audit_logger):
    # Log some events
    audit_logger.log_event("TEST_EVENT_1", {"foo": "bar"})
    audit_logger.log_event("TEST_EVENT_2", {"status": "ok"})
    audit_logger.log_event("TEST_EVENT_3", {"action": "delete"})
    
    # Verify chain
    is_valid, invalid_index = audit_logger.verify_chain()
    assert is_valid == True
    assert invalid_index == -1
    
    logs = audit_logger.db.get_all_logs()
    assert len(logs) == 3

def test_detect_tampering_modified_data(audit_logger):
    audit_logger.log_event("EVENT_A", {})
    audit_logger.log_event("EVENT_B", {})
    
    # Maliciously alter the database
    with audit_logger.db.get_connection() as conn:
        conn.execute("UPDATE audit_logs SET event_type = 'EVENT_HACKED' WHERE id = 1")
        
    is_valid, invalid_index = audit_logger.verify_chain()
    assert is_valid == False
    assert invalid_index == 0 # First log fails hash check

def test_detect_tampering_deleted_log(audit_logger):
    audit_logger.log_event("EVENT_1", {})
    audit_logger.log_event("EVENT_2", {})
    audit_logger.log_event("EVENT_3", {})
    
    # Maliciously delete the middle log
    with audit_logger.db.get_connection() as conn:
        conn.execute("DELETE FROM audit_logs WHERE id = 2")
        
    is_valid, invalid_index = audit_logger.verify_chain()
    assert is_valid == False
    # The chain breaks at the log that used to be index 2 (now index 1 in the list)
    assert invalid_index == 1 
