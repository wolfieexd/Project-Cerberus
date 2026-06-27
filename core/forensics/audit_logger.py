import json
import hashlib
import datetime
from typing import Dict, Any, Tuple

from core.forensics.forensic_db import ForensicDatabase

class AuditLogger:
    """
    Handles structured, tamper-evident cryptographic logging.
    Each log is hashed along with the hash of the previous log, 
    forming a secure chain.
    """
    
    # In a real hardware-backed system, this would be derived from a TPM
    # or a dedicated logging key. For the prototype, we use a static seed.
    SECRET_SEED = b"FORTRESS_AUDIT_SEED_256"

    def __init__(self, db_path: str):
        self.db = ForensicDatabase(db_path)
        
    def _compute_hash(self, timestamp: str, event_type: str, details_json: str, previous_hash: str) -> str:
        """
        Computes a SHA-256 HMAC-like hash linking the current event to the previous one.
        """
        raw_data = f"{timestamp}|{event_type}|{details_json}|{previous_hash}"
        
        h = hashlib.sha256()
        h.update(self.SECRET_SEED)
        h.update(raw_data.encode('utf-8'))
        return h.hexdigest()

    def log_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """
        Records an event into the forensic database securely.
        """
        timestamp = datetime.datetime.utcnow().isoformat()
        details_json = json.dumps(details, sort_keys=True)
        
        last_log = self.db.get_last_log()
        previous_hash = last_log["chain_hash"] if last_log else "GENESIS_HASH"
        
        chain_hash = self._compute_hash(timestamp, event_type, details_json, previous_hash)
        
        self.db.insert_log(timestamp, event_type, details_json, chain_hash)

    def verify_chain(self) -> Tuple[bool, int]:
        """
        Verifies the cryptographic chain of all logs.
        Returns a tuple: (is_valid, index_of_first_invalid_log)
        If valid, the index is -1.
        """
        logs = self.db.get_all_logs()
        
        previous_hash = "GENESIS_HASH"
        for i, log in enumerate(logs):
            expected_hash = self._compute_hash(
                log["timestamp"], 
                log["event_type"], 
                log["details_json"], 
                previous_hash
            )
            
            if log["chain_hash"] != expected_hash:
                return False, i
                
            previous_hash = log["chain_hash"]
            
        return True, -1
