import time
import datetime
from core.auth.system_db import SystemDatabase

class TimerEngine:
    """
    Manages the persistent countdown timer.
    Synchronizes state with the system database.
    """
    
    def __init__(self, system_db: SystemDatabase, audit_logger=None):
        self.system_db = system_db
        self.audit_logger = audit_logger
        self.state = self.system_db.get_timer_state()
        self._last_tick_time = None
        
    def start(self) -> None:
        """
        Starts or resumes the countdown timer.
        If expired, does nothing.
        """
        if self.state.get("is_expired", False):
            return
            
        self.state["is_running"] = True
        self._last_tick_time = time.time()
        self._flush_state()
        
        if self.audit_logger:
            self.audit_logger.log_event("TIMER_STARTED", {"remaining_ms": self.state["remaining_ms"]})
        
    def tick(self) -> None:
        """
        To be called continuously (e.g., in a background thread or event loop).
        Calculates elapsed time and updates state.
        """
        if not self.state.get("is_running", False) or self.state.get("is_expired", False):
            return
            
        current_time = time.time()
        if self._last_tick_time:
            elapsed_ms = int((current_time - self._last_tick_time) * 1000)
            
            new_remaining = self.state["remaining_ms"] - elapsed_ms
            if new_remaining <= 0:
                self.state["remaining_ms"] = 0
                self.state["is_expired"] = True
                self.state["is_running"] = False
                if self.audit_logger:
                    self.audit_logger.log_event("TIMER_EXPIRED", {"reason": "Countdown reached zero"})
            else:
                self.state["remaining_ms"] = new_remaining
                
        self._last_tick_time = current_time
        self._flush_state()
        
    def pause(self) -> None:
        """
        Pauses the timer (e.g. when USB is ejected gracefully or application closes).
        """
        if not self.state.get("is_running", False):
            return
            
        self.tick() # Ensure latest delta is applied
        self.state["is_running"] = False
        self._last_tick_time = None
        self._flush_state()
        
        if self.audit_logger:
            self.audit_logger.log_event("TIMER_PAUSED", {"remaining_ms": self.state["remaining_ms"]})
        
    def is_expired(self) -> bool:
        return self.state.get("is_expired", False)
        
    def get_remaining_seconds(self) -> float:
        return max(0, self.state.get("remaining_ms", 0) / 1000.0)
        
    def _flush_state(self) -> None:
        """
        Writes current state back to the database.
        """
        self.system_db.update_timer_state(
            remaining_ms=self.state["remaining_ms"],
            is_running=self.state["is_running"],
            is_expired=self.state["is_expired"]
        )
