import pytest
import time

from core.auth.system_db import SystemDatabase
from core.timer.timer_engine import TimerEngine

@pytest.fixture
def system_db(tmp_path):
    db_path = str(tmp_path / "system.db")
    return SystemDatabase(db_path)

def test_timer_initialization(system_db):
    engine = TimerEngine(system_db)
    assert engine.get_remaining_seconds() == 120.0
    assert not engine.is_expired()

def test_timer_countdown(system_db):
    engine = TimerEngine(system_db)
    engine.start()
    
    # Sleep 50ms and tick
    time.sleep(0.05)
    engine.tick()
    
    remaining = engine.get_remaining_seconds()
    assert remaining < 120.0
    assert remaining > 119.0
    assert not engine.is_expired()

def test_timer_persistence(system_db):
    engine1 = TimerEngine(system_db)
    engine1.start()
    
    time.sleep(0.1)
    engine1.tick()
    engine1.pause()
    
    remaining1 = engine1.get_remaining_seconds()
    
    # Create new instance (simulates app restart)
    engine2 = TimerEngine(system_db)
    remaining2 = engine2.get_remaining_seconds()
    
    # It should have exactly the same remaining time
    assert remaining1 == remaining2
    assert remaining2 < 120.0

def test_timer_expiration(system_db):
    # Manually set db state to 1ms remaining to test expiration quickly
    system_db.update_timer_state(remaining_ms=1, is_running=False, is_expired=False)
    
    engine = TimerEngine(system_db)
    engine.start()
    
    time.sleep(0.01) # Sleep 10ms
    engine.tick()
    
    assert engine.is_expired() == True
    assert engine.get_remaining_seconds() == 0.0
    
    # State should be flushed to db
    db_state = system_db.get_timer_state()
    assert db_state["is_expired"] == True
    assert db_state["remaining_ms"] == 0
