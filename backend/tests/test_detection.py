from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base
from app.detection import process_event
from app.models import SecurityAlert

def test_bruteforce_rule(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    db = Session()
    try:
        for _ in range(6):
            process_event(db, {
                "source_ip": "203.0.113.9",
                "destination_ip": "10.0.0.1",
                "source_port": 4000,
                "destination_port": 22,
                "protocol": "TCP",
                "event_type": "auth_failure",
                "bytes_count": 100,
                "simulated": True,
                "details": "isolated unit test",
            })
        assert db.query(SecurityAlert).filter_by(attack_type="Brute Force").count() >= 1
    finally:
        db.close()
        engine.dispose()
