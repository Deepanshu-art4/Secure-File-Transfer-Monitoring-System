"""
Database initialization and default seed script for Secure File Transfer Monitoring System.
Creates all relational tables and populates baseline users, security rules, and system settings.
"""

import sys
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.core.database import engine, Base, SessionLocal
from backend.core.security import hash_password
from backend.models import (
    User, UserRole,
    SecurityRule, RuleType, SeverityLevel,
    SystemSetting, AuditLog
)


def init_database():
    print("[*] Initializing database schema...")
    Base.metadata.create_all(bind=engine)
    print("[+] Relational tables created successfully.")

    session = SessionLocal()
    try:
        # 1. Seed Default Users
        seed_users = [
            {
                "username": "admin",
                "email": "admin@soc.local",
                "password": "AdminPassword@2026",
                "role": UserRole.ADMIN
            },
            {
                "username": "analyst",
                "email": "analyst@soc.local",
                "password": "AnalystPassword@2026",
                "role": UserRole.ANALYST
            },
            {
                "username": "user1",
                "email": "user1@soc.local",
                "password": "UserPassword@2026",
                "role": UserRole.USER
            }
        ]

        created_users_count = 0
        for u in seed_users:
            existing = session.query(User).filter((User.username == u["username"]) | (User.email == u["email"])).first()
            if not existing:
                new_user = User(
                    username=u["username"],
                    email=u["email"],
                    hashed_password=hash_password(u["password"]),
                    role=u["role"],
                    is_active=True
                )
                session.add(new_user)
                created_users_count += 1
                print(f"[+] Created default user: {u['username']} ({u['role'].value})")

        # 2. Seed Default Configurable Security Rules
        seed_rules = [
            {
                "rule_code": "RULE_LARGE_FILE",
                "name": "Large File Transfer Exceeded",
                "description": "Flags transfers that exceed configured organizational file size threshold (e.g., > 50 MB).",
                "rule_type": RuleType.FILE_SIZE,
                "condition_config": {"max_size_mb": 50},
                "risk_weight": 20,
                "severity": SeverityLevel.HIGH,
                "is_enabled": True
            },
            {
                "rule_code": "RULE_OFF_HOURS",
                "name": "Off-Hours Transfer Activity",
                "description": "Flags file transfer activities conducted outside designated business operating hours.",
                "rule_type": RuleType.OFF_HOURS,
                "condition_config": {"work_start_hour": 9, "work_end_hour": 18},
                "risk_weight": 20,
                "severity": SeverityLevel.MEDIUM,
                "is_enabled": True
            },
            {
                "rule_code": "RULE_UNKNOWN_DEST",
                "name": "Transfer to Untrusted Destination",
                "description": "Flags file transfers directed toward unapproved external IPs or unknown host destinations.",
                "rule_type": RuleType.UNKNOWN_DESTINATION,
                "condition_config": {
                    "approved_subnets": ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "127.0.0.1/32"]
                },
                "risk_weight": 30,
                "severity": SeverityLevel.HIGH,
                "is_enabled": True
            },
            {
                "rule_code": "RULE_EXCESSIVE_TX",
                "name": "Excessive Transfer Burst Detected",
                "description": "Flags an abnormal spike in transfer frequency within a tight temporal detection window.",
                "rule_type": RuleType.EXCESSIVE_TRANSFERS,
                "condition_config": {"threshold_count": 10, "window_minutes": 10},
                "risk_weight": 20,
                "severity": SeverityLevel.MEDIUM,
                "is_enabled": True
            },
            {
                "rule_code": "RULE_INSECURE_PROTO",
                "name": "Insecure File Transfer Protocol",
                "description": "Detects transfers using unencrypted, vulnerable legacy protocols such as plain FTP or HTTP.",
                "rule_type": RuleType.INSECURE_PROTOCOL,
                "condition_config": {"blocked_protocols": ["FTP", "HTTP", "TELNET", "TFTP"]},
                "risk_weight": 20,
                "severity": SeverityLevel.HIGH,
                "is_enabled": True
            },
            {
                "rule_code": "RULE_INTEGRITY_FAIL",
                "name": "SHA-256 File Integrity Verification Failure",
                "description": "Detects cryptographic SHA-256 checksum mismatches indicating file tampering or transit corruption.",
                "rule_type": RuleType.INTEGRITY_FAILURE,
                "condition_config": {"strict_enforcement": True},
                "risk_weight": 30,
                "severity": SeverityLevel.CRITICAL,
                "is_enabled": True
            },
            {
                "rule_code": "RULE_FAILED_PATTERN",
                "name": "Repeated Transfer Failure Pattern",
                "description": "Flags recurring sequential transfer errors indicating brute-force or transfer disruption attempts.",
                "rule_type": RuleType.FAILED_PATTERN,
                "condition_config": {"failure_threshold": 3, "window_minutes": 15},
                "risk_weight": 15,
                "severity": SeverityLevel.MEDIUM,
                "is_enabled": True
            }
        ]

        created_rules_count = 0
        for r in seed_rules:
            existing_rule = session.query(SecurityRule).filter(SecurityRule.rule_code == r["rule_code"]).first()
            if not existing_rule:
                rule = SecurityRule(**r)
                session.add(rule)
                created_rules_count += 1
                print(f"[+] Created security rule: {r['rule_code']} ({r['severity'].value})")

        # 3. Seed System Settings
        seed_settings = [
            {
                "setting_key": "DEFAULT_ALERT_RISK_THRESHOLD",
                "setting_value": "30",
                "description": "Minimum risk score required to automatically trigger an incident alert (0-100)"
            },
            {
                "setting_key": "AUTOMATIC_QUARANTINE_ON_CRITICAL",
                "setting_value": "true",
                "description": "Automatically isolate files in quarantine storage if transfer risk level is CRITICAL"
            },
            {
                "setting_key": "MAX_ALLOWED_FILE_SIZE_MB",
                "setting_value": "100",
                "description": "Hard ceiling on maximum allowable upload payload size"
            }
        ]

        for s in seed_settings:
            existing_setting = session.query(SystemSetting).filter(SystemSetting.setting_key == s["setting_key"]).first()
            if not existing_setting:
                setting = SystemSetting(**s)
                session.add(setting)

        # 4. Audit Log Entry for Initialization
        audit = AuditLog(
            username="SYSTEM",
            action="DATABASE_INITIALIZED",
            resource_type="DATABASE",
            resource_id="INITIAL_SCHEMA",
            ip_address="127.0.0.1",
            status="SUCCESS",
            details_json={
                "seeded_users": created_users_count,
                "seeded_rules": created_rules_count
            }
        )
        session.add(audit)

        session.commit()
        print("\n[SUCCESS] DATABASE SEEDING COMPLETED SUCCESSFULLY!")

        # Print summary
        total_users = session.query(User).count()
        total_rules = session.query(SecurityRule).count()
        print(f"[*] Total Users in DB: {total_users}")
        print(f"[*] Total Configurable Security Rules in DB: {total_rules}")

    except Exception as e:
        session.rollback()
        print(f"[ERROR] Database initialization failed: {e}")
        raise e
    finally:
        session.close()


if __name__ == "__main__":
    init_database()
