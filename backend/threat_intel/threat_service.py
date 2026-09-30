import ipaddress
import httpx
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.models import ThreatIntelRecord, ThreatLevel


# Built-in reputation dataset for air-gapped / simulated SOC labs
KNOWN_MALICIOUS_IPS = {
    "185.220.101.5": {"score": 95, "level": ThreatLevel.MALICIOUS, "types": ["Tor Exit Node", "Port Scan"]},
    "45.154.255.88": {"score": 85, "level": ThreatLevel.MALICIOUS, "types": ["Botnet C2", "Brute Force"]},
    "194.26.29.112": {"score": 75, "level": ThreatLevel.SUSPICIOUS, "types": ["SSH Probing", "Malware Hosting"]},
    "198.51.100.45": {"score": 65, "level": ThreatLevel.SUSPICIOUS, "types": ["Suspicious Scanner"]},
}


class ThreatIntelService:
    """
    Threat Intelligence Integration Engine.
    Provides IP reputation lookups, AbuseIPDB integration, local caching,
    and automatic threat classification (CLEAN, SUSPICIOUS, MALICIOUS).
    """

    CACHE_TTL_HOURS = 24

    @classmethod
    async def check_ip(cls, ip: str, db: Session) -> ThreatIntelRecord:
        """
        Queries IP reputation from local cache or external providers.
        """
        ip_clean = ip.strip()

        # 1. Check local cache
        cached = db.query(ThreatIntelRecord).filter(
            ThreatIntelRecord.ip_address == ip_clean
        ).first()

        now = datetime.now(timezone.utc)
        if cached:
            # Check if cache is still fresh
            cached_time = cached.last_checked_at
            if cached_time.tzinfo is None:
                cached_time = cached_time.replace(tzinfo=timezone.utc)
            if (now - cached_time) < timedelta(hours=cls.CACHE_TTL_HOURS):
                return cached

        # 2. Check for private/internal IP
        is_private = False
        try:
            ip_obj = ipaddress.ip_address(ip_clean)
            is_private = ip_obj.is_private or ip_obj.is_loopback
        except ValueError:
            pass

        if is_private:
            record_data = {
                "score": 0,
                "level": ThreatLevel.CLEAN,
                "types": ["RFC 1918 Private / Loopback Network"],
                "provider": "Local Network Policy",
                "raw": {"type": "private_network", "ip": ip_clean}
            }
        elif ip_clean in KNOWN_MALICIOUS_IPS:
            known = KNOWN_MALICIOUS_IPS[ip_clean]
            record_data = {
                "score": known["score"],
                "level": known["level"],
                "types": known["types"],
                "provider": "SOC Threat Intelligence Feed",
                "raw": {"matched_signature": True, "ip": ip_clean}
            }
        elif settings.ABUSEIPDB_API_KEY:
            record_data = await cls._query_abuseipdb(ip_clean)
        else:
            # Default clean external IP for development
            record_data = {
                "score": 5,
                "level": ThreatLevel.CLEAN,
                "types": ["Standard External IP"],
                "provider": "Heuristic Assessment",
                "raw": {"status": "unflagged", "ip": ip_clean}
            }

        # 3. Update or create record in cache
        if cached:
            cached.reputation_score = record_data["score"]
            cached.threat_level = record_data["level"]
            cached.threat_types_json = record_data["types"]
            cached.source_provider = record_data["provider"]
            cached.raw_response_json = record_data["raw"]
            cached.last_checked_at = now
            record = cached
        else:
            record = ThreatIntelRecord(
                ip_address=ip_clean,
                reputation_score=record_data["score"],
                threat_level=record_data["level"],
                threat_types_json=record_data["types"],
                source_provider=record_data["provider"],
                raw_response_json=record_data["raw"],
                last_checked_at=now
            )
            db.add(record)

        db.commit()
        db.refresh(record)
        return record

    @classmethod
    async def _query_abuseipdb(cls, ip: str) -> Dict[str, Any]:
        """Queries the official AbuseIPDB v2 REST API if an API key is configured."""
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": settings.ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {"ipAddress": ip, "maxAgeInDays": "90"}

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.get(url, headers=headers, params=params)
                if res.status_code == 200:
                    data = res.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    if score >= 70:
                        level = ThreatLevel.MALICIOUS
                    elif score >= 20:
                        level = ThreatLevel.SUSPICIOUS
                    else:
                        level = ThreatLevel.CLEAN

                    return {
                        "score": score,
                        "level": level,
                        "types": data.get("reports", []) or ["External Abuse Reports"],
                        "provider": "AbuseIPDB API v2",
                        "raw": data
                    }
        except Exception:
            pass

        return {
            "score": 10,
            "level": ThreatLevel.UNKNOWN,
            "types": ["External Lookup Timeout"],
            "provider": "AbuseIPDB Fallback",
            "raw": {"status": "api_unavailable"}
        }
