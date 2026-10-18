"""
ThreatFusion CTI - IOC Extraction Utility
"""

import re
import hashlib
from typing import List, Dict, Any


class IOCExtractor:
    IPV4_PATTERN = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )
    SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
    MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
    URL_PATTERN = re.compile(
        r"""\b(?:https?|ftp|hxxps?|h[xX]{2}ps?)://(?:[a-zA-Z0-9$_.+!*',;:&=~-]|%[0-9a-fA-F]{2})+[^\s<>"'{}|\\^`]*""",
        re.IGNORECASE,
    )
    DOMAIN_PATTERN = re.compile(
        r"\b(?!(?:https?|ftp|hxxps?|h[xX]{2}ps?)://)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b",
        re.IGNORECASE,
    )

    @classmethod
    def extract_all(cls, text: str) -> List[Dict[str, Any]]:
        results = []
        seen = set()

        if not text:
            return results

        # IPv4 Indicators
        for match in cls.IPV4_PATTERN.finditer(text):
            val = match.group(0)
            if val not in seen:
                seen.add(val)
                ioc_id = hashlib.sha256(f"IPV4:{val}".encode()).hexdigest()
                results.append({"ioc_id": ioc_id, "ioc_type": "IPV4", "ioc_value": val})

        # SHA256 Hashes
        for match in cls.SHA256_PATTERN.finditer(text):
            val = match.group(0).lower()
            if val not in seen:
                seen.add(val)
                ioc_id = hashlib.sha256(f"SHA256:{val}".encode()).hexdigest()
                results.append({"ioc_id": ioc_id, "ioc_type": "SHA256", "ioc_value": val})

        # MD5 Hashes
        for match in cls.MD5_PATTERN.finditer(text):
            val = match.group(0).lower()
            if val not in seen:
                seen.add(val)
                ioc_id = hashlib.sha256(f"MD5:{val}".encode()).hexdigest()
                results.append({"ioc_id": ioc_id, "ioc_type": "MD5", "ioc_value": val})

        # URLs
        for match in cls.URL_PATTERN.finditer(text):
            val = match.group(0)
            if val not in seen:
                seen.add(val)
                ioc_id = hashlib.sha256(f"URL:{val}".encode()).hexdigest()
                results.append({"ioc_id": ioc_id, "ioc_type": "URL", "ioc_value": val})

        # Domains
        for match in cls.DOMAIN_PATTERN.finditer(text):
            val = match.group(0).lower()
            if val not in seen:
                seen.add(val)
                ioc_id = hashlib.sha256(f"DOMAIN:{val}".encode()).hexdigest()
                results.append({"ioc_id": ioc_id, "ioc_type": "DOMAIN", "ioc_value": val})

        return results
