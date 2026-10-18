import re
import hashlib
from typing import List, Dict, Any

class IOCExtractor:
    IPV4_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]
    SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
    MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
    DOMAIN_PATTERN = re.compile(r'\b(?!(?:https?|ftp)://)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)+[a-zA-
    URL_PATTERN = re.compile(r'\bhttps?://[^\s/$.?#].[^\s]*\b')

    @classmethod
    def defang(cls, text: str) -> str:
        text = text.replace("http://", "hxxp://").replace("https://", "hxxps://")
        return text.replace(".", "[.]")

    @classmethod
    def refang(cls, text: str) -> str:
        text = text.replace("hxxp://", "http://").replace("hxxps://", "https://")
        return text.replace("[.]", ".").replace("[:]", ":")

    @classmethod
    def is_bogon_or_internal_ip(cls, ip: str) -> bool:
        octets = [int(x) for x in ip.split('.')]
        if octets[0] in [10, 127, 0]:
            return True
        if octets[0] == 172 and (16 <= octets[1] <= 31):
            return True
        if octets[0] == 192 and octets[1] == 168:
            return True
        if octets[0] >= 224:
            return True
        return False

    @classmethod
    def extract_all(cls, raw_text: str) -> List[Dict[str, Any]]:
        clean_text = cls.refang(raw_text)
        results: List[Dict[str, Any]] = []
        observed_hashes = set()

        # URLs
        for url in cls.URL_PATTERN.findall(clean_text):
            val = cls.defang(url)
            ioc_id = hashlib.sha256(f"URL:{val}".encode()).hexdigest()
            if ioc_id not in observed_hashes:
                observed_hashes.add(ioc_id)
                results.append({"ioc_id": ioc_id, "ioc_type": "URL", "ioc_value": val})

        # IPv4
        for ip in cls.IPV4_PATTERN.findall(clean_text):
            if not cls.is_bogon_or_internal_ip(ip):
                val = cls.defang(ip)
                ioc_id = hashlib.sha256(f"IPV4:{val}".encode()).hexdigest()
                if ioc_id not in observed_hashes:
                    observed_hashes.add(ioc_id)
                    results.append({"ioc_id": ioc_id, "ioc_type": "IPV4", "ioc_value": val})

        # SHA256
        for sha in cls.SHA256_PATTERN.findall(clean_text):
            val = sha.lower()
            ioc_id = hashlib.sha256(f"SHA256:{val}".encode()).hexdigest()
            if ioc_id not in observed_hashes:
                observed_hashes.add(ioc_id)
                results.append({"ioc_id": ioc_id, "ioc_type": "SHA256", "ioc_value": val})

        # MD5
        for md5 in cls.MD5_PATTERN.findall(clean_text):
            val = md5.lower()
            ioc_id = hashlib.sha256(f"MD5:{val}".encode()).hexdigest()
            if ioc_id not in observed_hashes:
                observed_hashes.add(ioc_id)
                results.append({"ioc_id": ioc_id, "ioc_type": "MD5", "ioc_value": val})

        # Domains
        for dom in cls.DOMAIN_PATTERN.findall(clean_text):
            if not any(dom.lower().endswith(ext) for ext in [".png", ".jpg", ".exe", ".pdf"]):
                val = cls.defang(dom.lower())
                ioc_id = hashlib.sha256(f"DOMAIN:{val}".encode()).hexdigest()
                if ioc_id not in observed_hashes:
                    observed_hashes.add(ioc_id)
                    results.append({"ioc_id": ioc_id, "ioc_type": "DOMAIN", "ioc_value": val})

        return results
