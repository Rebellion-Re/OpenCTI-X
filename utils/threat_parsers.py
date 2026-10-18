"""
ThreatFusion CTI - Deterministic Threat Intelligence Parsing Engine
Extracts: IPs, Domains, URLs, Hashes, Emails, CVEs, Threat Actors, Tools,
Malware, Campaigns, Countries, Regions, Industries, TTPs, and MITRE Techniques.
"""

import re
import ipaddress
import hashlib
from typing import List, Dict, Any, Set, Optional, Tuple
from urllib.parse import urlparse


class ThreatParsers:
    # ---------------------------------------------------------
    # COMPILED REGEX CATALOG
    # ---------------------------------------------------------
    # Network Indicators
    IPV4_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    IPV6_PATTERN = re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:|'
        r'\b:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){1,6}\b|'
        r'\b[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}\b'
    )
    URL_PATTERN = re.compile(
        r'\b(?:https?|ftp|hxxps?|h[xX]{2}ps?)://(?:[a-zA-Z0-9$_.+!*',;:&=~-]|%[0-9a-fA-F]{2})+[^\s<>"\'{}|\\^`]*',
        re.IGNORECASE
    )
    DOMAIN_PATTERN = re.compile(
        r'\b(?!(?:https?|ftp|hxxps?|h[xX]{2}ps?)://)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2
        re.IGNORECASE
    )
    EMAIL_PATTERN = re.compile(
        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,64}\b'
    )

    # Cryptographic Hashes
    MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
    SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
    SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')

    # Vulnerability Identifiers
    CVE_PATTERN = re.compile(r'\bCVE-(?:1999|20[0-9]{2})-[0-9]{4,7}\b', re.IGNORECASE)

    # MITRE ATT&CK Identifiers
    MITRE_TECHNIQUE_PATTERN = re.compile(r'\bT1[0-9]{3}(?:\.[0-9]{3})?\b')
    MITRE_TACTIC_PATTERN = re.compile(r'\bTA00[0-9]{2}\b')

    # File extensions to ignore when validating raw domain matches
    EXCLUDED_EXTENSIONS = {
        'exe', 'dll', 'sys', 'bat', 'vbs', 'ps1', 'sh', 'py', 'bin', 'elf', 'doc',
        'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'pdf', 'zip', 'tar', 'gz', '7z', 'rar',
        'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'txt', 'csv', 'json', 'yaml', 'yml',
        'xml', 'html', 'css', 'js', 'md', 'tmp', 'log', 'bak', 'cfg', 'ini', 'iso'
    }

    # Common TLD whitelist validation for high-precision domain filtering
    COMMON_TLDS = {
        'com', 'net', 'org', 'edu', 'gov', 'mil', 'int', 'io', 'ai', 'co', 'me', 'info',
        'biz', 'xyz', 'top', 'club', 'online', 'site', 'pro', 'mobi', 'ru', 'cn', 'ir',
        'ua', 'uk', 'de', 'fr', 'nl', 'eu', 'su', 'in', 'jp', 'kr', 'br', 'cc', 'to',
        'ws', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'live', 'agency', 'space', 'cloud'
    }

    @staticmethod
    def refang(text: str) -> str:
        """Restores defanged indicators to standard RFC formats for parsing."""
        if not text:
            return ""
        s = text
        s = re.sub(r'\[\.\]|\(\.\)|\{\.\}', '.', s)
        s = re.sub(r'\[:\]|\(:\]', ':', s)
        s = re.sub(r'hxxps?://', lambda m: 'https://' if 's' in m.group(0).lower() else 'http://', s, flags=re.I)
        s = re.sub(r'h[xX]{2}ps?://', lambda m: 'https://' if 's' in m.group(0).lower() else 'http://', s, flags=re.
        s = re.sub(r'\[@\]|\(@\)', '@', s)
        return s

    @staticmethod
    def defang(indicator: str, ioc_type: str) -> str:
        """Defangs parsed indicators for safe storage, display, and export."""
        if not indicator:
            return ""
        if ioc_type in ("DOMAIN", "IPV4", "IPV6"):
            return indicator.replace('.', '[.]')
        if ioc_type == "URL":
            s = indicator.replace("http://", "hxxp://").replace("https://", "hxxps://")
            parts = s.split("://", 1)
            if len(parts) == 2:
                scheme, rest = parts
                domain_part = rest.split("/", 1)[0]
                defanged_domain = domain_part.replace(".", "[.]")
                return f"{scheme}://{defanged_domain}{rest[len(domain_part):]}"
            return s.replace(".", "[.]")
        if ioc_type == "EMAIL":
            return indicator.replace("@", "[@]").replace(".", "[.]")
        return indicator

    @classmethod
    def is_valid_public_ip(cls, ip_str: str) -> bool:
        """Validates that IP string is valid and not loopback, private, multicast, or bogon."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return not (
                ip.is_private or
                ip.is_loopback or
                ip.is_multicast or
                ip.is_reserved or
                ip.is_link_local or
                ip.is_unspecified
            )
        except ValueError:
            return False

    @classmethod
    def extract_ips(cls, text: str) -> List[Dict[str, str]]:
        refanged = cls.refang(text)
        results = []
        seen = set()

        # IPv4
        for match in cls.IPV4_PATTERN.finditer(refanged):
            ip = match.group(0)
            if ip not in seen and cls.is_valid_public_ip(ip):
                seen.add(ip)
                results.append({
                    "raw": ip,
                    "normalized": ip,
                    "defanged": cls.defang(ip, "IPV4"),
                    "type": "IPV4"
                })

        # IPv6
        for match in cls.IPV6_PATTERN.finditer(refanged):
            ip = match.group(0)
            if ip not in seen and cls.is_valid_public_ip(ip):
                seen.add(ip)
                results.append({
                    "raw": ip,
                    "normalized": str(ipaddress.ip_address(ip)),
                    "defanged": cls.defang(ip, "IPV6"),
                    "type": "IPV6"
                })

        return results

    @classmethod
    def extract_urls(cls, text: str) -> List[Dict[str, str]]:
        refanged = cls.refang(text)
        results = []
        seen = set()

        for match in cls.URL_PATTERN.finditer(refanged):
            raw_url = match.group(0).rstrip('.,;)]}>"\'')
            if raw_url.lower() in seen:
                continue
            try:
                parsed = urlparse(raw_url)
                if parsed.scheme in ('http', 'https', 'ftp') and parsed.netloc:
                    seen.add(raw_url.lower())
                    results.append({
                        "raw": raw_url,
                        "normalized": raw_url,
                        "defanged": cls.defang(raw_url, "URL"),
                        "type": "URL",
                        "hostname": parsed.netloc.split(':')[0]
                    })
            except Exception:
                continue

        return results

    @classmethod
    def extract_domains(cls, text: str, excluded_hosts: Optional[Set[str]] = None) -> List[Dict[str, str]]:
        refanged = cls.refang(text)
        results = []
        seen = set(h.lower() for h in (excluded_hosts or set()))

        for match in cls.DOMAIN_PATTERN.finditer(refanged):
            dom = match.group(0).lower().rstrip('.')
            ext = dom.split('.')[-1]

            if ext in cls.EXCLUDED_EXTENSIONS:
                continue
            if ext not in cls.COMMON_TLDS:
                continue
            if dom in seen or len(dom) < 4:
                continue

            seen.add(dom)
            results.append({
                "raw": dom,
                "normalized": dom,
                "defanged": cls.defang(dom, "DOMAIN"),
                "type": "DOMAIN"
            })

        return results

    @classmethod
    def extract_emails(cls, text: str) -> List[Dict[str, str]]:
        refanged = cls.refang(text)
        results = []
        seen = set()

        for match in cls.EMAIL_PATTERN.finditer(refanged):
            mail = match.group(0).lower()
            ext = mail.split('.')[-1]
            if ext in cls.EXCLUDED_EXTENSIONS or ext not in cls.COMMON_TLDS:
                continue
            if mail not in seen:
                seen.add(mail)
                results.append({
                    "raw": match.group(0),
                    "normalized": mail,
                    "defanged": cls.defang(mail, "EMAIL"),
                    "type": "EMAIL"
                })

        return results

    @classmethod
    def extract_hashes(cls, text: str) -> List[Dict[str, str]]:
        results = []
        seen = set()

        # Extract SHA256
        sha256_matches = set()
        for match in cls.SHA256_PATTERN.finditer(text):
            h = match.group(0).lower()
            sha256_matches.add(h)
            if h not in seen:
                seen.add(h)
                results.append({
                    "raw": match.group(0),
                    "normalized": h,
                    "type": "SHA256"
                })

        # Extract SHA1
        sha1_matches = set()
        for match in cls.SHA1_PATTERN.finditer(text):
            h = match.group(0).lower()
            # Prevent substring matching against larger sha256
            if not any(h in full_sha for full_sha in sha256_matches):
                sha1_matches.add(h)
                if h not in seen:
                    seen.add(h)
                    results.append({
                        "raw": match.group(0),
                        "normalized": h,
                        "type": "SHA1"
                    })

        # Extract MD5
        for match in cls.MD5_PATTERN.finditer(text):
            h = match.group(0).lower()
            # Prevent substring matching against sha256 or sha1
            if not any(h in full_h for full_h in sha256_matches | sha1_matches):
                if h not in seen:
                    seen.add(h)
                    results.append({
                        "raw": match.group(0),
                        "normalized": h,
                        "type": "MD5"
                    })

        return results

    @classmethod
    def extract_cves(cls, text: str) -> List[str]:
        seen = set()
        cves = []
        for match in cls.CVE_PATTERN.finditer(text):
            cve = match.group(0).upper()
            if cve not in seen:
                seen.add(cve)
                cves.append(cve)
        return cves

    @classmethod
    def extract_mitre_ids(cls, text: str) -> Tuple[List[str], List[str]]:
        techniques = list(set(cls.MITRE_TECHNIQUE_PATTERN.findall(text)))
        tactics = list(set(cls.MITRE_TACTIC_PATTERN.findall(text)))
        return techniques, tactics
