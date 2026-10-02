"""
Indicator of Compromise (IOC) Validation Engine
Module: backend.services.ioc_validator

Validates syntactic structure for defensive indicators:
IPv4, IPv6, Domain, URL, MD5, SHA-1, SHA-256, and CVE IDs.

IMPORTANT DEFENSIVE PRINCIPLE:
Syntactic validation determines whether an indicator is formatted correctly according to
technical standards. Validation does NOT imply maliciousness or confirmed compromise.
"""

import re
import ipaddress
from urllib.parse import urlparse

# Regular Expressions for indicator syntax validation
RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_CVE = re.compile(r"^CVE-(1999|20\d{2})-\d{4,7}$", re.IGNORECASE)
RE_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
RE_EMAIL = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

def validate_indicator(indicator_input: str) -> dict:
    """
    Validates and normalizes indicator syntax.

    Returns:
        dict: {
            "valid": bool,
            "indicator_type": str,
            "normalized_value": str,
            "validation_notes": str
        }
    """
    if not indicator_input or not isinstance(indicator_input, str):
        return {
            "valid": False,
            "indicator_type": "UNKNOWN",
            "normalized_value": "",
            "validation_notes": "Indicator string is empty or invalid data type."
        }

    raw = indicator_input.strip()
    
    # 1. Check CVE identifier
    if RE_CVE.match(raw):
        normalized = raw.upper()
        return {
            "valid": True,
            "indicator_type": "CVE ID",
            "normalized_value": normalized,
            "validation_notes": "Syntactically valid Common Vulnerabilities and Exposures (CVE) identifier."
        }
    elif raw.upper().startswith("CVE-"):
        return {
            "valid": False,
            "indicator_type": "CVE ID",
            "normalized_value": raw.upper(),
            "validation_notes": "Malformed CVE identifier. Expected format: CVE-YYYY-NNNN+."
        }

    # 2. Check File Hashes (MD5, SHA-1, SHA-256)
    if re.match(r"^[a-fA-F0-9]+$", raw):
        length = len(raw)
        if length == 32:
            return {
                "valid": True,
                "indicator_type": "FILE HASH (MD5)",
                "normalized_value": raw.lower(),
                "validation_notes": "Valid 128-bit hexadecimal MD5 cryptographic hash format."
            }
        elif length == 40:
            return {
                "valid": True,
                "indicator_type": "FILE HASH (SHA-1)",
                "normalized_value": raw.lower(),
                "validation_notes": "Valid 160-bit hexadecimal SHA-1 cryptographic hash format."
            }
        elif length == 64:
            return {
                "valid": True,
                "indicator_type": "FILE HASH (SHA-256)",
                "normalized_value": raw.lower(),
                "validation_notes": "Valid 256-bit hexadecimal SHA-256 cryptographic hash format."
            }

    # 3. Check IPv4 Address
    try:
        ip_obj = ipaddress.ip_address(raw)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            # Check if documentation or private range
            if ip_obj in ipaddress.ip_network("192.0.2.0/24") or \
               ip_obj in ipaddress.ip_network("198.51.100.0/24") or \
               ip_obj in ipaddress.ip_network("203.0.113.0/24"):
                note = "Valid IPv4 format. Safe RFC 5737 documentation test IP address."
            elif ip_obj.is_private:
                note = "Valid IPv4 format. Private RFC 1918 internal IP address."
            else:
                note = "Valid public IPv4 format."
            return {
                "valid": True,
                "indicator_type": "IP ADDRESS (IPv4)",
                "normalized_value": str(ip_obj),
                "validation_notes": note
            }
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            note = "Valid IPv6 format."
            if ip_obj in ipaddress.ip_network("2001:db8::/32"):
                note += " Safe RFC 3849 documentation test IPv6 address."
            return {
                "valid": True,
                "indicator_type": "IP ADDRESS (IPv6)",
                "normalized_value": str(ip_obj).lower(),
                "validation_notes": note
            }
    except ValueError:
        pass

    # 4. Check URL
    if raw.startswith("http://") or raw.startswith("https://"):
        try:
            parsed = urlparse(raw)
            if parsed.scheme in ["http", "https"] and parsed.netloc:
                # Disallow raw malformed hosts
                clean_netloc = parsed.netloc.split(":")[0]
                if clean_netloc and ("." in clean_netloc or clean_netloc.endswith(".invalid") or clean_netloc == "localhost"):
                    return {
                        "valid": True,
                        "indicator_type": "URL",
                        "normalized_value": raw.strip(),
                        "validation_notes": "Valid HTTP/HTTPS Uniform Resource Identifier."
                    }
            return {
                "valid": False,
                "indicator_type": "URL",
                "normalized_value": raw,
                "validation_notes": "Invalid or incomplete URL format."
            }
        except Exception:
            return {
                "valid": False,
                "indicator_type": "URL",
                "normalized_value": raw,
                "validation_notes": "Failed URL parsing."
            }

    # 5. Check Email / Sender Address
    if RE_EMAIL.match(raw):
        return {
            "valid": True,
            "indicator_type": "EMAIL/SENDER DOMAIN",
            "normalized_value": raw.lower(),
            "validation_notes": "Valid RFC 5322 email address format."
        }

    # 6. Check Domain Name
    clean_domain = raw.lower()
    # Strip optional trailing dot
    if clean_domain.endswith("."):
        clean_domain = clean_domain[:-1]

    if RE_DOMAIN.match(clean_domain):
        # Additional RFC checks: labels cannot exceed 63 chars, total len <= 253
        if len(clean_domain) <= 253 and all(len(part) <= 63 for part in clean_domain.split(".")):
            note = "Valid Fully Qualified Domain Name (FQDN) syntax."
            if clean_domain.endswith(".invalid") or clean_domain.endswith(".example") or clean_domain.endswith(".test"):
                note += " Safe RFC 2606 reserved top-level domain."
            return {
                "valid": True,
                "indicator_type": "DOMAIN",
                "normalized_value": clean_domain,
                "validation_notes": note
            }

    # If it looks like an attempted IP address with invalid octets
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", raw):
        return {
            "valid": False,
            "indicator_type": "IP ADDRESS (IPv4)",
            "normalized_value": raw,
            "validation_notes": "Invalid IPv4 address. Octet value outside allowable 0-255 range."
        }

    return {
        "valid": False,
        "indicator_type": "UNKNOWN",
        "normalized_value": raw,
        "validation_notes": "Unrecognized or malformed indicator string."
    }

if __name__ == "__main__":
    # Self-test cases
    samples = [
        "198.51.100.25", "999.12.34.56", "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "login-check.invalid", "bad domain name with space.com",
        "https://example.org/path/test", "44d88612fea8a8f36de82e1278abb02f",
        "CVE-2026-1045", "CVE-INVALID-99"
    ]
    for s in samples:
        res = validate_indicator(s)
        print(f"[{res['valid']}] {s:45} -> {res['indicator_type']} ({res['validation_notes']})")
