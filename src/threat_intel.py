"""Threat-intelligence enrichment for IP indicators.

Threat intelligence is CONTEXT for an analyst. It does not prove compromise,
and a missing or clean result does not prove an IP is benign.

Two providers share one tiny interface (``name`` + ``lookup_ip``):

- ``MockThreatIntelProvider`` (default): deterministic, offline, clearly
  labelled as simulated. It makes no network requests.
- ``AbuseIPDBProvider`` (optional): queries the AbuseIPDB v2 ``/check`` API.
  It is used only when explicitly selected, and it needs ``ABUSEIPDB_API_KEY``.

Providers raise ``ThreatIntelError`` on failure. ``CachedThreatIntel`` turns
failures into an "unavailable" result, so enrichment can never break the
detection pipeline.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

import requests

MALICIOUS = "MALICIOUS"
SUSPICIOUS = "SUSPICIOUS"
UNKNOWN = "UNKNOWN"
BENIGN = "BENIGN"
UNAVAILABLE = "UNAVAILABLE"  # the lookup failed or was not performed

MOCK_SOURCE = "Mock Threat Intelligence (simulated)"
MOCK_DISCLAIMER = "Simulated data for demonstration only. This is NOT real threat intelligence."


class ThreatIntelError(Exception):
    """A lookup failed. Messages never contain API keys."""


class MissingApiKeyError(ThreatIntelError):
    pass


class AuthenticationError(ThreatIntelError):
    pass


class RateLimitError(ThreatIntelError):
    pass


@dataclass
class ThreatIntelResult:
    indicator: str
    indicator_type: str
    reputation: str
    confidence: float | None  # the source's confidence in its reputation (0.0-1.0), if any
    tags: list[str]
    source: str
    simulated: bool
    details: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def unavailable_result(indicator: str, source: str, simulated: bool, reason: str) -> ThreatIntelResult:
    return ThreatIntelResult(
        indicator=indicator,
        indicator_type="ip",
        reputation=UNAVAILABLE,
        confidence=None,
        tags=[],
        source=source,
        simulated=simulated,
        error=reason,
    )


def _validate_ip(indicator: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(indicator)
    except ValueError:
        raise ThreatIntelError(f"{indicator!r} is not a valid IP address") from None


class ThreatIntelProvider(Protocol):
    name: str
    simulated: bool

    def lookup_ip(self, ip: str) -> ThreatIntelResult: ...


# --- Mock provider ----------------------------------------------------------

# Deterministic, invented entries for the addresses in the simulated dataset.
# The attacker addresses are RFC 5737 documentation IPs: no real intelligence
# about them exists.
MOCK_INDICATORS: dict[str, dict[str, Any]] = {
    "203.0.113.45": {
        "reputation": MALICIOUS,
        "confidence": 0.90,
        "tags": ["ssh-brute-force", "scanner"],
        "details": {"simulated_reports": 37, "first_reported": "2026-08-30"},
    },
    "198.51.100.77": {
        "reputation": MALICIOUS,
        "confidence": 0.85,
        "tags": ["malware-distribution"],
        "details": {"simulated_reports": 12, "first_reported": "2026-09-10"},
    },
    "192.0.2.80": {
        "reputation": SUSPICIOUS,
        "confidence": 0.60,
        "tags": ["newly-observed", "file-hosting"],
        "details": {"simulated_reports": 2, "first_reported": "2026-09-13"},
    },
    "140.82.112.3": {"reputation": BENIGN, "confidence": 0.95, "tags": ["code-hosting"], "details": {}},
    "140.82.121.4": {"reputation": BENIGN, "confidence": 0.95, "tags": ["code-hosting"], "details": {}},
    "52.97.146.162": {"reputation": BENIGN, "confidence": 0.95, "tags": ["cloud-email"], "details": {}},
}


class MockThreatIntelProvider:
    """Offline, deterministic provider. Every result is marked ``simulated``."""

    name = MOCK_SOURCE
    simulated = True

    def lookup_ip(self, ip: str) -> ThreatIntelResult:
        _validate_ip(ip)
        entry = MOCK_INDICATORS.get(ip)
        if entry is None:
            return ThreatIntelResult(
                indicator=ip,
                indicator_type="ip",
                reputation=UNKNOWN,
                confidence=None,
                tags=[],
                source=MOCK_SOURCE,
                simulated=True,
                details={
                    "note": "No mock intelligence for this IP. Absence of intelligence does not mean benign.",
                    "disclaimer": MOCK_DISCLAIMER,
                },
            )
        return ThreatIntelResult(
            indicator=ip,
            indicator_type="ip",
            reputation=entry["reputation"],
            confidence=entry["confidence"],
            tags=list(entry["tags"]),
            source=MOCK_SOURCE,
            simulated=True,
            details={**entry["details"], "disclaimer": MOCK_DISCLAIMER},
        )


# --- AbuseIPDB provider -----------------------------------------------------

ABUSEIPDB_API_KEY_ENV = "ABUSEIPDB_API_KEY"
ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

# Project-chosen thresholds on AbuseIPDB's abuseConfidenceScore (0-100).
# A low score is reported as UNKNOWN, not BENIGN: "few reports" is not "safe".
ABUSEIPDB_MALICIOUS_SCORE = 75
ABUSEIPDB_SUSPICIOUS_SCORE = 25


class AbuseIPDBProvider:
    """Optional real provider for the AbuseIPDB v2 ``/check`` endpoint.

    It sends only the IP address to AbuseIPDB's documented API. It never
    contacts the IP itself, and it refuses to send private, documentation or
    other non-public addresses to a third party.
    """

    name = "AbuseIPDB"
    simulated = False

    def __init__(
        self,
        api_key: str,
        session: requests.Session | None = None,
        timeout_seconds: float = 10.0,
        max_age_days: int = 90,
    ) -> None:
        if not api_key:
            raise MissingApiKeyError(f"{ABUSEIPDB_API_KEY_ENV} is not set")
        self._api_key = api_key
        self._session = session or requests.Session()
        self.timeout_seconds = timeout_seconds
        self.max_age_days = max_age_days

    def __repr__(self) -> str:  # never show the key
        return f"AbuseIPDBProvider(timeout_seconds={self.timeout_seconds}, max_age_days={self.max_age_days})"

    @classmethod
    def from_environment(cls, **kwargs: Any) -> AbuseIPDBProvider:
        return cls(os.environ.get(ABUSEIPDB_API_KEY_ENV, "").strip(), **kwargs)

    def lookup_ip(self, ip: str) -> ThreatIntelResult:
        if not _validate_ip(ip).is_global:
            raise ThreatIntelError(f"{ip} is not a publicly routable address; it was not sent to AbuseIPDB")
        response = self._request(ip)
        data = self._parse(response)
        return self._to_result(ip, data)

    def _request(self, ip: str) -> requests.Response:
        try:
            response = self._session.get(
                ABUSEIPDB_CHECK_URL,
                headers={"Key": self._api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": self.max_age_days},
                timeout=self.timeout_seconds,
            )
        # Messages are written here on purpose: library exception text is not
        # passed on, so request details can never leak into output.
        except requests.Timeout:
            raise ThreatIntelError(f"AbuseIPDB did not respond within {self.timeout_seconds} seconds") from None
        except requests.ConnectionError:
            raise ThreatIntelError("could not connect to AbuseIPDB") from None
        except requests.RequestException:
            raise ThreatIntelError("AbuseIPDB request failed") from None

        if response.status_code in (401, 403):
            raise AuthenticationError(f"AbuseIPDB rejected the API key (HTTP {response.status_code})")
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After", "unknown")
            raise RateLimitError(f"AbuseIPDB rate limit reached; retry after {retry_after} seconds")
        if response.status_code != 200:
            raise ThreatIntelError(f"unexpected HTTP status {response.status_code} from AbuseIPDB")
        return response

    @staticmethod
    def _parse(response: requests.Response) -> dict[str, Any]:
        try:
            payload = response.json()
        except ValueError:
            raise ThreatIntelError("AbuseIPDB returned a response that is not valid JSON") from None
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict):
            raise ThreatIntelError("AbuseIPDB response has no 'data' object")
        score = data.get("abuseConfidenceScore")
        if not isinstance(score, int) or isinstance(score, bool) or not 0 <= score <= 100:
            raise ThreatIntelError("AbuseIPDB response has no valid 'abuseConfidenceScore'")
        return data

    @staticmethod
    def _reputation(score: int, whitelisted: bool) -> str:
        if whitelisted:
            return BENIGN
        if score >= ABUSEIPDB_MALICIOUS_SCORE:
            return MALICIOUS
        if score >= ABUSEIPDB_SUSPICIOUS_SCORE:
            return SUSPICIOUS
        return UNKNOWN

    def _to_result(self, ip: str, data: dict[str, Any]) -> ThreatIntelResult:
        score = data["abuseConfidenceScore"]
        whitelisted = data.get("isWhitelisted") is True
        tags = []
        if data.get("isTor") is True:
            tags.append("tor-exit-node")
        if data.get("usageType"):
            tags.append(str(data["usageType"]).lower().replace(" ", "-"))
        return ThreatIntelResult(
            indicator=ip,
            indicator_type="ip",
            reputation=self._reputation(score, whitelisted),
            confidence=score / 100,
            tags=tags,
            source=self.name,
            simulated=False,
            details={
                # Optional fields: missing ones are recorded as None.
                "abuse_confidence_score": score,
                "total_reports": data.get("totalReports"),
                "distinct_reporters": data.get("numDistinctUsers"),
                "last_reported_at": data.get("lastReportedAt"),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "is_whitelisted": data.get("isWhitelisted"),
                "max_age_days": self.max_age_days,
            },
        )


# --- Cache ------------------------------------------------------------------


class CachedThreatIntel:
    """In-memory, per-run cache around a provider.

    Each IP is looked up at most once per run. Failures are cached too, so a
    rate-limited or unreachable API is not hit again for the same IP.
    """

    def __init__(self, provider: ThreatIntelProvider) -> None:
        self.provider = provider
        self._cache: dict[str, ThreatIntelResult] = {}
        self.provider_calls = 0
        self.cache_hits = 0

    def lookup_ip(self, ip: str) -> ThreatIntelResult:
        if ip in self._cache:
            self.cache_hits += 1
            return self._cache[ip]

        self.provider_calls += 1
        try:
            result = self.provider.lookup_ip(ip)
        except ThreatIntelError as exc:
            result = unavailable_result(ip, self.provider.name, self.provider.simulated, str(exc))
        self._cache[ip] = result
        return result
