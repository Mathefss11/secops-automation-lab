import json

import pytest
import requests

from src.threat_intel import (
    ABUSEIPDB_API_KEY_ENV,
    ABUSEIPDB_CHECK_URL,
    BENIGN,
    MALICIOUS,
    MOCK_SOURCE,
    SUSPICIOUS,
    UNAVAILABLE,
    UNKNOWN,
    AbuseIPDBProvider,
    AuthenticationError,
    CachedThreatIntel,
    MissingApiKeyError,
    MockThreatIntelProvider,
    RateLimitError,
    ThreatIntelError,
)

# Fake value used only in tests; it is never sent anywhere (network is blocked).
FAKE_KEY = "test-key-not-real-0123456789"
PUBLIC_IP = "8.8.8.8"


# --- Test doubles -----------------------------------------------------------


def make_response(status=200, body=None, text=None, headers=None) -> requests.Response:
    """A real requests.Response object, built locally (no HTTP involved)."""
    response = requests.Response()
    response.status_code = status
    response._content = (json.dumps(body) if body is not None else (text or "")).encode("utf-8")
    response.encoding = "utf-8"
    response.headers.update(headers or {})
    return response


class FakeSession:
    """Stands in for requests.Session: records calls, returns or raises what it is given."""

    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error is not None:
            raise self.error
        return self.response


def provider_with(response=None, error=None):
    session = FakeSession(response, error)
    return AbuseIPDBProvider(FAKE_KEY, session=session), session


ABUSEIPDB_OK = {
    "data": {
        "ipAddress": PUBLIC_IP,
        "isPublic": True,
        "ipVersion": 4,
        "isWhitelisted": False,
        "abuseConfidenceScore": 88,
        "countryCode": "US",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Example ISP",
        "domain": "example.net",
        "hostnames": [],
        "isTor": False,
        "totalReports": 120,
        "numDistinctUsers": 40,
        "lastReportedAt": "2026-10-01T12:00:00+00:00",
    }
}


# =========================================================================
# Mock provider
# =========================================================================


def test_mock_known_malicious_ip():
    result = MockThreatIntelProvider().lookup_ip("203.0.113.45")
    assert result.reputation == MALICIOUS
    assert result.confidence == 0.90
    assert "ssh-brute-force" in result.tags


def test_mock_known_suspicious_ip():
    result = MockThreatIntelProvider().lookup_ip("192.0.2.80")
    assert result.reputation == SUSPICIOUS


def test_mock_benign_ip():
    assert MockThreatIntelProvider().lookup_ip("140.82.112.3").reputation == BENIGN


def test_mock_unknown_ip_is_unknown_not_benign():
    result = MockThreatIntelProvider().lookup_ip("192.0.2.81")
    assert result.reputation == UNKNOWN
    assert result.confidence is None
    assert "does not mean benign" in result.details["note"]


def test_mock_is_deterministic():
    first = MockThreatIntelProvider().lookup_ip("198.51.100.77")
    second = MockThreatIntelProvider().lookup_ip("198.51.100.77")
    assert first == second


def test_mock_results_are_clearly_simulated():
    for ip in ("203.0.113.45", "192.0.2.81"):
        result = MockThreatIntelProvider().lookup_ip(ip)
        assert result.simulated is True
        assert result.source == MOCK_SOURCE
        assert "(simulated)" in result.source
        assert "NOT real threat intelligence" in result.details["disclaimer"]
        assert result.to_dict()["simulated"] is True


def test_mock_rejects_invalid_ip():
    with pytest.raises(ThreatIntelError):
        MockThreatIntelProvider().lookup_ip("not-an-ip")


def test_mock_works_with_network_blocked():
    # conftest blocks all sockets; the mock must still answer.
    assert MockThreatIntelProvider().lookup_ip("203.0.113.45").reputation == MALICIOUS


# =========================================================================
# AbuseIPDB provider (all HTTP is faked)
# =========================================================================


def test_successful_response_is_structured():
    provider, session = provider_with(make_response(200, ABUSEIPDB_OK))
    result = provider.lookup_ip(PUBLIC_IP)

    assert result.reputation == MALICIOUS
    assert result.confidence == 0.88
    assert result.source == "AbuseIPDB"
    assert result.simulated is False
    assert result.details["total_reports"] == 120
    assert "data-center/web-hosting/transit" in result.tags


def test_request_uses_documented_endpoint_header_and_timeout():
    provider, session = provider_with(make_response(200, ABUSEIPDB_OK))
    provider.lookup_ip(PUBLIC_IP)

    [(url, kwargs)] = session.calls
    assert url == ABUSEIPDB_CHECK_URL
    assert kwargs["headers"]["Key"] == FAKE_KEY
    assert kwargs["params"] == {"ipAddress": PUBLIC_IP, "maxAgeInDays": 90}
    assert kwargs["timeout"] == 10.0
    assert FAKE_KEY not in url and FAKE_KEY not in json.dumps(kwargs["params"])


@pytest.mark.parametrize(
    "score, whitelisted, expected",
    [(80, False, MALICIOUS), (40, False, SUSPICIOUS), (0, False, UNKNOWN), (90, True, BENIGN)],
)
def test_score_to_reputation(score, whitelisted, expected):
    body = {"data": {**ABUSEIPDB_OK["data"], "abuseConfidenceScore": score, "isWhitelisted": whitelisted}}
    provider, _ = provider_with(make_response(200, body))
    assert provider.lookup_ip(PUBLIC_IP).reputation == expected


def test_missing_api_key(monkeypatch):
    monkeypatch.delenv(ABUSEIPDB_API_KEY_ENV, raising=False)
    with pytest.raises(MissingApiKeyError):
        AbuseIPDBProvider.from_environment()


def test_api_key_is_read_from_environment(monkeypatch):
    monkeypatch.setenv(ABUSEIPDB_API_KEY_ENV, FAKE_KEY)
    session = FakeSession(make_response(200, ABUSEIPDB_OK))
    AbuseIPDBProvider.from_environment(session=session).lookup_ip(PUBLIC_IP)
    assert session.calls[0][1]["headers"]["Key"] == FAKE_KEY


@pytest.mark.parametrize("status", [401, 403])
def test_authentication_error(status):
    body = {"errors": [{"detail": "Authentication failed.", "status": status}]}
    provider, _ = provider_with(make_response(status, body))
    with pytest.raises(AuthenticationError):
        provider.lookup_ip(PUBLIC_IP)


def test_rate_limit_reports_retry_after():
    provider, _ = provider_with(make_response(429, {"errors": []}, headers={"Retry-After": "3600"}))
    with pytest.raises(RateLimitError, match="3600"):
        provider.lookup_ip(PUBLIC_IP)


def test_timeout():
    provider, _ = provider_with(error=requests.Timeout("read timed out"))
    with pytest.raises(ThreatIntelError, match="did not respond"):
        provider.lookup_ip(PUBLIC_IP)


def test_connection_failure():
    provider, _ = provider_with(error=requests.ConnectionError("name resolution failed"))
    with pytest.raises(ThreatIntelError, match="could not connect"):
        provider.lookup_ip(PUBLIC_IP)


def test_malformed_json():
    provider, _ = provider_with(make_response(200, text="<html>gateway error</html>"))
    with pytest.raises(ThreatIntelError, match="not valid JSON"):
        provider.lookup_ip(PUBLIC_IP)


@pytest.mark.parametrize("status", [404, 422, 500, 503])
def test_unexpected_status(status):
    provider, _ = provider_with(make_response(status, {"errors": [{"detail": "x", "status": status}]}))
    with pytest.raises(ThreatIntelError, match=str(status)):
        provider.lookup_ip(PUBLIC_IP)


@pytest.mark.parametrize(
    "body",
    [
        {},  # no "data"
        {"data": None},
        {"data": "not an object"},
        [1, 2, 3],  # not an object at all
        {"data": {"ipAddress": PUBLIC_IP}},  # score missing
        {"data": {"abuseConfidenceScore": "high"}},  # wrong type
        {"data": {"abuseConfidenceScore": 250}},  # out of range
    ],
)
def test_missing_or_invalid_required_fields(body):
    provider, _ = provider_with(make_response(200, body))
    with pytest.raises(ThreatIntelError):
        provider.lookup_ip(PUBLIC_IP)


def test_missing_optional_fields_are_tolerated():
    provider, _ = provider_with(make_response(200, {"data": {"abuseConfidenceScore": 30}}))
    result = provider.lookup_ip(PUBLIC_IP)
    assert result.reputation == SUSPICIOUS
    assert result.details["total_reports"] is None
    assert result.tags == []


@pytest.mark.parametrize("ip", ["10.0.1.15", "192.168.1.1", "127.0.0.1", "203.0.113.45", "198.51.100.77"])
def test_non_public_ips_are_never_sent(ip):
    provider, session = provider_with(make_response(200, ABUSEIPDB_OK))
    with pytest.raises(ThreatIntelError, match="not a publicly routable"):
        provider.lookup_ip(ip)
    assert session.calls == []


def test_api_key_never_appears_in_errors_or_output():
    scenarios = [
        dict(response=make_response(401, {})),
        dict(response=make_response(429, {})),
        dict(response=make_response(500, {})),
        dict(response=make_response(200, text="garbage")),
        dict(error=requests.Timeout(f"timeout with {FAKE_KEY}")),
        dict(error=requests.ConnectionError(f"failed: Key={FAKE_KEY}")),
    ]
    for scenario in scenarios:
        provider, _ = provider_with(**scenario)
        intel = CachedThreatIntel(provider)
        result = intel.lookup_ip(PUBLIC_IP)
        assert result.reputation == UNAVAILABLE
        assert FAKE_KEY not in json.dumps(result.to_dict())
        assert FAKE_KEY not in repr(provider)


# =========================================================================
# Cache
# =========================================================================


class CountingProvider:
    name = "counting"
    simulated = True

    def __init__(self):
        self.calls = 0

    def lookup_ip(self, ip):
        self.calls += 1
        return MockThreatIntelProvider().lookup_ip(ip)


def test_cache_calls_provider_once_per_indicator():
    provider = CountingProvider()
    intel = CachedThreatIntel(provider)

    first = intel.lookup_ip("203.0.113.45")
    second = intel.lookup_ip("203.0.113.45")

    assert provider.calls == 1
    assert second is first
    assert (intel.provider_calls, intel.cache_hits) == (1, 1)


def test_cache_keeps_different_indicators_separate():
    provider = CountingProvider()
    intel = CachedThreatIntel(provider)
    intel.lookup_ip("203.0.113.45")
    intel.lookup_ip("192.0.2.80")
    assert provider.calls == 2


def test_failures_become_unavailable_results_and_are_cached():
    provider, session = provider_with(make_response(429, {}, headers={"Retry-After": "60"}))
    intel = CachedThreatIntel(provider)

    first = intel.lookup_ip(PUBLIC_IP)
    intel.lookup_ip(PUBLIC_IP)

    assert first.reputation == UNAVAILABLE
    assert "rate limit" in first.error
    assert first.simulated is False
    assert len(session.calls) == 1  # a rate-limited API is not hit again
