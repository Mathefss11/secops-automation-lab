"""STATIC checks of the YARA-L portfolio rules in detections/.

These tests inspect the rule files as plain text: structure, metadata,
consistency with the Python project and documentation. They do NOT parse or
evaluate YARA-L, and they do NOT show that Google SecOps would accept the
rules. Only the Google SecOps API (verifyRuleText) in a live tenant can do
that, and no tenant was available. See docs/google-secops.md.
"""

import json
import re
from pathlib import Path

import pytest

from src.detection_engine import CREDENTIAL_ATTACK, PAYLOAD_EXECUTION, SUSPICIOUS_POWERSHELL, run_detections
from src.mitre import TECHNIQUE_NAMES, map_detection
from src.normalizer import normalize_events

ROOT = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = ROOT / "detections"
DOCS = ROOT / "docs" / "google-secops.md"
README = ROOT / "README.md"

RULES = {
    "credential_attack.yaral": CREDENTIAL_ATTACK,
    "suspicious_powershell.yaral": SUSPICIOUS_POWERSHELL,
    "payload_download_execution.yaral": PAYLOAD_EXECUTION,
}
SECTION_ORDER = ["meta", "events", "match", "outcome", "condition"]
REQUIRED_META = {"author", "description", "rule_name", "severity", "tactic", "technique", "disclaimer"}
SEVERITIES = {"Info", "Low", "Medium", "High", "Critical"}  # official style guide values
DISCLAIMER = "not validated in a live Google SecOps tenant"


def read(name: str) -> str:
    return (DETECTIONS_DIR / name).read_text(encoding="utf-8")


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def sections(text: str) -> dict[str, str]:
    """Split the rule body on section headers such as '  events:'."""
    body = strip_comments(text)
    parts = re.split(r"^\s*(meta|events|match|outcome|condition|options):\s*$", body, flags=re.M)
    return {parts[i]: parts[i + 1] for i in range(1, len(parts) - 1, 2)}


def meta(text: str) -> dict[str, str]:
    return dict(re.findall(r'^\s*(\w+)\s*=\s*"([^"]*)"', sections(text)["meta"], flags=re.M))


@pytest.fixture(scope="module")
def python_mappings():
    events, _ = normalize_events(json.loads((ROOT / "data" / "security_events.json").read_text(encoding="utf-8")))
    return {d.name: {t.technique_id for t in map_detection(d)} for d in run_detections(events)}


# --- Files and structure ------------------------------------------------------------


def test_all_rule_files_exist():
    assert sorted(p.name for p in DETECTIONS_DIR.glob("*.yaral")) == sorted(RULES)


@pytest.mark.parametrize("name", RULES)
def test_one_rule_per_file_with_balanced_braces(name):
    code = strip_comments(read(name))
    assert len(re.findall(r"^rule\s+\w+\s*\{", code, flags=re.M)) == 1
    assert code.count("{") == code.count("}")


def test_rule_names_are_unique():
    identifiers = [re.search(r"^rule\s+(\w+)", read(n), flags=re.M).group(1) for n in RULES]
    display_names = [meta(read(n))["rule_name"] for n in RULES]
    assert len(set(identifiers)) == len(identifiers) == 3
    assert len(set(display_names)) == 3


@pytest.mark.parametrize("name", RULES)
def test_sections_present_in_order(name):
    found = re.findall(r"^\s*(meta|events|match|outcome|condition|options):\s*$", strip_comments(read(name)), flags=re.M)
    assert found == SECTION_ORDER


@pytest.mark.parametrize("name", RULES)
def test_every_event_variable_appears_in_condition(name):
    """The official condition docs require every event variable to appear in condition."""
    parts = sections(read(name))
    event_variables = set(re.findall(r"\$(\w+)\.(?:metadata|principal|target|security_result|network|src)\b", parts["events"]))
    condition = parts["condition"]
    assert event_variables
    for variable in event_variables:
        assert re.search(rf"[$#]{variable}\b", condition), variable


@pytest.mark.parametrize("name", RULES)
def test_match_window_within_documented_limits(name):
    """Official match docs: windows from 1m to 48h."""
    value, unit = re.search(r"over\s+(\d+)([mhd])", sections(read(name))["match"]).groups()
    minutes = int(value) * {"m": 1, "h": 60, "d": 1440}[unit]
    assert 1 <= minutes <= 48 * 60


@pytest.mark.parametrize("name", RULES)
def test_style_no_tabs_or_trailing_whitespace(name):
    for line in read(name).splitlines():
        assert "\t" not in line
        assert line == line.rstrip()


# --- Metadata --------------------------------------------------------------------------


@pytest.mark.parametrize("name", RULES)
def test_required_metadata(name):
    values = meta(read(name))
    assert REQUIRED_META <= values.keys()
    assert values["severity"] in SEVERITIES
    assert all(value.strip() for value in values.values())


@pytest.mark.parametrize("name, python_name", RULES.items())
def test_rule_name_matches_python_detection(name, python_name):
    assert meta(read(name))["rule_name"] == python_name


@pytest.mark.parametrize("name, python_name", RULES.items())
def test_mitre_technique_consistent_with_python_mapping(name, python_name, python_mappings):
    technique = meta(read(name))["technique"]
    assert technique in TECHNIQUE_NAMES
    assert technique in python_mappings[python_name]


def test_tactics_match_techniques():
    tactics = {n: meta(read(n))["tactic"] for n in RULES}
    assert tactics == {
        "credential_attack.yaral": "TA0006",  # Credential Access
        "suspicious_powershell.yaral": "TA0002",  # Execution
        "payload_download_execution.yaral": "TA0011",  # Command and Control (T1105)
    }


def test_credential_rule_does_not_claim_password_spraying():
    text = read("credential_attack.yaral")
    assert meta(text)["technique"] == "T1110"
    assert "T1110.003" not in text
    assert "Not classified as password spraying" in text


@pytest.mark.parametrize("name", RULES)
def test_no_placeholders_and_disclaimer_present(name):
    text = read(name)
    assert not re.search(r"\b(TODO|TBD|FIXME|XXX|changeme|your_\w+)\b|<[A-Z_]+>", text, flags=re.I)
    assert DISCLAIMER in meta(text)["disclaimer"]
    assert "NOT been deployed" in text


@pytest.mark.parametrize("name", RULES)
def test_rule_does_not_hardcode_dataset_indicators(name):
    """Behavioral rules: no simulated IPs, hosts or users from data/security_events.json."""
    text = read(name)
    for indicator in ("203.0.113.45", "198.51.100.77", "192.0.2.80", "web-prod-01", "FIN-WS-07", "deploy", "mgarcia"):
        assert not re.search(rf"(?<![\w.-]){re.escape(indicator)}(?![\w.-])", text), indicator


# --- Documentation ---------------------------------------------------------------------


def test_docs_reference_every_rule_and_state_limitations():
    docs = DOCS.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    for name in RULES:
        assert f"detections/{name}" in docs
        assert f"detections/{name}" in readme
    assert "No Google SecOps tenant was available" in docs
    assert "verifyRuleText" in docs
    assert "is NOT UDM" in docs or "is **not** UDM" in readme
    assert "docs/google-secops.md" in readme


def test_docs_list_official_references():
    docs = DOCS.read_text(encoding="utf-8")
    references = docs.split("## Official References", 1)[1]
    assert references.count("https://docs.cloud.google.com/chronicle/docs/") >= 10
    assert "https://github.com/chronicle/detection-rules" in references
