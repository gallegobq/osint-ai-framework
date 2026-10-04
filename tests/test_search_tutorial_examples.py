from __future__ import annotations

import pytest

from app.osint.contracts import DISCOVERY_TARGET_TYPES
from app.osint.profiles import ScanProfile, scan_profile_catalog
from app.osint.targets import infer_targets, normalize_target


DOCUMENTED_EXAMPLES = (
    ("domain", "  EXAMPLE.COM. ", "example.com"),
    ("hostname", "WWW.EXAMPLE.COM.", "www.example.com"),
    ("ip", "8.8.8.8", "8.8.8.8"),
    ("asn", "15169", "AS15169"),
    ("url", "HTTPS://EXAMPLE.COM/path?source=test#fragment", "https://example.com/path?source=test"),
    ("username", "octocat", "octocat"),
    ("email", "analista@example.com", "analista@example.com"),
    ("hash", "D41D8CD98F00B204E9800998ECF8427E", "d41d8cd98f00b204e9800998ecf8427e"),
    ("cve", "cve-2021-44228", "CVE-2021-44228"),
    ("keyword", "  seguridad   defensiva  ", "seguridad defensiva"),
)


@pytest.mark.parametrize(
    ("target_type", "value", "expected"),
    DOCUMENTED_EXAMPLES,
)
def test_documented_search_examples_normalize_without_network(
    target_type: str,
    value: str,
    expected: str,
) -> None:
    assert normalize_target(target_type, value) == expected


def test_tutorial_covers_every_supported_target_type() -> None:
    documented_types = {target_type for target_type, _, _ in DOCUMENTED_EXAMPLES}

    assert documented_types == DISCOVERY_TARGET_TYPES


def test_documented_profiles_match_public_catalog() -> None:
    expected = {
        ScanProfile.AUTO.value,
        ScanProfile.PASSIVE.value,
        ScanProfile.FOOTPRINT.value,
        ScanProfile.INVESTIGATE.value,
        ScanProfile.ALL.value,
    }

    assert {item["name"] for item in scan_profile_catalog()} == expected


def test_automatic_detection_recognizes_explicit_safe_examples() -> None:
    objective = (
        "Revisa https://example.com/path, AS15169, "
        "analista@example.com, CVE-2021-44228, "
        "D41D8CD98F00B204E9800998ECF8427E, @octocat y 8.8.8.8"
    )

    inferred = {
        (item["type"], item["value"])
        for item in infer_targets(objective)
    }

    assert {
        ("url", "https://example.com/path"),
        ("domain", "example.com"),
        ("asn", "AS15169"),
        ("email", "analista@example.com"),
        ("cve", "CVE-2021-44228"),
        ("hash", "d41d8cd98f00b204e9800998ecf8427e"),
        ("username", "octocat"),
        ("ip", "8.8.8.8"),
    } <= inferred


def test_private_ip_is_never_inferred_as_an_ip_target() -> None:
    inferred = infer_targets("Revisa 192.168.1.10 en el laboratorio autorizado")

    assert all(item["type"] != "ip" for item in inferred)


def test_plain_language_falls_back_to_a_keyword() -> None:
    assert infer_targets("marca de laboratorio autorizada") == [
        {
            "type": "keyword",
            "value": "marca de laboratorio autorizada",
        }
    ]
