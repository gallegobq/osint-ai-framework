from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from app.core.settings import settings
from app.models.evidence import Evidence, EvidenceSource
from app.schemas.evidence import EvidenceCreate
from app.services.evidence_service import EvidenceService


def _service() -> EvidenceService:
    return EvidenceService(Mock(), Mock(), Mock(), Mock(), Mock(), Mock())


def _data(**overrides) -> EvidenceCreate:
    values = {
        "collector": "manual",
        "source_type": "web-page",
        "locator": "https://example.test/source",
        "source_metadata": {"headers": {"etag": "abc"}, "status": 200},
        "kind": "web_observation",
        "title": "Observed page",
        "content": "Evidence body",
        "observed_at": datetime(2026, 9, 19, 14, 30, tzinfo=timezone.utc),
        "raw_data": {"items": [1, 2], "verified": True},
    }
    values.update(overrides)
    return EvidenceCreate(**values)


def _source(data: EvidenceCreate) -> EvidenceSource:
    return EvidenceSource(
        id=7,
        investigation_id=3,
        collector=data.collector,
        source_type=data.source_type,
        locator=data.locator,
        locator_hash=hashlib.sha256(data.locator.encode("utf-8")).hexdigest(),
        collected_at=datetime(2026, 9, 19, 14, 31, tzinfo=timezone.utc),
        source_metadata=data.source_metadata,
    )


def _signed_evidence() -> Evidence:
    data = _data()
    source = _source(data)
    signing_key = EvidenceService._signing_key()
    evidence = Evidence(
        id=11,
        investigation_id=3,
        source_id=source.id,
        created_by_id=5,
        kind=data.kind,
        title=data.title,
        content=data.content,
        content_hash=EvidenceService._content_hash(data, source=source),
        integrity_signature="",
        integrity_version=EvidenceService.INTEGRITY_VERSION,
        integrity_key_id=EvidenceService._key_id(signing_key),
        observed_at=data.observed_at,
        collected_at=datetime(2026, 9, 19, 14, 31, tzinfo=timezone.utc),
        raw_data=data.raw_data,
        source=source,
    )
    evidence.integrity_signature = EvidenceService._sign_manifest(
        EvidenceService._integrity_manifest(
            evidence,
            content_hash=evidence.content_hash,
        ),
        signing_key,
    )
    return evidence


def test_canonical_hash_is_order_and_timezone_stable() -> None:
    first = _data(
        source_metadata={"b": 2, "a": 1},
        raw_data={"nested": {"z": 3, "a": 1}},
    )
    second = _data(
        source_metadata={"a": 1, "b": 2},
        raw_data={"nested": {"a": 1, "z": 3}},
        observed_at=first.observed_at.astimezone(
            timezone(timedelta(hours=-5))
        ),
    )

    assert EvidenceService._content_hash(first) == EvidenceService._content_hash(
        second
    )


def test_canonical_hash_covers_source_and_observation_fields() -> None:
    original = _data()
    original_hash = EvidenceService._content_hash(original)

    variants = (
        _data(source_type="api-response"),
        _data(source_metadata={"status": 404}),
        _data(locator="https://example.test/other"),
        _data(observed_at=datetime(2026, 9, 20, tzinfo=timezone.utc)),
        _data(raw_data={"items": [1, 3]}),
        _data(content="Changed evidence body"),
    )

    assert all(
        EvidenceService._content_hash(item) != original_hash
        for item in variants
    )


def test_v2_verification_accepts_untouched_evidence() -> None:
    result = _service()._verify_integrity(_signed_evidence())

    assert result.valid is True
    assert result.content_hash_valid is True
    assert result.signature_valid is True
    assert result.scheme == "canonical-v2"
    assert result.key_available is True


def test_v2_verification_detects_content_and_metadata_tampering() -> None:
    evidence = _signed_evidence()
    evidence.source.source_metadata = {"status": 500}

    result = _service()._verify_integrity(evidence)

    assert result.valid is False
    assert result.content_hash_valid is False
    assert result.signature_valid is False


def test_v2_signature_covers_creator_and_investigation_context() -> None:
    evidence = _signed_evidence()
    evidence.created_by_id = 999

    result = _service()._verify_integrity(evidence)

    assert result.valid is False
    assert result.content_hash_valid is True
    assert result.signature_valid is False


def test_v1_verification_remains_backward_compatible() -> None:
    data = _data()
    source = _source(data)
    content_hash = EvidenceService._legacy_content_hash(data)
    signature = hmac.new(
        settings.secret_key.get_secret_value().encode("utf-8"),
        content_hash.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    evidence = Evidence(
        id=12,
        investigation_id=3,
        source_id=source.id,
        created_by_id=5,
        kind=data.kind,
        title=data.title,
        content=data.content,
        content_hash=content_hash,
        integrity_signature=signature,
        integrity_version=EvidenceService.LEGACY_INTEGRITY_VERSION,
        integrity_key_id=EvidenceService.LEGACY_KEY_ID,
        observed_at=data.observed_at,
        collected_at=source.collected_at,
        raw_data=data.raw_data,
        source=source,
    )

    result = _service()._verify_integrity(evidence)

    assert result.valid is True
    assert result.scheme == "legacy-v1"
    assert result.warnings


def test_default_evidence_key_is_domain_separated_from_secret_key() -> None:
    assert EvidenceService._signing_key() != (
        settings.secret_key.get_secret_value().encode("utf-8")
    )


def test_evidence_metadata_size_is_bounded() -> None:
    with pytest.raises(ValidationError):
        _data(source_metadata={"value": "x" * 100_001})


def test_evidence_raw_data_depth_is_bounded() -> None:
    nested: dict = {}
    current = nested
    for _ in range(33):
        child: dict = {}
        current["child"] = child
        current = child

    with pytest.raises(ValidationError):
        _data(raw_data=nested)
