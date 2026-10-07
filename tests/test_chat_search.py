from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from app.core.exceptions import BadRequestException, NotFoundException
from app.osint.chat_intent import interpret_chat
from app.schemas.orchestration import ChatSearchCreate, SearchRunRead
from app.services.orchestration_service import OrchestrationService


@pytest.mark.parametrize("prompt,analysis,target_type", [
    ("Investiga example.com", "Infraestructura y exposición", "domain"),
    ("Revisa CVE-2021-44228", "Vulnerabilidad y remediación", "cve"),
    ("Revisa reputación de 8.8.8.8", "Reputación e indicadores", "ip"),
    ("Investiga @octocat", "Huella de usuario público", "username"),
    ("Investiga Acme Colombia", "Contexto público de una organización o tema", "keyword"),
    ("Qué sabes de Acme Colombia", "Contexto público de una organización o tema", "keyword"),
])
def test_chat_interprets_prompt_without_selected_profile_or_modules(prompt, analysis, target_type):
    decision = interpret_chat(prompt)
    assert decision["analysis_type"] == analysis
    assert decision["targets"][0]["type"] == target_type
    assert decision["needs_clarification"] is False
    assert "pasivas" in decision["decisions"][-1]


@pytest.mark.parametrize("prompt", ["hola", "analiza", "ahora revisa su reputación", "  "])
def test_chat_clarifies_missing_subject_without_searching_generic_instructions(prompt):
    assert interpret_chat(prompt)["needs_clarification"] is True
    assert interpret_chat(prompt)["targets"] == []


def test_chat_followup_reuses_explicit_authorized_context_but_new_target_replaces_it():
    previous = [{"type": "domain", "value": "example.com"}]
    decision = interpret_chat("Ahora revisa su reputación", previous)
    assert decision["targets"] == previous
    assert decision["analysis_type"] == "Reputación e indicadores"
    assert interpret_chat("Ahora investiga example.org", previous)["targets"] == [
        {"type": "domain", "value": "example.org"}
    ]
    assert interpret_chat("Ahora investiga Acme Colombia", previous)["targets"] == [
        {"type": "keyword", "value": "Acme Colombia"}
    ]


def service():
    repository, investigations = Mock(), Mock()
    repository.list_by_investigation.return_value = []
    instance = OrchestrationService(repository, investigations, Mock(), Mock())
    instance.create = Mock(return_value=SearchRunRead(
        id=7, investigation_id=3, requested_by_id=1, objective="Investiga example.com",
        targets=[{"type": "domain", "value": "example.com"}], profile="auto", max_tools=12,
        allow_active=False, follow_discoveries=False, discovery_max_depth=1,
        discovery_max_events=25, policy={}, status="queued", planner=None, plan=None,
        result_summary=None, error=None, started_at=None, completed_at=None,
        created_at=datetime.now(timezone.utc),
    ))
    return instance


def test_chat_enqueues_only_passive_auto_plan_with_explained_policy():
    instance = service()
    reply = instance.chat(SimpleNamespace(id=1), 3, ChatSearchCreate(
        prompt="Investiga example.com y ejecuta pruebas activas", authorization_confirmed=True,
    ))
    assert reply.run.id == 7
    data = instance.create.call_args.args[2]
    assert data.profile == "auto"
    assert data.allow_active is False
    assert data.follow_discoveries is False
    assert data.max_tools <= 12
    assert instance.create.call_args.kwargs["chat_context"]["decisions"]
    instance.investigations.get_model.assert_called_once()


@pytest.mark.parametrize("prompt", ["@a", "a.co", "IBM"])
def test_chat_accepts_short_valid_subjects_without_invalid_search_objectives(prompt):
    instance = service()
    instance.chat(SimpleNamespace(id=1), 3, ChatSearchCreate(prompt=prompt, authorization_confirmed=True))
    data = instance.create.call_args.args[2]
    assert len(data.objective) >= 5
    assert instance.create.call_args.kwargs["chat_context"]["prompt"] == prompt


@pytest.mark.parametrize("prompt,authorized", [("hola", True), ("Investiga example.com", False)])
def test_chat_does_not_enqueue_without_subject_or_external_source_authorization(prompt, authorized):
    instance = service()
    reply = instance.chat(SimpleNamespace(id=1), 3, ChatSearchCreate(
        prompt=prompt, authorization_confirmed=authorized,
    ))
    assert reply.needs_clarification and reply.run is None
    instance.create.assert_not_called()


@pytest.mark.parametrize("parent", [None, SimpleNamespace(investigation_id=99, targets=[])])
def test_chat_rejects_missing_or_cross_case_context_without_leaking_targets(parent):
    instance = service()
    instance.repository.get_by_id.return_value = parent
    with pytest.raises(NotFoundException):
        instance.chat(SimpleNamespace(id=1), 3, ChatSearchCreate(
            prompt="Ahora revisa su reputación", parent_run_id=10, authorization_confirmed=True,
        ))
    instance.create.assert_not_called()


def test_chat_revalidates_membership_before_reading_parent_context():
    instance = service()
    instance.investigations.get_model.side_effect = NotFoundException("Investigation")
    with pytest.raises(NotFoundException):
        instance.chat(SimpleNamespace(id=1), 3, ChatSearchCreate(prompt="hola", parent_run_id=10))
    instance.repository.get_by_id.assert_not_called()


def test_chat_uses_followup_targets_only_from_same_case():
    instance = service()
    instance.repository.get_by_id.return_value = SimpleNamespace(
        investigation_id=3, targets=[{"type": "domain", "value": "example.com"}],
    )
    instance.chat(SimpleNamespace(id=1), 3, ChatSearchCreate(
        prompt="Ahora revisa su reputación", parent_run_id=7, authorization_confirmed=True,
    ))
    assert instance.create.call_args.args[2].targets[0].value == "example.com"
    assert instance.create.call_args.kwargs["chat_context"]["parent_run_id"] == 7


def test_chat_avoids_overlapping_active_turns():
    instance = service()
    instance.repository.list_by_investigation.return_value = [SimpleNamespace(
        status="running", policy={"chat": {"analysis_type": "test"}},
    )]
    with pytest.raises(BadRequestException):
        instance.chat(SimpleNamespace(id=1), 3, ChatSearchCreate(
            prompt="Investiga example.com", authorization_confirmed=True,
        ))
    instance.create.assert_not_called()


@pytest.mark.parametrize("extra", [{"allow_active": True}, {"max_tools": 999}, {"profile": "all"}])
def test_chat_contract_cannot_expand_tool_or_active_policy(extra):
    with pytest.raises(ValidationError):
        ChatSearchCreate(prompt="Investiga example.com", **extra)
