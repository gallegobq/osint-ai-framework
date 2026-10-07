from datetime import datetime, timezone

from app.core.exceptions import BadRequestException, NotFoundException
from app.core.exceptions import ServiceUnavailableException
from app.core.settings import settings
from app.models.job import SearchRun
from app.models.user import User
from app.osint.targets import infer_targets, normalize_target
from app.osint.chat_intent import interpret_chat
from app.osint.active_collectors import SandboxTlsHttpBaselineCollector
from app.repositories.job_repository import (
    SearchDiscoveryRepository,
    SearchRunRepository,
)
from app.schemas.orchestration import (
    SearchDiscoveryEdgeRead,
    SearchDiscoveryGraphRead,
    SearchDiscoveryRead,
    SearchRunCreate,
    SearchRunRead,
    SearchRunStatus,
    ChatSearchCreate,
    ChatSearchRead,
)
from app.schemas.project import ProjectMemberRole
from app.services.audit_service import AuditService
from app.services.engagement_policy import active_target_scope_status, require_active_actor
from app.services.investigation_service import InvestigationService
from app.workers.dispatcher import JobDispatcher


class OrchestrationService:
    def __init__(
        self,
        repository: SearchRunRepository,
        investigations: InvestigationService,
        audit_service: AuditService,
        dispatcher: JobDispatcher,
    ):
        self.repository = repository
        self.discoveries = SearchDiscoveryRepository(repository.db)
        self.investigations = investigations
        self.audit = audit_service
        self.dispatcher = dispatcher

    def create(
        self,
        actor: User,
        investigation_id: int,
        data: SearchRunCreate,
        *,
        chat_context: dict | None = None,
    ) -> SearchRunRead:
        investigation = self.investigations.get_model(
            actor,
            investigation_id,
            minimum_role=ProjectMemberRole.EDITOR,
        )
        if data.max_tools > settings.orchestrator_max_tools:
            raise BadRequestException(
                "max_tools exceeds the configured orchestration limit."
            )
        if data.discovery_max_depth > settings.orchestrator_max_discovery_depth:
            raise BadRequestException(
                "discovery_max_depth exceeds the configured orchestration limit."
            )
        if data.discovery_max_events > settings.orchestrator_max_discovery_events:
            raise BadRequestException(
                "discovery_max_events exceeds the configured orchestration limit."
            )
        targets = (
            [
                {
                    "type": target.type.value,
                    "value": normalize_target(target.type.value, target.value),
                }
                for target in data.targets
            ]
            if data.targets
            else infer_targets(data.objective)
        )
        if data.allow_active:
            require_active_actor(actor, self.investigations.users)
            if len((data.scope_note or "").strip()) < 10:
                raise BadRequestException(
                    "Active pentest runs require a target-specific scope note."
                )
            active_allowed, reason = active_target_scope_status(
                investigation,
                targets,
                data.scope_note,
            )
            if not active_allowed:
                raise BadRequestException(reason or "Active testing is not allowed.")
        run = self.repository.create(
            SearchRun(
                investigation_id=investigation_id,
                requested_by_id=actor.id,
                objective=" ".join(data.objective.split()),
                targets=targets,
                profile=data.profile.value,
                max_tools=data.max_tools,
                allow_active=data.allow_active,
                follow_discoveries=data.follow_discoveries,
                discovery_max_depth=data.discovery_max_depth,
                discovery_max_events=data.discovery_max_events,
                policy={
                    **({"chat": chat_context} if chat_context else {}),
                    "authorization_confirmed": True,
                    "scope_note": data.scope_note,
                    "allow_active": data.allow_active,
                    "execution_boundary": (
                        "soc-sandbox" if data.allow_active else "passive-collectors"
                    ),
                    "operation_mode": investigation.operation_mode,
                    "profile": data.profile.value,
                    "discovery": {
                        "enabled": data.follow_discoveries,
                        "max_depth": data.discovery_max_depth,
                        "max_events": data.discovery_max_events,
                        "active_collectors": False,
                    },
                    "active_testing_authorized": (
                        investigation.active_testing_authorized
                    ),
                    "engagement_start_at": (
                        investigation.engagement_start_at.isoformat()
                        if investigation.engagement_start_at
                        else None
                    ),
                    "engagement_end_at": (
                        investigation.engagement_end_at.isoformat()
                        if investigation.engagement_end_at
                        else None
                    ),
                },
                status=SearchRunStatus.QUEUED.value,
            )
        )
        self.audit.record(
            actor_user_id=actor.id,
            action="orchestration.enqueue",
            resource_type="search_run",
            resource_id=run.id,
            data={
                "target_types": sorted({item["type"] for item in targets}),
                "max_tools": data.max_tools,
                "allow_active": data.allow_active,
                "operation_mode": investigation.operation_mode,
                "profile": data.profile.value,
                "follow_discoveries": data.follow_discoveries,
                "discovery_max_depth": data.discovery_max_depth,
                "discovery_max_events": data.discovery_max_events,
            },
        )
        self.repository.commit()

        try:
            self.dispatcher.enqueue_search_run(run.id)
        except Exception as exc:
            run.status = SearchRunStatus.FAILED.value
            run.error = "Background queue unavailable."
            run.completed_at = datetime.now(timezone.utc)
            self.repository.commit()
            raise ServiceUnavailableException(
                "Background queue unavailable."
            ) from exc

        return SearchRunRead.model_validate(run)

    def chat(self, actor: User, investigation_id: int, data: ChatSearchCreate) -> ChatSearchRead:
        investigation = self.investigations.get_model(actor, investigation_id, minimum_role=ProjectMemberRole.EDITOR)
        previous_targets = None
        if data.parent_run_id is not None:
            parent = self.repository.get_by_id(data.parent_run_id)
            if parent is None or parent.investigation_id != investigation_id:
                raise NotFoundException("Conversation context")
            # The context must belong to the same authorized case, not another project.
            previous_targets = parent.targets
        decision = interpret_chat(data.prompt, previous_targets)
        if decision["needs_clarification"]:
            return ChatSearchRead(**{k: decision[k] for k in (
                "message", "analysis_type", "decisions", "needs_clarification"
            )})
        if not data.authorization_confirmed:
            return ChatSearchRead(
                message="Antes de consultar fuentes externas, confirma que puedes investigar estos objetivos.",
                analysis_type=decision["analysis_type"], decisions=decision["decisions"],
                needs_clarification=True,
            )
        active = decision.get("active_requested", False)
        if active:
            require_active_actor(actor, self.investigations.users)
            if any(target["type"] not in {"domain", "hostname"} for target in decision["targets"]):
                return ChatSearchRead(
                    message="La verificación activa disponible admite dominios o hostnames explícitos. "
                    "Indica el host autorizado; no convertiré otros objetivos automáticamente.",
                    analysis_type=decision["analysis_type"], decisions=decision["decisions"],
                    needs_clarification=True,
                )
            targets = [{"type": target["type"], "value": normalize_target(target["type"], target["value"])}
                       for target in decision["targets"]]
            if len(targets) > min(12, settings.orchestrator_max_tools):
                raise BadRequestException("Reduce el número de hosts para verificar todo el alcance autorizado.")
            allowed, reason = active_target_scope_status(
                investigation, targets,
                data.active_scope_note or "Verificación TLS/HTTP TCP/443: " + ", ".join(t["value"] for t in targets),
            )
            if not allowed:
                return ChatSearchRead(
                    message=f"No iniciaré acciones activas: {reason} Configura un caso pentest "
                    "con autorización, hosts exactos y ventana vigente.",
                    analysis_type=decision["analysis_type"], decisions=decision["decisions"],
                    needs_clarification=True,
                )
            if not SandboxTlsHttpBaselineCollector().availability()[0]:
                return ChatSearchRead(
                    message="La verificación activa no está disponible: el sandbox está desactivado "
                    "o mal configurado. No presentaré una consulta pasiva como verificación activa.",
                    analysis_type=decision["analysis_type"], decisions=decision["decisions"],
                    needs_clarification=True,
                )
            if not data.active_authorization_confirmed or not (data.active_scope_note or "").strip():
                return ChatSearchRead(
                    message="Confirma esta ejecución activa: una negociación TLS y una petición HEAD "
                    "por host en TCP/443. Requiere un caso pentest autorizado y vigente, sin cambios "
                    "en sistemas ni seguimiento de nuevos objetivos.",
                    analysis_type=decision["analysis_type"], decisions=decision["decisions"],
                    needs_clarification=True, requires_active_authorization=True,
                    active_targets=[target["value"] for target in targets],
                )
        if any(run.status in {"queued", "running"} and (run.policy or {}).get("chat")
               for run in self.repository.list_by_investigation(investigation_id)):
            raise BadRequestException("Ya hay un análisis del chat en curso en este caso. Espera su resultado.")
        prompt = " ".join(data.prompt.split())
        run = self.create(actor, investigation_id, SearchRunCreate(
            objective=prompt if len(prompt) >= 5 else f"Investigar {prompt}", targets=decision["targets"],
            max_tools=min(12, settings.orchestrator_max_tools),
            profile="footprint" if active else "auto",
            authorization_confirmed=True, allow_active=active, follow_discoveries=False,
            scope_note=data.active_scope_note if active else None,
        ), chat_context={
            "prompt": prompt,
            "analysis_type": decision["analysis_type"], "message": decision["message"],
            "decisions": decision["decisions"], "parent_run_id": data.parent_run_id,
            "intent_method": "bounded-explicit-target-rules-v1",
            "active_authorization_confirmed": bool(active and data.active_authorization_confirmed),
        })
        return ChatSearchRead(message=decision["message"], analysis_type=decision["analysis_type"],
                              decisions=decision["decisions"], needs_clarification=False, run=run)

    def get(self, actor: User, run_id: int) -> SearchRunRead:
        run = self.repository.get_by_id(run_id)
        if run is None:
            raise NotFoundException("Search run")
        self.investigations.get_model(actor, run.investigation_id)
        return SearchRunRead.model_validate(run)

    def list(
        self,
        actor: User,
        investigation_id: int,
    ) -> list[SearchRunRead]:
        self.investigations.get_model(actor, investigation_id)
        return [
            SearchRunRead.model_validate(run)
            for run in self.repository.list_by_investigation(investigation_id)
        ]

    def discovery_graph(
        self,
        actor: User,
        run_id: int,
    ) -> SearchDiscoveryGraphRead:
        run = self.repository.get_by_id(run_id)
        if run is None:
            raise NotFoundException("Search run")
        self.investigations.get_model(actor, run.investigation_id)
        return SearchDiscoveryGraphRead(
            nodes=[
                SearchDiscoveryRead.model_validate(node)
                for node in self.discoveries.list_nodes(run_id)
            ],
            edges=[
                SearchDiscoveryEdgeRead.model_validate(edge)
                for edge in self.discoveries.list_edges(run_id)
            ],
        )
