from dataclasses import asdict, dataclass
from enum import StrEnum


class ScanProfile(StrEnum):
    """Reproducible collector-selection strategies."""

    AUTO = "auto"
    PASSIVE = "passive"
    FOOTPRINT = "footprint"
    INVESTIGATE = "investigate"
    ALL = "all"


@dataclass(frozen=True, slots=True)
class ScanProfileDefinition:
    name: ScanProfile
    label: str
    description: str
    deterministic: bool
    passive_only: bool


PROFILE_DEFINITIONS = (
    ScanProfileDefinition(
        name=ScanProfile.AUTO,
        label="Automático",
        description=(
            "El planificador local selecciona fuentes compatibles y aplica un "
            "fallback determinista si el modelo no está disponible."
        ),
        deterministic=False,
        passive_only=False,
    ),
    ScanProfileDefinition(
        name=ScanProfile.PASSIVE,
        label="Pasivo",
        description=(
            "Ejecuta todas las fuentes pasivas compatibles sin contacto activo "
            "con el objetivo."
        ),
        deterministic=True,
        passive_only=True,
    ),
    ScanProfileDefinition(
        name=ScanProfile.FOOTPRINT,
        label="Huella",
        description=(
            "Prioriza DNS, certificados, infraestructura, históricos y superficie "
            "de exposición."
        ),
        deterministic=True,
        passive_only=False,
    ),
    ScanProfileDefinition(
        name=ScanProfile.INVESTIGATE,
        label="Investigar",
        description=(
            "Prioriza enriquecimiento, reputación, identidad y contexto de "
            "inteligencia."
        ),
        deterministic=True,
        passive_only=True,
    ),
    ScanProfileDefinition(
        name=ScanProfile.ALL,
        label="Completo",
        description=(
            "Ejecuta todo el catálogo compatible; los módulos activos siguen "
            "requiriendo modo pentest, alcance y permiso explícitos."
        ),
        deterministic=True,
        passive_only=False,
    ),
)


def scan_profile_catalog() -> list[dict[str, object]]:
    return [
        {
            **asdict(definition),
            "name": definition.name.value,
        }
        for definition in PROFILE_DEFINITIONS
    ]
