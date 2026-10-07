import re
import unicodedata

from app.osint.targets import infer_targets


def requests_active_verification(prompt: str) -> bool:
    text = "".join(c for c in unicodedata.normalize("NFKD", prompt.casefold())
                   if not unicodedata.combining(c))
    # Explicit requests only; a question about TLS is not consent to contact a host.
    if re.search(r"\b(?:sin|no|not|without)\b", text):
        return False
    return bool(re.search(
        r"\b(?:verifica(?:r)?|comprueba|comprobar|valida(?:r)?|check|verify)\b.*"
        r"\b(?:activamente|activa|activo|tls|https|http)\b|"
        r"\b(?:pruebas? activas?|verificacion activa|active verification)\b", text,
    ))


def interpret_chat(prompt: str, previous_targets: list[dict] | None = None) -> dict:
    """Explain bounded routing decisions, never infer authorization or new identities."""
    prompt = " ".join(prompt.split())
    text = "".join(c for c in unicodedata.normalize("NFKD", prompt.casefold())
                   if not unicodedata.combining(c))
    inferred = infer_targets(prompt)
    explicit = [target for target in inferred if target["type"] != "keyword"]
    named_subject = re.fullmatch(r"(?:ahora\s+)?(?:investiga(?:r)?|analiza(?:r)?|busca(?:r)?|investigate|research)\s+(.+)",
                                prompt, flags=re.IGNORECASE)
    if not explicit and named_subject:
        subject = named_subject.group(1).strip(' "\'')
        if len(subject) >= 3 and not re.match(r"(?:su|sus|eso|el mismo|lo anterior)\b", subject, re.IGNORECASE):
            explicit = [{"type": "keyword", "value": subject[:200]}]
    follow_up = bool(re.search(r"\b(ahora|continua|continuar|su|sus|eso|anterior|mismo|same|their|it)\b", text))
    targets = explicit or (previous_targets if follow_up else None)
    inherited = not explicit and bool(targets)
    if not targets:
        # Named subjects can be researched as text; generic instructions cannot.
        subject = re.sub(
            r"^(?:investiga(?:r)?|analiza(?:r)?|busca(?:r)?|investigate|research)\s+", "", prompt,
            flags=re.IGNORECASE,
        ).strip(' "\'')
        generic = bool(re.fullmatch(
            r"(?:hola|ayuda|continua|continuar|sigue|analiza|investiga|busca|"
            r"(?:ahora )?(?:revisa|analiza|investiga)(?: (?:su|la))? "
            r"(?:reputacion|infraestructura|seguridad|huella)|haz (?:un )?analisis)", text
        ))
        if follow_up or generic or len(subject) < 3:
            return {"targets": [], "analysis_type": "Objetivo pendiente",
                    "decisions": [], "needs_clarification": True,
                    "message": "¿Qué objetivo quieres investigar? Puedes escribir un dominio, "
                    "IP pública, CVE, @usuario o «investiga Nombre de empresa»."}
        targets = [{"type": "keyword", "value": subject[:200]}]
    types = {target["type"] for target in targets}
    if "cve" in types:
        analysis, reason = "Vulnerabilidad y remediación", "Detecté un identificador CVE."
    elif types & {"hash", "email"} or re.search(r"\b(incidente|phishing|malware|ioc|reputacion|amenaza)\b", text):
        analysis, reason = "Reputación e indicadores", "El pedido contiene indicadores o pide contexto de amenaza."
    elif "username" in types:
        analysis, reason = "Huella de usuario público", "Detecté un identificador de usuario explícito."
    elif types & {"domain", "hostname", "ip", "asn", "url"}:
        analysis, reason = "Infraestructura y exposición", "Detecté un objetivo de infraestructura pública."
    else:
        analysis, reason = "Contexto público de una organización o tema", "El pedido contiene un tema para buscar por texto."
    decisions = [reason, "Elegiré fuentes compatibles con el objetivo mediante el planificador local validado."]
    if inherited:
        decisions.append("Conservo los objetivos del mensaje anterior; no invento otros.")
    decisions.append("Sólo consultas pasivas, sin pruebas activas ni seguimiento automático de nuevos objetivos.")
    active = requests_active_verification(prompt)
    if active:
        analysis = "Verificación activa TLS/HTTP"
        decisions[-1] = ("Propongo una negociación TLS y una petición HTTP HEAD por host en TCP/443, "
                         "dentro del sandbox; sin modificar sistemas ni ampliar objetivos.")
    return {"targets": targets, "analysis_type": analysis, "decisions": decisions,
            "active_requested": active,
            "needs_clarification": False,
            "message": f"Voy a realizar un análisis de {analysis.lower()}. "
            "Te mostraré las fuentes elegidas, su motivo y los resultados verificables."}
