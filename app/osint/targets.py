import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from email_validator import EmailNotValidError, validate_email

from app.core.exceptions import BadRequestException
from app.osint.domain import normalize_domain


ASN_PATTERN = re.compile(r"^(?:AS)?([0-9]{1,10})$", re.IGNORECASE)
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
URL_CANDIDATE_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
IPV4_CANDIDATE_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
IPV6_CANDIDATE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"
    r"(?![A-Za-z0-9:])"
)
ASN_CANDIDATE_PATTERN = re.compile(r"\bAS[0-9]{1,10}\b", re.IGNORECASE)
DOMAIN_CANDIDATE_PATTERN = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}\b"
)
MENTION_PATTERN = re.compile(r"(?<![\w@])@([A-Za-z0-9][A-Za-z0-9_.-]{0,62})")
EMAIL_CANDIDATE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}"
)
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$", re.IGNORECASE)
CVE_CANDIDATE_PATTERN = re.compile(
    r"\bCVE-[0-9]{4}-[0-9]{4,19}\b",
    re.IGNORECASE,
)
HASH_PATTERN = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")
HASH_CANDIDATE_PATTERN = re.compile(
    r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})"
    r"(?![A-Fa-f0-9])"
)


def normalize_ip(value: object) -> str:
    if not isinstance(value, str):
        raise BadRequestException("query.ip must be a string.")
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise BadRequestException("Invalid IP address.") from exc
    if not address.is_global:
        raise BadRequestException("Only public IP addresses are allowed.")
    return address.compressed


def normalize_asn(value: object) -> str:
    candidate = str(value).strip()
    match = ASN_PATTERN.fullmatch(candidate)
    if match is None:
        raise BadRequestException("Invalid autonomous system number.")
    number = int(match.group(1))
    if number < 1 or number > 4_294_967_295:
        raise BadRequestException("Autonomous system number is out of range.")
    return f"AS{number}"


def normalize_username(value: object) -> str:
    if not isinstance(value, str):
        raise BadRequestException("query.username must be a string.")
    candidate = value.strip()
    if not USERNAME_PATTERN.fullmatch(candidate):
        raise BadRequestException("Invalid public username.")
    return candidate


def normalize_hostname(value: object) -> str:
    """Normalize a public DNS hostname without inferring its registrable domain."""

    return normalize_domain(value)


def normalize_email(value: object) -> str:
    if not isinstance(value, str):
        raise BadRequestException("query.email must be a string.")
    try:
        result = validate_email(
            value.strip(),
            check_deliverability=False,
            allow_smtputf8=False,
        )
    except EmailNotValidError as exc:
        raise BadRequestException("Invalid email address.") from exc
    return result.normalized


def normalize_hash(value: object) -> str:
    if not isinstance(value, str):
        raise BadRequestException("query.hash must be a string.")
    candidate = value.strip().lower()
    if not HASH_PATTERN.fullmatch(candidate):
        raise BadRequestException("Hash must be MD5, SHA-1, or SHA-256 hexadecimal.")
    return candidate


def normalize_cve(value: object) -> str:
    if not isinstance(value, str):
        raise BadRequestException("query.cve must be a string.")
    candidate = value.strip().upper()
    if not CVE_PATTERN.fullmatch(candidate):
        raise BadRequestException("Invalid CVE identifier.")
    return candidate


def normalize_keyword(value: object) -> str:
    if not isinstance(value, str):
        raise BadRequestException("query.keyword must be a string.")
    candidate = " ".join(value.split())
    if len(candidate) < 2 or len(candidate) > 200:
        raise BadRequestException("Keyword must contain between 2 and 200 characters.")
    return candidate


def normalize_public_url(value: object) -> str:
    if not isinstance(value, str):
        raise BadRequestException("query.url must be a string.")
    candidate = value.strip()
    if len(candidate) > 2048:
        raise BadRequestException("URL is too long.")
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise BadRequestException("Only absolute HTTP(S) URLs are allowed.")
    if parsed.username or parsed.password:
        raise BadRequestException("URLs with embedded credentials are not allowed.")

    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        host = normalize_domain(parsed.hostname)
    else:
        host = normalize_ip(parsed.hostname)

    try:
        port = parsed.port
    except ValueError as exc:
        raise BadRequestException("Invalid URL port.") from exc
    netloc = host if port is None else f"{host}:{port}"
    return urlunsplit(
        (parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, "")
    )


NORMALIZERS = {
    "domain": normalize_domain,
    "hostname": normalize_hostname,
    "ip": normalize_ip,
    "asn": normalize_asn,
    "username": normalize_username,
    "email": normalize_email,
    "hash": normalize_hash,
    "cve": normalize_cve,
    "keyword": normalize_keyword,
    "url": normalize_public_url,
}


def normalize_target(target_type: str, value: object) -> str:
    normalizer = NORMALIZERS.get(target_type)
    if normalizer is None:
        raise BadRequestException(f"Unsupported target type: {target_type}.")
    return normalizer(value)


def infer_targets(objective: str) -> list[dict[str, str]]:
    """Infer only syntactically explicit targets; never infer private IPs."""

    inferred: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(target_type: str, value: str) -> None:
        try:
            normalized = normalize_target(target_type, value)
        except BadRequestException:
            return
        identity = (target_type, normalized)
        if identity not in seen and len(inferred) < 20:
            seen.add(identity)
            inferred.append({"type": target_type, "value": normalized})

    for match in URL_CANDIDATE_PATTERN.finditer(objective):
        candidate = match.group(0).rstrip(".,;:!?)]}")
        add("url", candidate)
        host = None
        try:
            host = urlsplit(normalize_public_url(candidate)).hostname
            ipaddress.ip_address(host or "")
        except BadRequestException:
            continue
        except ValueError:
            if host:
                add("domain", host)
        else:
            if host:
                add("ip", host)

    for match in ASN_CANDIDATE_PATTERN.finditer(objective):
        add("asn", match.group(0))
    for match in EMAIL_CANDIDATE_PATTERN.finditer(objective):
        add("email", match.group(0))
    for match in CVE_CANDIDATE_PATTERN.finditer(objective):
        add("cve", match.group(0))
    for match in HASH_CANDIDATE_PATTERN.finditer(objective):
        add("hash", match.group(0))
    for pattern in (IPV4_CANDIDATE_PATTERN, IPV6_CANDIDATE_PATTERN):
        for match in pattern.finditer(objective):
            add("ip", match.group(0).rstrip("."))
    for match in DOMAIN_CANDIDATE_PATTERN.finditer(objective):
        add("domain", match.group(0))
    for match in MENTION_PATTERN.finditer(objective):
        add("username", match.group(1))

    if not inferred:
        add("keyword", objective[:200])
    return inferred
