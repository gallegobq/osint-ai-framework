import re

from app.core.exceptions import BadRequestException


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}$"
)


def normalize_domain(value: object) -> str:
    if not isinstance(value, str):
        raise BadRequestException("query.domain must be a string.")

    candidate = value.strip().lower().rstrip(".")

    try:
        ascii_domain = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise BadRequestException("Invalid internationalized domain.") from exc

    if not DOMAIN_PATTERN.fullmatch(ascii_domain):
        raise BadRequestException("Invalid domain name.")

    return ascii_domain
