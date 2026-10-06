import re
from datetime import datetime, timezone
from urllib.parse import quote

from app.core.exceptions import BadRequestException
from app.osint.contracts import CollectedItem, Collector
from app.osint.http import SafeHttpClient
from app.osint.passive_collectors import _json_item
from app.osint.targets import normalize_username


NAMESPACE_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
REPOSITORY_PATTERN = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*")


def _last_updated(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not 10 <= len(value) <= 40:
        raise ValueError("Invalid Docker Hub repository timestamp.")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed > datetime.now(timezone.utc):
        raise ValueError("Invalid Docker Hub repository timestamp.")
    return parsed.astimezone(timezone.utc).isoformat()


class DockerHubRepositoriesCollector(Collector):
    name = "username_dockerhub_repositories"
    description = "Lists one bounded page of public Docker Hub namespace repositories."
    target_types = frozenset({"username"})
    query_field = "username"
    provider = "Docker Hub"
    reference_url = (
        "https://docs.docker.com/reference/api/hub/latest/operations/listNamespaceRepositories/"
    )
    module_family = "container_registry"
    capability_id = "container_registry:dockerhub-public-namespace-repositories"
    maximum_repositories = 25

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        namespace = normalize_username(query.get("username")).lower()
        if not NAMESPACE_PATTERN.fullmatch(namespace):
            raise BadRequestException("Invalid Docker Hub namespace.")
        return {"username": namespace}

    def collect(self, query: dict) -> list[CollectedItem]:
        namespace = self.validate_query(query)["username"]
        endpoint = f"https://hub.docker.com/v2/namespaces/{quote(namespace)}/repositories"
        payload = self.client.get_json(
            endpoint,
            params={"page": 1, "page_size": self.maximum_repositories, "ordering": "name"},
            allowed_hosts={"hub.docker.com"},
        )
        if not isinstance(payload, dict):
            raise ValueError("Unexpected Docker Hub repository response.")
        count, results, next_page = (payload.get(key) for key in ("count", "results", "next"))
        if (
            not isinstance(count, int) or isinstance(count, bool)
            or not 0 <= count <= 9_223_372_036_854_775_807
            or not isinstance(results, list) or len(results) > self.maximum_repositories
            or count < len(results)
            or (next_page is not None and (
                not isinstance(next_page, str) or not next_page or len(next_page) > 2_048
            ))
        ):
            raise ValueError("Invalid or oversized Docker Hub repository page.")
        repositories = []
        seen = set()
        for row in results:
            if not isinstance(row, dict):
                raise ValueError("Invalid Docker Hub repository record.")
            name, description = row.get("name"), row.get("description")
            counts = [row.get(key) for key in ("star_count", "pull_count")]
            if (
                row.get("namespace") != namespace or row.get("is_private") is not False
                or not isinstance(name, str) or not 1 <= len(name) <= 255
                or not REPOSITORY_PATTERN.fullmatch(name) or name in seen
                or not isinstance(description, str) or len(description) > 1_000
                or any(not isinstance(value, int) or isinstance(value, bool)
                       or not 0 <= value <= 9_223_372_036_854_775_807 for value in counts)
            ):
                raise ValueError("Invalid, private or unrelated Docker Hub repository.")
            seen.add(name)
            repositories.append({
                "name": name, "namespace": namespace, "description": description,
                "star_count": counts[0], "pull_count": counts[1],
                "last_updated": _last_updated(row.get("last_updated")),
                "url": f"https://hub.docker.com/r/{quote(namespace)}/{quote(name)}",
            })
        repositories.sort(key=lambda row: row["name"])
        return [_json_item(
            source_type="container_registry", locator=endpoint, kind=self.name,
            title=f"Public Docker Hub repositories in {namespace}", provider=self.provider,
            data={
                "namespace": namespace, "reported_public_count": count,
                "repositories": repositories, "repositories_checked": len(repositories),
                "truncated": count > len(repositories) or next_page is not None,
                "page": 1, "page_size": self.maximum_repositories,
                "scope": "Anonymous public repository metadata only; no image downloads, "
                "private repositories, authentication or pagination-link traversal. "
                "A namespace may identify an organization or user; matching names do not "
                "prove a person's identity, repository safety or deployment. Empty results "
                "do not establish that an account does not exist.",
            },
        )]
