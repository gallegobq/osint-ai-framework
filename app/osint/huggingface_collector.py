import re
from datetime import datetime, timezone
from urllib.parse import quote

from app.core.exceptions import BadRequestException
from app.osint.contracts import CollectedItem, Collector
from app.osint.http import SafeHttpClient
from app.osint.passive_collectors import _json_item
from app.osint.targets import normalize_username


NAMESPACE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}")
MODEL_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}")


def _count(value: object) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 2**63 - 1:
        raise ValueError("Invalid Hugging Face model count.")
    return value


def _modified(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not 10 <= len(value) <= 40:
        raise ValueError("Invalid Hugging Face model timestamp.")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed > datetime.now(timezone.utc):
        raise ValueError("Invalid Hugging Face model timestamp.")
    return parsed.astimezone(timezone.utc).isoformat()


class HuggingFaceModelsCollector(Collector):
    name = "username_huggingface_models"
    description = "Retrieves bounded public model metadata for a Hugging Face publisher."
    target_types = frozenset({"username"})
    query_field = "username"
    provider = "Hugging Face Hub"
    reference_url = "https://huggingface.co/docs/huggingface_hub/package_reference/hf_api#huggingface_hub.HfApi.list_models"
    endpoint = "https://huggingface.co/api/models"
    module_family = "model_registry"
    capability_id = "model_registry:huggingface-public-publisher-models"
    maximum_models = 25
    expanded_fields = ("author", "private", "downloads", "likes", "lastModified",
                       "pipeline_tag", "gated")

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        namespace = normalize_username(query.get("username"))
        if not NAMESPACE_PATTERN.fullmatch(namespace):
            raise BadRequestException("Invalid Hugging Face publisher namespace.")
        return {"username": namespace}

    def collect(self, query: dict) -> list[CollectedItem]:
        namespace = self.validate_query(query)["username"]
        payload = self.client.get_json(
            self.endpoint,
            params={"author": namespace, "limit": self.maximum_models + 1,
                    "sort": "downloads", "expand": list(self.expanded_fields)},
            allowed_hosts={"huggingface.co"},
        )
        if not isinstance(payload, list) or len(payload) > self.maximum_models + 1:
            raise ValueError("Invalid or oversized Hugging Face model response.")
        models = []
        seen = set()
        for row in payload:
            if not isinstance(row, dict):
                raise ValueError("Invalid Hugging Face model record.")
            model_id, author = row.get("id"), row.get("author")
            if (
                not isinstance(model_id, str) or len(model_id) > 160 or model_id.count("/") != 1
                or not isinstance(author, str) or not NAMESPACE_PATTERN.fullmatch(author)
                or author.casefold() != namespace.casefold()
                or row.get("private") is not False
            ):
                raise ValueError("Private, unrelated or invalid Hugging Face model identity.")
            owner, name = model_id.split("/")
            if (
                owner.casefold() != namespace.casefold() or not NAMESPACE_PATTERN.fullmatch(owner)
                or not MODEL_NAME_PATTERN.fullmatch(name) or name.endswith((".", "-"))
                or ".." in name or "--" in name or model_id.casefold() in seen
            ):
                raise ValueError("Invalid or duplicate Hugging Face model ID.")
            gated, pipeline = row.get("gated"), row.get("pipeline_tag")
            if (
                not (isinstance(gated, bool) or isinstance(gated, str) and gated in {"auto", "manual"})
                or (pipeline is not None and (not isinstance(pipeline, str) or len(pipeline) > 100))
            ):
                raise ValueError("Invalid Hugging Face model access or task metadata.")
            seen.add(model_id.casefold())
            models.append({
                "model_id": model_id, "author": author, "gated": gated,
                "pipeline_tag": pipeline, "downloads": _count(row.get("downloads")),
                "likes": _count(row.get("likes")), "last_modified": _modified(row.get("lastModified")),
                "url": f"https://huggingface.co/{quote(owner)}/{quote(name)}",
            })
        # Validate even the extra sentinel row before emitting a bounded projection.
        selected = models[:self.maximum_models]
        return [_json_item(
            source_type="model_registry", locator=self.endpoint, kind=self.name,
            title=f"Public Hugging Face model metadata for {namespace}", provider=self.provider,
            data={
                "namespace": namespace, "models": selected, "records_checked": len(payload),
                "truncated": len(models) > len(selected), "model_limit": self.maximum_models,
                "scope": "One bounded anonymous response ordered by provider downloads, "
                "not an exhaustive catalog. Metadata only: no model weights, code, configs, "
                "cards, inference, authentication or pagination traversal. Public gated "
                "metadata does not imply access to files. A publisher can be a user or "
                "organization; matching names do not establish personal identity, model "
                "safety or deployment. Empty results do not prove an account is absent.",
            },
        )]
