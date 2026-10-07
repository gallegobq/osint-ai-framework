from urllib.parse import quote

from app.core.exceptions import BadRequestException
from app.osint.contracts import CollectedItem, Collector
from app.osint.http import SafeHttpClient
from app.osint.huggingface_collector import (
    MODEL_NAME_PATTERN,
    NAMESPACE_PATTERN,
    _count,
    _modified,
)
from app.osint.passive_collectors import _json_item
from app.osint.targets import normalize_username


class HuggingFaceDatasetsCollector(Collector):
    name = "username_huggingface_datasets"
    description = "Retrieves bounded public dataset metadata for a Hugging Face publisher."
    target_types = frozenset({"username"})
    query_field = "username"
    provider = "Hugging Face Hub"
    reference_url = "https://huggingface.co/docs/huggingface_hub/package_reference/hf_api#huggingface_hub.HfApi.list_datasets"
    endpoint = "https://huggingface.co/api/datasets"
    module_family = "dataset_registry"
    capability_id = "dataset_registry:huggingface-public-publisher-datasets"
    maximum_datasets = 25
    expanded_fields = ("author", "private", "downloads", "likes", "lastModified",
                       "gated", "disabled")

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
            params={"author": namespace, "limit": self.maximum_datasets + 1,
                    "sort": "downloads", "expand": list(self.expanded_fields)},
            allowed_hosts={"huggingface.co"},
        )
        if not isinstance(payload, list) or len(payload) > self.maximum_datasets + 1:
            raise ValueError("Invalid or oversized Hugging Face dataset response.")
        datasets, seen = [], set()
        for row in payload:
            if not isinstance(row, dict):
                raise ValueError("Invalid Hugging Face dataset record.")
            dataset_id, author = row.get("id"), row.get("author")
            if (
                not isinstance(dataset_id, str) or len(dataset_id) > 160
                or dataset_id.count("/") != 1 or not isinstance(author, str)
                or not NAMESPACE_PATTERN.fullmatch(author)
                or author.casefold() != namespace.casefold() or row.get("private") is not False
            ):
                raise ValueError("Private, unrelated or invalid Hugging Face dataset identity.")
            owner, name = dataset_id.split("/")
            if (
                owner.casefold() != namespace.casefold() or not NAMESPACE_PATTERN.fullmatch(owner)
                or not MODEL_NAME_PATTERN.fullmatch(name) or name.endswith((".", "-"))
                or ".." in name or "--" in name or dataset_id.casefold() in seen
            ):
                raise ValueError("Invalid or duplicate Hugging Face dataset ID.")
            gated, disabled = row.get("gated"), row.get("disabled")
            if (
                not (isinstance(gated, bool) or isinstance(gated, str) and gated in {"auto", "manual"})
                or not isinstance(disabled, bool)
            ):
                raise ValueError("Invalid Hugging Face dataset access metadata.")
            seen.add(dataset_id.casefold())
            datasets.append({
                "dataset_id": dataset_id, "author": author, "gated": gated, "disabled": disabled,
                "downloads": _count(row.get("downloads")), "likes": _count(row.get("likes")),
                "last_modified": _modified(row.get("lastModified")),
                "url": f"https://huggingface.co/datasets/{quote(owner)}/{quote(name)}",
            })
        # Validate the sentinel too; an omitted record must not bypass identity checks.
        selected = datasets[:self.maximum_datasets]
        return [_json_item(
            source_type="dataset_registry", locator=self.endpoint, kind=self.name,
            title=f"Public Hugging Face dataset metadata for {namespace}", provider=self.provider,
            data={
                "namespace": namespace, "datasets": selected, "records_checked": len(payload),
                "truncated": len(datasets) > len(selected), "dataset_limit": self.maximum_datasets,
                "scope": "One bounded anonymous response ordered by provider downloads, "
                "not an exhaustive catalog. Metadata only: no dataset rows, files, cards, "
                "scripts, authentication or pagination traversal. Public gated or disabled "
                "metadata does not imply file access. Publisher names do not establish "
                "personal identity, ownership of underlying data, licensing, consent or "
                "dataset safety. Empty results do not prove an account is absent.",
            },
        )]
