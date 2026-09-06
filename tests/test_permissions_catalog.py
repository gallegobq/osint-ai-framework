from app.core.permissions import Permissions
from app.seed.rbac import DEFAULT_PERMISSIONS


def permission_constants() -> set[str]:
    values: set[str] = set()
    for category_name, category in vars(Permissions).items():
        if category_name.startswith("_"):
            continue
        if not isinstance(category, type):
            continue
        for name, value in vars(category).items():
            if name.isupper() and isinstance(value, str):
                values.add(value)
    return values


def test_every_permission_constant_is_seeded_once() -> None:
    seeded = [item["code"] for item in DEFAULT_PERMISSIONS]
    assert len(seeded) == len(set(seeded))
    assert set(seeded) == permission_constants()


def test_permission_code_matches_resource_and_action() -> None:
    for item in DEFAULT_PERMISSIONS:
        assert item["code"] == f"{item['resource']}:{item['action']}"
