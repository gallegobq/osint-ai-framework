from datetime import datetime, timedelta, timezone

import jwt
import pytest
from jwt.exceptions import InvalidTokenError
from pydantic import ValidationError

from app.auth.jwt import decode_token
from app.auth.schemas import LoginRequest, RefreshTokenRequest
from app.core.settings import settings
from app.schemas.investigation import (
    InvestigationTaskUpdate,
    InvestigationUpdate,
)
from app.schemas.project import ProjectUpdate


@pytest.mark.parametrize(
    ("schema", "payload"),
    [
        (ProjectUpdate, {"name": None}),
        (ProjectUpdate, {"status": None}),
        (InvestigationUpdate, {"title": None}),
        (InvestigationUpdate, {"priority": None}),
        (InvestigationTaskUpdate, {"status": None}),
    ],
)
def test_patch_contracts_reject_null_for_required_columns(
    schema,
    payload: dict,
) -> None:
    with pytest.raises(ValidationError):
        schema.model_validate(payload)


def test_authentication_payloads_have_size_limits() -> None:
    with pytest.raises(ValidationError):
        LoginRequest(username="u" * 51, password="valid")
    with pytest.raises(ValidationError):
        RefreshTokenRequest(refresh_token="x" * 4097)


def test_jwt_decoder_requires_all_session_claims() -> None:
    now = datetime.now(timezone.utc)
    incomplete_token = jwt.encode(
        {
            "sub": "1",
            "type": "access",
            "iat": now,
            "exp": now + timedelta(minutes=1),
        },
        settings.secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )

    with pytest.raises(InvalidTokenError):
        decode_token(incomplete_token)
