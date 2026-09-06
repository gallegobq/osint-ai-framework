from pydantic import BaseModel, Field


class MfaSetupResponse(BaseModel):
    secret: str
    provisioning_uri: str


class MfaVerifyRequest(BaseModel):
    code: str = Field(pattern=r"^[0-9]{6}$")


class MfaDisableRequest(MfaVerifyRequest):
    password: str = Field(min_length=1, max_length=128)
