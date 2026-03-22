from pydantic import BaseModel


class TokenValidationRequest(BaseModel):
    github_token: str


class GitHubUser(BaseModel):
    login: str
    avatar_url: str


class TokenValidationResponse(BaseModel):
    valid: bool
    user: GitHubUser
    scopes: str
