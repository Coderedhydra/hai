from __future__ import annotations

import base64
import os
from typing import List, Optional

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application configuration loaded from environment variables.

    All values have safe defaults suitable for local development but should be
    overridden in production deployments.
    """

    operator_token: str = Field(
        default=os.getenv("OPERATOR_TOKEN", "dev-operator-token"),
        description="Token required for privileged operations (approve active, kill jobs).",
    )

    # Manifest verification: Ed25519 public key, base64 encoded
    auth_public_key_base64: Optional[str] = Field(
        default=os.getenv("AUTH_PUBLIC_KEY_BASE64"),
        description="Base64-encoded Ed25519 public key used to verify manifests.",
    )

    # Evidence signing & encryption
    evidence_hmac_key: str = Field(
        default=os.getenv("EVIDENCE_HMAC_KEY", "dev-secret-please-change"),
        description="HMAC key for evidence record signing (append-only integrity).",
    )
    evidence_encryption_key: Optional[str] = Field(
        default=os.getenv("EVIDENCE_ENCRYPTION_KEY"),
        description="Optional Fernet key to encrypt evidence 'data' payloads.",
    )

    # Queue manager for worker containers
    queue_manager_host: str = Field(default=os.getenv("QUEUE_MANAGER_HOST", "0.0.0.0"))
    queue_manager_port: int = Field(default=int(os.getenv("QUEUE_MANAGER_PORT", "5001")))
    queue_manager_authkey: str = Field(default=os.getenv("QUEUE_MANAGER_AUTHKEY", "devqueuekey"))

    # Rate limiting
    global_rps: float = Field(default=1.0, description="Global requests per second limit")
    per_target_rps: float = Field(default=0.5, description="Per-target requests per second limit")
    backoff_seconds: float = Field(default=1.0, description="Backoff when rate-limited")

    # Allowed HTTP methods (safe defaults)
    allowed_http_methods: List[str] = Field(default_factory=lambda: ["GET", "HEAD"])

    # Claude gateway
    claude_api_key: Optional[str] = Field(default=os.getenv("CLAUDE_API_KEY"))

    # Storage locations
    evidence_dir: str = Field(default=os.getenv("EVIDENCE_DIR", "/evidence"))
    reports_dir: str = Field(default=os.getenv("REPORTS_DIR", "/reports"))

    class Config:
        env_file = ".env"

    def get_auth_public_key_bytes(self) -> Optional[bytes]:
        if not self.auth_public_key_base64:
            return None
        return base64.b64decode(self.auth_public_key_base64)


settings = Settings()

