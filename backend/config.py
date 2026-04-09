# backend/config.py
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import AnyHttpUrl, SecretStr
from typing import Literal


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # App
    APP_NAME: str = "MemoryScope"
    ENV: Literal["development", "production", "test"] = "development"
    SECRET_KEY: SecretStr
    API_PREFIX: str = "/api/v1"
    ALLOWED_ORIGINS: list[AnyHttpUrl] = []

    # Database
    DATABASE_URL: str  # postgresql+asyncpg://user:pass@host/db

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Object Storage (MinIO / S3)
    S3_ENDPOINT: str = "http://minio:9000"
    S3_ACCESS_KEY: SecretStr
    S3_SECRET_KEY: SecretStr
    S3_BUCKET_DUMPS: str = "dumps"
    S3_BUCKET_REPORTS: str = "reports"
    S3_USE_SSL: bool = False

    # Volatility3
    VOLATILITY_PATH: str = "/opt/volatility3/vol.py"
    SYMBOL_SERVER_URL: str = "https://downloads.volatilityfoundation.org/volatility3/symbols/"
    SYMBOL_CACHE_PATH: str = "/opt/volatility3/volatility3/symbols"
    DWARF2JSON_PATH: str = "dwarf2json"  # path/name of dwarf2json binary
    # Remote ISF banner indexes tried in order before falling back to local build
    REMOTE_ISF_URLS: list[str] = [
        "https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/banners/banners.json",
        "https://raw.githubusercontent.com/leludo84/vol3-linux-profiles/main/banners-isf.json",
    ]
    PLUGIN_TIMEOUT_SECONDS: int = 600       # 10 min per plugin
    WORKER_TMP_DIR: str = "/tmp/memoryscope"
    MAX_DUMP_SIZE_BYTES: int = 64 * 1024 ** 3   # 64 GB
    MAX_CASES_PER_HOUR_PER_USER: int = 20   # upload rate limit per user

    # AI  (seeded to system_settings on first start; managed from Admin UI thereafter)
    ANTHROPIC_API_KEY: SecretStr = SecretStr("")
    # Fallback: any OpenAI-compatible endpoint (Ollama, vLLM, LiteLLM, OpenAI, …)
    FALLBACK_API_URL: str = ""        # e.g. http://ollama:11434/v1
    FALLBACK_API_KEY: SecretStr | None = None
    FALLBACK_MODEL: str = ""          # e.g. llama3.2, gpt-4o
    PRIMARY_MODEL: str = "claude-opus-4-5"
    FAST_MODEL: str = "claude-sonnet-4-5"       # for sub-agents / summaries
    AI_MAX_CONTEXT_TOKENS: int = 180_000
    SUMMARISE_THRESHOLD_CHARS: int = 80_000     # summarise plugin output above this

    # Enrichment
    VIRUSTOTAL_API_KEY: SecretStr | None = None
    VT_RATE_LIMIT_PER_MIN: int = 500             # premium = 500/min; free tier = 4/min
    VT_MAX_IOCS: int = 40                        # cap submissions per enrichment run

    # Auth
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_EXPIRE_MINUTES: int = 60
    JWT_REFRESH_EXPIRE_DAYS: int = 30

    # OIDC / SSO (Authentik)
    # Leave OIDC_CLIENT_ID empty to disable SSO entirely.
    OIDC_CLIENT_ID: str = ""
    OIDC_CLIENT_SECRET: SecretStr | None = None
    OIDC_DISCOVERY_URL: str = ""   # e.g. https://auth.example.com/application/o/memoryscope/.well-known/openid-configuration
    OIDC_REDIRECT_URI: str = ""    # e.g. https://memoryscope.example.com/api/v1/auth/oidc/callback
    OIDC_FRONTEND_CALLBACK_URL: str = "http://localhost:3000/auth/callback"
    OIDC_PROVIDER_NAME: str = "SSO"          # Label shown on the login button
    OIDC_ROLE_CLAIM: str = "groups"          # id_token claim that carries group membership
    OIDC_ADMIN_GROUP: str = "memoryscope-admins"   # Group that maps to the admin role
    OIDC_ENABLED: bool = True                # Master toggle — False disables SSO without clearing config
    OIDC_JIT_PROVISIONING: bool = False      # Create unknown users on first login
    OIDC_VERIFY_SSL: bool = True             # Set False to skip TLS cert verification (e.g. self-signed CA)

    # LDAP / LDAPS authentication
    LDAP_ENABLED: bool = False
    LDAP_URL: str = ""                          # ldap://host:389 or ldaps://host:636
    LDAP_USE_STARTTLS: bool = False             # upgrade plain LDAP to TLS
    LDAP_TLS_VERIFY: bool = True                # verify TLS certificate
    LDAP_BIND_DN: str = ""                      # service account DN
    LDAP_BIND_PASSWORD: SecretStr = SecretStr("")
    LDAP_BASE_DN: str = ""                      # search base, e.g. dc=example,dc=com
    LDAP_USER_FILTER: str = "(mail={username})"   # {username} is substituted; use (uid={username}) for short usernames
    LDAP_ATTR_EMAIL: str = "mail"               # attribute holding user's email
    LDAP_ATTR_DISPLAY_NAME: str = "displayName" # attribute for display name
    LDAP_GROUP_BASE_DN: str = ""                # base DN for group search (defaults to LDAP_BASE_DN)
    LDAP_ADMIN_GROUP: str = ""                  # DN of group → admin role
    LDAP_ANALYST_GROUP: str = ""                # DN of group → analyst role
    LDAP_VIEWER_GROUP: str = ""                 # DN of group → viewer role
    LDAP_JIT_PROVISIONING: bool = True          # auto-create users on first LDAP login

    # Watch Folder — automatically import dumps dropped into a local directory
    WATCH_DIR_ENABLED: bool = False
    WATCH_DIR: str = ""              # absolute path to watch; empty = disabled
    WATCH_DIR_POLL_INTERVAL: int = 30   # seconds between scans
    WATCH_DIR_STABLE_AGE: int = 30      # ignore files modified less than N seconds ago

    # Logging
    LOG_FILE: str = "logs/memoryscope.log"   # path relative to repo root; set to "" to disable
    LOG_MAX_BYTES: int = 10 * 1024 * 1024    # 10 MB per file
    LOG_BACKUP_COUNT: int = 5

    # Strings extraction
    STRINGS_MAX_WORKERS: int = 4        # parallel chunk workers for strings extraction
    STRINGS_SEARCH_CAP: int = 10_000    # max matches returned per search query
    STRINGS_PLUGIN_THRESHOLD: int = 100 # max filtered matches to enable "Run strings plugin" button

    # Celery
    CELERY_CONCURRENCY: int = 4

    # Retention
    DUMP_RETENTION_DAYS: int = 30
    REPORT_RETENTION_DAYS: int = 365


settings = Settings()
