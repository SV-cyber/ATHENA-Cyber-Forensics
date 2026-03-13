"""
ATHENA Configuration Management
Loads settings from environment variables
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file
ENV_FILE = Path(__file__).resolve().parents[2] / ".env"
load_dotenv(ENV_FILE)


class DatabaseConfig:
    USER = os.getenv("POSTGRES_USER", "athena")
    PASSWORD = os.getenv("POSTGRES_PASSWORD", "athena_secure_password_2026")
    HOST = os.getenv("POSTGRES_HOST", "localhost")
    PORT = int(os.getenv("POSTGRES_PORT", 5432))
    DB = os.getenv("POSTGRES_DB", "athena_db")

    @staticmethod
    def connection_string():
        return f"postgresql://{DatabaseConfig.USER}:{DatabaseConfig.PASSWORD}@{DatabaseConfig.HOST}:{DatabaseConfig.PORT}/{DatabaseConfig.DB}"


class RedisConfig:
    HOST = os.getenv("REDIS_HOST", "localhost")
    PORT = int(os.getenv("REDIS_PORT", 6379))
    DB = int(os.getenv("REDIS_DB", 0))


class APIConfig:
    HOST = os.getenv("API_HOST", "0.0.0.0")
    PORT = int(os.getenv("API_PORT", 8001))
    DEBUG = os.getenv("DEBUG", "True").lower() == "true"