"""
Configuration settings for Web3 Risk Monitor

Uses pydantic-settings for type-safe configuration management.
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Ethereum RPC
    eth_rpc_url: str = Field(
        default="https://eth-mainnet.g.alchemy.com/v2/demo",
        description="Ethereum mainnet RPC endpoint"
    )

    eth_testnet_rpc_url: Optional[str] = Field(
        default=None,
        description="Ethereum testnet RPC endpoint (optional)"
    )

    # Database
    database_url: Optional[str] = Field(
        default=None,
        description="PostgreSQL connection URL"
    )

    # Rate limiting
    rpc_requests_per_second: int = Field(
        default=10,
        description="Max RPC requests per second"
    )

    # Batch processing
    batch_size: int = Field(
        default=100,
        description="Number of items to process in batch"
    )

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


# Global settings instance
settings = Settings()
