"""OWASP LLM Top 10 database model."""

from datetime import datetime

from sqlalchemy import ARRAY, DateTime, String, Text
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR
from sqlalchemy.orm import Mapped, mapped_column

from cve_mcp.models.base import Base


class OwaspLlmTop10(Base):
    """OWASP LLM Top 10 for Large Language Model Applications v1.1 (2023)."""

    __tablename__ = "owasp_llm_top10"

    llm_id: Mapped[str] = mapped_column(String(10), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    description_vector: Mapped[TSVECTOR | None] = mapped_column(TSVECTOR)
    common_examples: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    prevention_strategies: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    example_attack_scenarios: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    related_techniques: Mapped[dict | None] = mapped_column(JSONB)
    url: Mapped[str | None] = mapped_column(String(500))
    version: Mapped[str | None] = mapped_column(String(20), server_default="1.1")
    data_last_updated: Mapped[datetime | None] = mapped_column(
        DateTime, server_default="NOW()"
    )

    def __repr__(self) -> str:
        return f"<OwaspLlmTop10(llm_id='{self.llm_id}', name='{self.name}')>"
