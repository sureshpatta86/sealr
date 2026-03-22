import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import DateTime, ForeignKey, Integer, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.utils.database import Base


class Fix(Base):
    __tablename__ = "Fixes"

    Id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    VulnerabilityId: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("Vulnerabilities.Id", ondelete="CASCADE"),
        nullable=False,
    )
    Status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="generating"
    )
    DiffContent: Mapped[str | None] = mapped_column(Text, nullable=True)
    ConfidenceScore: Mapped[Decimal | None] = mapped_column(
        Numeric(5, 2), nullable=True
    )
    AIModel: Mapped[str] = mapped_column(String(50), nullable=False)
    AIPromptTokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    AICompletionTokens: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    BuildOutput: Mapped[str | None] = mapped_column(Text, nullable=True)
    TestOutput: Mapped[str | None] = mapped_column(Text, nullable=True)
    RetryCount: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    PRUrl: Mapped[str | None] = mapped_column(String(500), nullable=True)
    PRNumber: Mapped[int | None] = mapped_column(Integer, nullable=True)
    BranchName: Mapped[str | None] = mapped_column(String(200), nullable=True)
    CreatedAt: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    ValidatedAt: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )

    vulnerability = relationship("Vulnerability", back_populates="fix")
