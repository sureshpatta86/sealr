import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.utils.database import Base


class Scan(Base):
    __tablename__ = "Scans"

    Id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    RepositoryId: Mapped[str] = mapped_column(
        String(36), ForeignKey("Repositories.Id"), nullable=False
    )
    UserId: Mapped[str] = mapped_column(
        String(36), ForeignKey("Users.Id"), nullable=False
    )
    Status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="queued"
    )
    Language: Mapped[str] = mapped_column(String(50), nullable=False)
    Framework: Mapped[str | None] = mapped_column(String(100), nullable=True)
    Branch: Mapped[str] = mapped_column(String(100), nullable=False)
    CommitSha: Mapped[str | None] = mapped_column(String(40), nullable=True)
    TotalVulnerabilities: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    FixedCount: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    StartedAt: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    CompletedAt: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    ErrorMessage: Mapped[str | None] = mapped_column(Text, nullable=True)
    ScanDurationSec: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    CreatedAt: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )

    repository = relationship("Repository", back_populates="scans")
    user = relationship("User", back_populates="scans")
    vulnerabilities = relationship(
        "Vulnerability", back_populates="scan", cascade="all, delete-orphan"
    )
    events = relationship(
        "ScanEvent", back_populates="scan", cascade="all, delete-orphan"
    )
