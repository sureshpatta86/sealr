import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.utils.database import Base


class ScanConfig(Base):
    __tablename__ = "ScanConfigs"

    Id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    UserId: Mapped[str] = mapped_column(
        String(36), ForeignKey("Users.Id"), nullable=False
    )
    RepositoryId: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("Repositories.Id"), nullable=True
    )
    EnabledScanners: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default='["dependency","secrets","sast","malware","config","license"]',
    )
    AutoCreatePR: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    ScheduleCron: Mapped[str | None] = mapped_column(String(100), nullable=True)
    ExcludedPaths: Mapped[str | None] = mapped_column(Text, nullable=True)
    SeverityThreshold: Mapped[str] = mapped_column(
        String(20), nullable=False, default="low"
    )
    CreatedAt: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )

    user = relationship("User", back_populates="scan_configs")
